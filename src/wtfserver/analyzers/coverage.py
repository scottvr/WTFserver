"""Evidence coverage analyzer.

Reports what evidence was actually available before anything interprets host
behavior: per-channel history spans, whether channels cover the requested
window, and limitation findings for evidence gaps (disabled channels, short
retention, truncation, collector errors, missing process auditing, missing
security history, no history at all).

This analyzer always runs — it must report even when eventlog collection
failed entirely.
"""

from __future__ import annotations

from typing import Any

from ..model import (
    EVIDENCE_OBSERVED,
    EVIDENCE_UNKNOWN,
    Category,
    Finding,
    FindingType,
    parse_iso,
    to_iso,
)
from .base import AnalysisContext, Analyzer

_HISTORICAL_CATEGORIES = (
    Category.EVENT,
    Category.LOGON,
    Category.PROCESS_ACTIVITY,
    Category.SERVICE_ACTIVITY,
    Category.SCHEDULED_ACTIVITY,
    Category.SYSTEM_LIFECYCLE,
)

# Channel names (attribute values, compared case-insensitively) whose disabled
# state meaningfully limits analysis. Per CONTRACTS.md §4 these exact channels
# are the only ones flagged as channel_disabled.
_INTERESTING_CHANNELS = (
    "security",
    "microsoft-windows-taskscheduler/operational",
    "microsoft-windows-powershell/operational",
)

_SECURITY_CHANNEL = "security"

_MAX_CHANNEL_ROWS = 40
_MAX_SUPPORTING = 50


def _as_int(value: Any) -> int:
    """Coerce a possibly-malformed attribute to an int; 0 when unusable."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _cap_supporting(details: dict[str, Any], ids: list[str]) -> list[str]:
    if len(ids) > _MAX_SUPPORTING:
        details["supporting_capped"] = True
        details["supporting_total"] = len(ids)
        return ids[:_MAX_SUPPORTING]
    return ids


class _Channel:
    """Parsed view of one evidence_channel observation."""

    def __init__(self, obs, since):
        attrs = obs.attributes or {}
        self.obs_id = obs.id
        raw_name = attrs.get("channel")
        self.channel = raw_name if isinstance(raw_name, str) else "(unknown)"
        raw_enabled = attrs.get("enabled")
        self.enabled = raw_enabled if isinstance(raw_enabled, bool) else None
        self.record_count = _as_int(attrs.get("record_count"))
        raw_error = attrs.get("error")
        self.error = raw_error if isinstance(raw_error, str) else None
        oldest_raw = attrs.get("oldest_record")
        newest_raw = attrs.get("newest_record")
        self.oldest = oldest_raw if isinstance(oldest_raw, str) else None
        self.newest = newest_raw if isinstance(newest_raw, str) else None
        self.oldest_dt = parse_iso(self.oldest) if self.oldest else None
        self.newest_dt = parse_iso(self.newest) if self.newest else None
        self.collected_events = _as_int(attrs.get("collected_events"))
        self.truncated = bool(attrs.get("truncated"))
        if self.oldest_dt and self.newest_dt:
            self.span_days: float | None = round(
                (self.newest_dt - self.oldest_dt).total_seconds() / 86400.0, 1
            )
        else:
            self.span_days = None
        # covers_window is null when the window is max or oldest is unknown.
        if since is not None and self.oldest_dt is not None:
            self.covers_window: bool | None = self.oldest_dt <= since
        else:
            self.covers_window = None

    def row(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "enabled": self.enabled,
            "record_count": self.record_count,
            "oldest": self.oldest,
            "newest": self.newest,
            "span_days": self.span_days,
            "covers_window": self.covers_window,
            "collected_events": self.collected_events,
            "truncated": self.truncated,
            "error": self.error,
        }

    @property
    def worth_noting(self) -> bool:
        # Populated, explicitly disabled, or errored channels are worth a row.
        return self.record_count > 0 or self.enabled is False or self.error is not None


class CoverageAnalyzer(Analyzer):
    name = "coverage"
    required_categories = ()  # always runs, even with no eventlog evidence

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        channels = [
            _Channel(obs, ctx.since) for obs in ctx.get(Category.EVIDENCE_CHANNEL)
        ]

        findings.append(self._coverage_finding(ctx, channels))
        findings.extend(self._limitations(ctx, channels))
        return findings

    # --- evidence_coverage ---

    def _coverage_finding(self, ctx: AnalysisContext, channels: list[_Channel]) -> Finding:
        noted = sorted(
            (c for c in channels if c.worth_noting),
            key=lambda c: (-c.record_count, c.channel),
        )
        shown = noted[:_MAX_CHANNEL_ROWS]
        populated = [c for c in channels if c.record_count > 0]
        spans = [c.span_days for c in populated if c.span_days is not None]
        total_span = max(spans) if spans else None

        resolved = to_iso(ctx.since) if ctx.since else None
        if ctx.collection_end:
            collection_end = to_iso(ctx.collection_end)
        else:
            collection_end = ctx.manifest.get("collection_end")

        details: dict[str, Any] = {
            "window": {
                "requested": ctx.manifest.get("requested_since"),
                "resolved": resolved,
                "collection_end": collection_end,
            },
            "channels": [c.row() for c in shown],
            "channels_omitted": len(noted) - len(shown),
            "total_span_days": total_span,
        }
        supporting = _cap_supporting(details, [c.obs_id for c in noted])

        if channels:
            conclusion = (
                f"Inventoried {len(channels)} event log channel(s); "
                f"{len(populated)} contain records"
            )
            if total_span is not None:
                conclusion += f", with history spanning up to {total_span} days"
            conclusion += "."
        else:
            conclusion = (
                "No event log channel inventory is available; "
                "historical evidence coverage cannot be assessed."
            )

        return Finding(
            id=ctx.next_finding_id(),
            finding_type=FindingType.EVIDENCE_COVERAGE,
            analyzer=self.name,
            conclusion=conclusion,
            evidence_class=EVIDENCE_OBSERVED,
            supporting_observations=supporting,
            details=details,
        )

    # --- limitations ---

    def _limitations(self, ctx: AnalysisContext, channels: list[_Channel]) -> list[Finding]:
        out: list[Finding] = []
        requested = ctx.manifest.get("requested_since") or "requested"

        # Disabled interesting channels.
        for chan in sorted(channels, key=lambda c: c.channel):
            if chan.enabled is False and chan.channel.lower() in _INTERESTING_CHANNELS:
                out.append(
                    self._limitation(
                        ctx,
                        "channel_disabled",
                        chan.channel,
                        f"Channel '{chan.channel}' is disabled; its history is "
                        f"unavailable for this analysis.",
                        [chan.obs_id],
                    )
                )

        # Retention shorter than the requested window.
        if ctx.since is not None:
            for chan in sorted(channels, key=lambda c: c.channel):
                if (
                    chan.record_count > 0
                    and chan.oldest_dt is not None
                    and chan.oldest_dt > ctx.since
                ):
                    out.append(
                        self._limitation(
                            ctx,
                            "retention_short",
                            chan.channel,
                            f"Channel '{chan.channel}' retains history only back to "
                            f"{chan.oldest}, later than the requested {requested} "
                            f"window start ({to_iso(ctx.since)}); earlier activity in "
                            f"this channel is not visible.",
                            [chan.obs_id],
                        )
                    )

        # Truncated channels.
        for chan in sorted(channels, key=lambda c: c.channel):
            if chan.truncated:
                out.append(
                    self._limitation(
                        ctx,
                        "truncated",
                        chan.channel,
                        f"Collection from channel '{chan.channel}' hit the "
                        f"per-channel event cap; older events within the requested "
                        f"window were not collected.",
                        [chan.obs_id],
                    )
                )

        # Collector errors from the manifest.
        for record in ctx.manifest.get("collectors", []) or []:
            if not isinstance(record, dict):
                continue
            name = str(record.get("name", "(unknown)"))
            errors = record.get("errors") or []
            failed = record.get("status") == "failed"
            if not failed and not errors:
                continue
            first = str(errors[0]) if errors else "unknown error"
            if failed:
                conclusion = (
                    f"Collector '{name}' failed and its evidence is missing from "
                    f"this analysis: {first}"
                )
            else:
                conclusion = (
                    f"Collector '{name}' reported {len(errors)} error(s) during "
                    f"collection; some of its evidence may be missing (first: {first})"
                )
            out.append(self._limitation(ctx, "collector_error", name, conclusion))

        has_history = any(ctx.get(cat) for cat in _HISTORICAL_CATEGORIES)

        # Process auditing appears off: history exists but not a single
        # process-start observation, from any source. Per CONTRACTS.md §4 the
        # trigger is the absence of ANY process_activity start observation —
        # analyzers never key logic on platform channel values.
        # TaskScheduler action_start events are scheduled_activity, not
        # process_activity, so they never count here.
        if has_history and not self._has_process_starts(ctx):
            out.append(
                self._limitation(
                    ctx,
                    "no_process_auditing",
                    None,
                    "No process-start events were observed in the available "
                    "history; process-creation auditing may be disabled or "
                    "unavailable, so process-level execution detail is missing.",
                )
            )

        # Security channel absent, unreadable, or empty.
        security = self._find_security(channels)
        if security is None:
            out.append(
                self._limitation(
                    ctx,
                    "no_security_log",
                    "Security",
                    "The Security event log was not found in the channel inventory; "
                    "no logon or audit history is available for this analysis.",
                )
            )
        elif security.error is not None:
            out.append(
                self._limitation(
                    ctx,
                    "no_security_log",
                    security.channel,
                    f"The Security event log could not be read "
                    f"({security.error}); no logon or audit history is available "
                    f"for this analysis.",
                    [security.obs_id],
                )
            )
        elif security.record_count == 0:
            out.append(
                self._limitation(
                    ctx,
                    "no_security_log",
                    security.channel,
                    "The Security event log contains no records; no logon or audit "
                    "history is available for this analysis.",
                    [security.obs_id],
                )
            )

        if not has_history:
            out.append(
                self._limitation(
                    ctx,
                    "no_history",
                    None,
                    "No historical event observations were collected; analysis is "
                    "limited to configuration and current state, and absence of "
                    "activity cannot be assessed.",
                )
            )

        return out

    @staticmethod
    def _find_security(channels: list[_Channel]) -> _Channel | None:
        for chan in channels:
            if chan.channel.lower() == _SECURITY_CHANNEL:
                return chan
        return None

    @staticmethod
    def _has_process_starts(ctx: AnalysisContext) -> bool:
        return any(
            obs.action == "start" for obs in ctx.get(Category.PROCESS_ACTIVITY)
        )

    def _limitation(
        self,
        ctx: AnalysisContext,
        kind: str,
        subject: str | None,
        conclusion: str,
        supporting: list[str] | None = None,
    ) -> Finding:
        return Finding(
            id=ctx.next_finding_id(),
            finding_type=FindingType.LIMITATION,
            analyzer=self.name,
            conclusion=conclusion,
            evidence_class=EVIDENCE_UNKNOWN,
            supporting_observations=list(supporting or []),
            details={"kind": kind, "subject": subject},
        )


ANALYZER = CoverageAnalyzer()
