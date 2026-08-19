"""Interactive-use analyzer.

Classifies how the host appears to be driven (interactive / service_driven /
batch_scheduled / mixed / apparently_quiet / unknown) from logon-category
observations, per CONTRACTS.md §4 (interactive_use). Emits exactly one
finding. When no logon observations exist the finding is evidence_class
unknown — absence of logon evidence is not evidence the host is unused.
"""

from __future__ import annotations

from ..model import (
    EVIDENCE_OBSERVED,
    EVIDENCE_UNKNOWN,
    Category,
    Finding,
    FindingType,
)
from .base import AnalysisContext, Analyzer

_SUPPORTING_CAP = 50
_MAX_PRINCIPALS = 10

# Historical activity categories, used only for the --since max window
# fallback (see _window_days).
_HISTORICAL_CATEGORIES = (
    Category.EVENT,
    Category.LOGON,
    Category.PROCESS_ACTIVITY,
    Category.SERVICE_ACTIVITY,
    Category.SCHEDULED_ACTIVITY,
    Category.SYSTEM_LIFECYCLE,
)

# Same machine-account/noise filter as the frequency analyzer (CONTRACTS.md
# §4): machine accounts end in "$"; noise principals match with or without a
# domain prefix, case-insensitively.
_NOISE_PRINCIPALS = {
    "system",
    "localsystem",
    "local service",
    "localservice",
    "network service",
    "networkservice",
    "anonymous logon",
}

_CLASSIFICATION_LEAD = {
    "interactive": "Interactive use observed",
    "batch_scheduled": "Logon activity appears batch/scheduled-driven",
    "service_driven": "Logon activity appears service-driven",
    "mixed": "Mixed logon activity observed",
    "apparently_quiet": "Host appears quiet during the observed window",
}


def _is_noise_principal(principal: str) -> bool:
    short = principal.rsplit("\\", 1)[-1].strip()
    if short.endswith("$"):
        return True
    return short.lower() in _NOISE_PRINCIPALS


def _window_days(ctx: AnalysisContext) -> float | None:
    # Window choice: when a window start was resolved (--since Nh), the window
    # is since..collection_end. With --since max (since is None) there is no
    # requested start, so fall back to the span of ALL historical observations
    # present in the bundle; None when no historical timestamps exist.
    if ctx.since is not None and ctx.collection_end is not None:
        return round((ctx.collection_end - ctx.since).total_seconds() / 86400.0, 2)
    stamps = []
    for category in _HISTORICAL_CATEGORIES:
        for obs in ctx.get(category):
            when = obs.when()
            if when is not None:
                stamps.append(when)
    if not stamps:
        return None
    return round((max(stamps) - min(stamps)).total_seconds() / 86400.0, 2)


def _window_phrase(window_days: float | None) -> str:
    if window_days is None:
        return "the available history"
    return f"the {window_days:.1f}-day available history"


class InteractiveAnalyzer(Analyzer):
    name = "interactive"
    # Must run even when the bundle has no logon evidence: the contract
    # requires exactly one finding (evidence_class unknown in that case).
    required_categories = ()

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        logons = ctx.get(Category.LOGON)
        window_days = _window_days(ctx)
        window_phrase = _window_phrase(window_days)

        counts = {
            "interactive": 0,
            "remote_interactive": 0,
            "network": 0,
            "batch": 0,
            "service": 0,
        }
        failed = 0
        principal_counts: dict[str, int] = {}
        interactive_stamps: list[tuple[object, str]] = []

        for obs in logons:  # already sorted (timestamp, id)
            if obs.action == "logon_failed":
                failed += 1
                continue
            if obs.action != "logon":
                continue  # logoffs are evidence of logon activity but not a kind
            kind = obs.attributes.get("logon_kind")
            if kind in counts:
                counts[kind] += 1
            if kind in ("interactive", "remote_interactive"):
                when = obs.when()
                if when is not None and obs.timestamp:
                    interactive_stamps.append((when, obs.timestamp))
                if obs.principal and not _is_noise_principal(obs.principal):
                    principal_counts[obs.principal] = principal_counts.get(obs.principal, 0) + 1

        classification = self._classify(bool(logons), counts, failed)

        principals = sorted(principal_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        interactive_principals = [[name, count] for name, count in principals[:_MAX_PRINCIPALS]]

        interactive_stamps.sort(key=lambda pair: pair[0])
        first_interactive = interactive_stamps[0][1] if interactive_stamps else None
        last_interactive = interactive_stamps[-1][1] if interactive_stamps else None

        details = {
            "classification": classification,
            "interactive_logons": counts["interactive"],
            "remote_interactive_logons": counts["remote_interactive"],
            "batch_logons": counts["batch"],
            "service_logons": counts["service"],
            "network_logons": counts["network"],
            "failed_logons": failed,
            "interactive_principals": interactive_principals,
            "first_interactive": first_interactive,
            "last_interactive": last_interactive,
            "window_days": window_days,
        }

        if classification == "unknown":
            conclusion = (
                f"No logon evidence available during {window_phrase}; "
                "how this host is used cannot be assessed from logon activity."
            )
            evidence_class = EVIDENCE_UNKNOWN
        else:
            summary = (
                f"{counts['interactive']} interactive, "
                f"{counts['remote_interactive']} remote-interactive, "
                f"{counts['batch']} batch, {counts['service']} service, and "
                f"{counts['network']} network logon(s), with {failed} failed "
                f"logon(s), over {window_phrase}"
            )
            conclusion = f"{_CLASSIFICATION_LEAD[classification]}: {summary}."
            evidence_class = EVIDENCE_OBSERVED

        supporting = [obs.id for obs in logons]
        if len(supporting) > _SUPPORTING_CAP:
            details["supporting_capped"] = True
            details["supporting_total"] = len(supporting)
            supporting = supporting[:_SUPPORTING_CAP]

        return [
            Finding(
                id=ctx.next_finding_id(),
                finding_type=FindingType.INTERACTIVE_USE,
                analyzer=self.name,
                conclusion=conclusion,
                evidence_class=evidence_class,
                supporting_observations=supporting,
                details=details,
            )
        ]

    @staticmethod
    def _classify(has_logons: bool, counts: dict[str, int], failed: int) -> str:
        # Rule order per CONTRACTS.md §4. "2x interactive" is read as 2x the
        # combined interactive+remote_interactive count (the quantity the
        # rule's head tests).
        if not has_logons:
            return "unknown"
        ir = counts["interactive"] + counts["remote_interactive"]
        batch = counts["batch"]
        service = counts["service"]
        if ir >= 5 and (batch + service) < 2 * ir:
            return "interactive"
        if batch >= 5 and batch >= 2 * ir:
            return "batch_scheduled"
        if service >= 5 and service >= 2 * ir:
            return "service_driven"
        if ir >= 1 and (batch + service) >= 5:
            return "mixed"
        if all(v < 5 for v in (*counts.values(), failed)):
            return "apparently_quiet"
        return "mixed"


ANALYZER = InteractiveAnalyzer()
