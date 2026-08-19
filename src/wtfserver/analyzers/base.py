"""Analyzer interface.

Analyzers consume normalized observations (never raw Windows structures) and
produce findings. They must be deterministic: same bundle in, same findings
out. Analyzers must not read the clock — use ctx.collection_end as "now".
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..model import Finding, Observation, parse_iso


@dataclass
class AnalysisContext:
    manifest: dict[str, Any]
    observations: list[Observation]  # sorted by (timestamp, id); None timestamps last
    by_category: dict[str, list[Observation]]
    since: datetime | None  # resolved analysis window start; None = max
    collection_start: datetime | None
    collection_end: datetime | None  # treat as "now" for all reasoning
    prior_findings: list[Finding] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)
    _finding_seq: int = 0

    def next_finding_id(self) -> str:
        self._finding_seq += 1
        return f"f-{self._finding_seq:04d}"

    def get(self, category: str) -> list[Observation]:
        return self.by_category.get(category, [])

    def findings_of_type(self, finding_type: str) -> list[Finding]:
        return [f for f in self.prior_findings if f.finding_type == finding_type]


def build_context(
    manifest: dict[str, Any],
    observations: list[Observation],
    options: dict[str, Any] | None = None,
) -> AnalysisContext:
    def sort_key(obs: Observation):
        when = obs.when()
        return (when is None, when or datetime.min, obs.id)

    ordered = sorted(observations, key=sort_key)
    by_category: dict[str, list[Observation]] = {}
    for obs in ordered:
        by_category.setdefault(obs.category, []).append(obs)

    since_raw = manifest.get("since_resolved")
    return AnalysisContext(
        manifest=manifest,
        observations=ordered,
        by_category=by_category,
        since=parse_iso(since_raw) if since_raw else None,
        collection_start=parse_iso(manifest.get("collection_start") or ""),
        collection_end=parse_iso(manifest.get("collection_end") or ""),
        options=options or {},
    )


_HISTORICAL_CATEGORIES = (
    "event",
    "logon",
    "process_activity",
    "service_activity",
    "scheduled_activity",
    "system_lifecycle",
)


def available_window_days(ctx: AnalysisContext) -> float | None:
    """Days of history actually available, never more than the requested window.

    Quoting the requested window as "available history" overstates the
    evidence when log retention is shorter. This returns the best
    evidence-channel coverage (oldest retained record, clipped to the window,
    through collection end), falling back to the span of historical
    observations; None when neither exists.
    """
    end = ctx.collection_end
    if end is None:
        return None

    best: float | None = None
    for obs in ctx.get("evidence_channel"):
        attrs = obs.attributes or {}
        oldest = parse_iso(str(attrs.get("oldest_record") or ""))
        if oldest is None:
            continue
        start = max(oldest, ctx.since) if ctx.since else oldest
        span = (end - start).total_seconds() / 86400.0
        if span >= 0 and (best is None or span > best):
            best = span

    if best is None:
        stamps = [
            when
            for cat in _HISTORICAL_CATEGORIES
            for obs in ctx.get(cat)
            if (when := obs.when()) is not None
        ]
        if stamps:
            start = min(stamps)
            if ctx.since:
                start = max(start, ctx.since)
            best = (end - start).total_seconds() / 86400.0

    if best is None:
        return None
    if ctx.since is not None:
        requested = (end - ctx.since).total_seconds() / 86400.0
        best = min(best, requested)
    return round(max(best, 0.0), 1)


class Analyzer(ABC):
    """One deterministic analysis pass.

    name: stable identifier, recorded on findings.
    required_categories: categories this analyzer needs; if none of them are
        present in the bundle the runner skips it (empty tuple = always run).
    """

    name: str = ""
    required_categories: tuple[str, ...] = ()

    @abstractmethod
    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        raise NotImplementedError
