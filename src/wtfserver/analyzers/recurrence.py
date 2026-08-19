"""Recurrence analyzer.

Detects scheduled actions with at least three observed starts and
characterizes their cadence deterministically from the gaps between
consecutive starts (CONTRACTS.md section 4, recurring_scheduled_activity).
"""

from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime

from ..model import (
    EVIDENCE_OBSERVED,
    Category,
    Finding,
    FindingType,
    Observation,
    to_iso,
)
from .base import AnalysisContext, Analyzer

_SUPPORTING_CAP = 50
_MIN_STARTS = 3

_DAY_SECONDS = 86400.0
_DAY_TOLERANCE = 3600.0
_HOUR_SECONDS = 3600.0
_HOUR_TOLERANCE = 300.0
# "Weekend gaps ~2-3 days": accept two to three days, widened by the daily
# tolerance at each end.
_WEEKEND_GAP_MIN = 2 * _DAY_SECONDS - 2 * _DAY_TOLERANCE
_WEEKEND_GAP_MAX = 3 * _DAY_SECONDS + 2 * _DAY_TOLERANCE

# "interval" requires a stable gap: MAD < 20% of the median gap.
_STABLE_MAD_FRACTION = 0.2


def _most_common(values: list[str | None]) -> str | None:
    """Most common non-empty value; ties broken by name ascending."""
    counts = Counter(v for v in values if v)
    if not counts:
        return None
    return min(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]


def _in_band(value: float, center: float, tolerance: float) -> bool:
    return abs(value - center) <= tolerance


def _classify_cadence(
    gaps: list[float], start_times: list[datetime]
) -> tuple[str, float, float]:
    """Return (cadence, median_gap_seconds, mad_seconds)."""
    median_gap = float(statistics.median(gaps))
    mad = float(statistics.median([abs(g - median_gap) for g in gaps]))
    if _in_band(median_gap, _DAY_SECONDS, _DAY_TOLERANCE):
        # weekdays is a strict special case of the daily band, so check first.
        all_weekday = all(t.weekday() < 5 for t in start_times)
        has_weekend_gap = any(
            _WEEKEND_GAP_MIN <= g <= _WEEKEND_GAP_MAX for g in gaps
        )
        gaps_explained = all(
            _in_band(g, _DAY_SECONDS, _DAY_TOLERANCE)
            or _WEEKEND_GAP_MIN <= g <= _WEEKEND_GAP_MAX
            for g in gaps
        )
        if all_weekday and has_weekend_gap and gaps_explained:
            return "weekdays", median_gap, mad
        return "daily", median_gap, mad
    if _in_band(median_gap, _HOUR_SECONDS, _HOUR_TOLERANCE):
        return "hourly", median_gap, mad
    if median_gap > 0 and mad < _STABLE_MAD_FRACTION * median_gap:
        return "interval", median_gap, mad
    return "irregular", median_gap, mad


def _typical_time(start_times: list[datetime]) -> str:
    # Plain median of seconds-since-midnight UTC. Start times straddling
    # midnight (e.g. 23:58 vs 00:02) would yield a misleading midpoint;
    # accepted first-build simplification per contract.
    seconds = [t.hour * 3600 + t.minute * 60 + t.second for t in start_times]
    median_seconds = int(statistics.median(seconds))
    return f"{median_seconds // 3600:02d}:{(median_seconds % 3600) // 60:02d}"


class RecurrenceAnalyzer(Analyzer):
    name = "recurrence"
    required_categories = (Category.SCHEDULED_ACTIVITY,)

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        starts: dict[str, list[Observation]] = {}
        action_starts: dict[str, list[Observation]] = {}
        failures: Counter[str] = Counter()
        for obs in ctx.get(Category.SCHEDULED_ACTIVITY):
            task = obs.scheduled_action
            if not task:
                continue
            if obs.action == "start":
                starts.setdefault(task, []).append(obs)
            elif obs.action == "action_start":
                action_starts.setdefault(task, []).append(obs)
            elif obs.action == "failed":
                failures[task] += 1

        # Fallback source for the action executable: configured task state.
        state_process: dict[str, str] = {}
        for obs in ctx.get(Category.SCHEDULED_TASK_STATE):
            if (
                obs.scheduled_action
                and obs.process
                and obs.scheduled_action not in state_process
            ):
                state_process[obs.scheduled_action] = obs.process

        entries: list[dict] = []
        for task, obs_list in starts.items():
            timed = [(o.when(), o) for o in obs_list]
            timed = [(t, o) for t, o in timed if t is not None]
            if len(timed) < _MIN_STARTS:
                continue
            timed.sort(key=lambda pair: (pair[0], pair[1].id))
            times = [t for t, _ in timed]
            gaps = [
                (times[i + 1] - times[i]).total_seconds()
                for i in range(len(times) - 1)
            ]
            cadence, median_gap, mad = _classify_cadence(gaps, times)
            typical = (
                _typical_time(times) if cadence in ("daily", "weekdays") else None
            )
            related = obs_list + action_starts.get(task, [])
            principal = _most_common([o.principal for o in related])
            process = _most_common([o.process for o in related]) or state_process.get(
                task
            )
            entries.append(
                {
                    "scheduled_action": task,
                    "count": len(timed),
                    "first": to_iso(times[0]),
                    "last": to_iso(times[-1]),
                    "cadence": cadence,
                    "interval_seconds": median_gap,
                    "typical_time": typical,
                    "jitter_seconds": mad,
                    "principal": principal,
                    "process": process,
                    "failure_count": failures.get(task, 0),
                    "_support_ids": [o.id for _, o in timed],
                }
            )

        entries.sort(key=lambda e: (-e["count"], e["scheduled_action"]))

        findings: list[Finding] = []
        for entry in entries:
            support_ids = entry.pop("_support_ids")
            supporting = support_ids[:_SUPPORTING_CAP]
            if len(support_ids) > _SUPPORTING_CAP:
                entry["supporting_capped"] = True
                entry["supporting_total"] = len(support_ids)
            findings.append(
                Finding(
                    id=ctx.next_finding_id(),
                    finding_type=FindingType.RECURRING_SCHEDULED_ACTIVITY,
                    analyzer=self.name,
                    conclusion=self._conclusion(entry),
                    evidence_class=EVIDENCE_OBSERVED,
                    rule_id="recurrence.scheduled_start.v1",
                    supporting_observations=supporting,
                    details=entry,
                )
            )
        return findings

    @staticmethod
    def _conclusion(entry: dict) -> str:
        text = (
            f"Scheduled action '{entry['scheduled_action']}' started "
            f"{entry['count']} times between {entry['first']} and "
            f"{entry['last']} (cadence: {entry['cadence']}"
        )
        if entry["typical_time"]:
            text += f", typically around {entry['typical_time']} UTC"
        text += ")"
        if entry["principal"]:
            text += f" as '{entry['principal']}'"
        if entry["process"]:
            text += f" running '{entry['process']}'"
        if entry["failure_count"]:
            text += (
                f"; {entry['failure_count']} failed run(s) for this task were "
                f"observed in the same window"
            )
        text += "."
        return text


ANALYZER = RecurrenceAnalyzer()
