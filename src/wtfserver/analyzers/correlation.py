"""Correlation analyzer.

Finds repeated activity episodes: an anchor event (scheduled start, service
start, or interactive/remote-interactive/batch logon) plus the observations
that consistently occur in a short window around it (CONTRACTS.md section 4,
activity_episode).
"""

from __future__ import annotations

import statistics
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from datetime import datetime, timedelta

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
_MAX_SEQUENCE_STEPS = 12
_MIN_OCCURRENCES = 3
_JACCARD_THRESHOLD = 0.6
_DEFAULT_BEFORE_SECONDS = 5.0
_DEFAULT_AFTER_SECONDS = 300.0

_ANCHOR_LOGON_KINDS = ("interactive", "remote_interactive", "batch")

# A member kind is (category, action, name).
_Kind = tuple[str, str, str]


def _basename(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or path


def _anchor_identity(obs: Observation) -> _Kind | None:
    """(category, action, name) if the observation is an anchor, else None."""
    if obs.category == Category.SCHEDULED_ACTIVITY and obs.action == "start":
        if obs.scheduled_action:
            return (obs.category, obs.action, obs.scheduled_action)
        return None
    if obs.category == Category.SERVICE_ACTIVITY and obs.action == "start":
        if obs.service:
            return (obs.category, obs.action, obs.service)
        return None
    if obs.category == Category.LOGON and obs.action == "logon":
        kind = obs.attributes.get("logon_kind")
        if kind in _ANCHOR_LOGON_KINDS and obs.principal:
            return (obs.category, obs.action, obs.principal)
        return None
    return None


def _member_name(obs: Observation) -> str | None:
    """Contract name-field per category; None means not usable as a member."""
    cat = obs.category
    if (
        cat == Category.SCHEDULED_ACTIVITY
        and obs.action in ("action_start", "action_complete")
        and obs.process
    ):
        # For task action events the executable is the informative name.
        return _basename(obs.process)
    if cat in (Category.SERVICE_ACTIVITY, Category.SERVICE_STATE):
        return obs.service
    if cat in (Category.SCHEDULED_ACTIVITY, Category.SCHEDULED_TASK_STATE):
        return obs.scheduled_action
    if cat in (Category.PROCESS_ACTIVITY, Category.PROCESS_STATE):
        return _basename(obs.process) if obs.process else None
    if cat == Category.SOCKET_STATE and obs.remote_host:
        if obs.remote_port is not None:
            return f"{obs.remote_host}:{obs.remote_port}"
        return obs.remote_host
    if cat == Category.LOGON:
        return obs.principal
    # Generic fallback: first available name field, in contract order.
    if obs.service:
        return obs.service
    if obs.scheduled_action:
        return obs.scheduled_action
    if obs.process:
        return _basename(obs.process)
    if obs.remote_host:
        if obs.remote_port is not None:
            return f"{obs.remote_host}:{obs.remote_port}"
        return obs.remote_host
    if obs.principal:
        return obs.principal
    return None


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


@dataclass
class _Occurrence:
    anchor_id: str
    time: datetime
    kinds: frozenset
    offsets: dict[_Kind, float]  # kind -> earliest offset seconds from anchor
    member_ids: dict[_Kind, str]  # kind -> obs id at that earliest offset


class CorrelationAnalyzer(Analyzer):
    name = "correlation"
    required_categories = (
        Category.SCHEDULED_ACTIVITY,
        Category.SERVICE_ACTIVITY,
        Category.LOGON,
    )

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        before = float(ctx.options.get("correlation_before", _DEFAULT_BEFORE_SECONDS))
        after = float(ctx.options.get("correlation_after", _DEFAULT_AFTER_SECONDS))

        # ctx.observations is sorted (timestamp, id) with untimestamped last;
        # keep only timestamped observations for windowing.
        timed: list[tuple[datetime, Observation]] = []
        for obs in ctx.observations:
            when = obs.when()
            if when is not None:
                timed.append((when, obs))
        times = [t for t, _ in timed]

        groups: dict[_Kind, list[_Occurrence]] = {}
        for when, obs in timed:
            identity = _anchor_identity(obs)
            if identity is None:
                continue
            lo = bisect_left(times, when - timedelta(seconds=before))
            hi = bisect_right(times, when + timedelta(seconds=after))
            offsets: dict[_Kind, float] = {}
            member_ids: dict[_Kind, str] = {}
            for member_time, member in timed[lo:hi]:
                if member.id == obs.id:
                    continue
                if _anchor_identity(member) == identity:
                    # Other occurrences of the same anchor are not members.
                    continue
                name = _member_name(member)
                if name is None:
                    continue
                kind = (member.category, member.action or "", name)
                if kind not in offsets:
                    # Time-ordered scan: first hit is the earliest offset.
                    offsets[kind] = (member_time - when).total_seconds()
                    member_ids[kind] = member.id
            groups.setdefault(identity, []).append(
                _Occurrence(obs.id, when, frozenset(offsets), offsets, member_ids)
            )

        episodes: list[dict] = []
        for identity, occurrences in groups.items():
            # Greedy clustering in time order: an occurrence joins the first
            # cluster whose representative (first occurrence) is similar enough.
            clusters: list[list[_Occurrence]] = []
            for occ in occurrences:
                for cluster in clusters:
                    if _jaccard(cluster[0].kinds, occ.kinds) >= _JACCARD_THRESHOLD:
                        cluster.append(occ)
                        break
                else:
                    clusters.append([occ])
            for cluster in clusters:
                episode = self._build_episode(identity, cluster)
                if episode is not None:
                    episodes.append(episode)

        episodes.sort(
            key=lambda e: (
                -e["occurrences"],
                e["anchor"]["name"],
                e["anchor"]["category"],
                e["anchor"]["action"],
                e["first"],
            )
        )
        return [self._to_finding(ctx, episode) for episode in episodes]

    @staticmethod
    def _build_episode(identity: _Kind, cluster: list[_Occurrence]) -> dict | None:
        if len(cluster) < _MIN_OCCURRENCES:
            return None
        occurrences = len(cluster)
        seen: dict[_Kind, int] = {}
        for occ in cluster:
            for kind in occ.kinds:
                seen[kind] = seen.get(kind, 0) + 1
        steps = []
        for kind, count in seen.items():
            if count * 2 < occurrences:
                continue  # below 50% presence
            offsets = [occ.offsets[kind] for occ in cluster if kind in occ.offsets]
            steps.append(
                {
                    "category": kind[0],
                    "action": kind[1],
                    "name": kind[2],
                    "typical_offset_seconds": float(statistics.median(offsets)),
                    "seen_in": count,
                }
            )
        if not steps:
            # Nothing beyond the anchor itself repeats; not an episode.
            return None
        steps.sort(
            key=lambda s: (
                s["typical_offset_seconds"],
                s["name"],
                s["category"],
                s["action"],
            )
        )
        steps = steps[:_MAX_SEQUENCE_STEPS]

        member_support: list[str] = []
        for step in steps:
            kind = (step["category"], step["action"], step["name"])
            for occ in cluster:
                if kind in occ.member_ids:
                    member_support.append(occ.member_ids[kind])
                    break

        category, action, name = identity
        return {
            "anchor": {"category": category, "action": action, "name": name},
            "occurrences": occurrences,
            "first": to_iso(cluster[0].time),
            "last": to_iso(cluster[-1].time),
            "typical_sequence": steps,
            "_anchor_ids": [occ.anchor_id for occ in cluster],
            "_member_ids": member_support,
        }

    def _to_finding(self, ctx: AnalysisContext, episode: dict) -> Finding:
        anchor_ids = episode.pop("_anchor_ids")
        member_ids = episode.pop("_member_ids")
        total = len(anchor_ids) + len(member_ids)
        if total > _SUPPORTING_CAP:
            # Reserve room for member examples so anchors don't crowd them out.
            keep_anchors = max(_SUPPORTING_CAP - len(member_ids), 0)
            supporting = (
                anchor_ids[:keep_anchors]
                + member_ids[: _SUPPORTING_CAP - keep_anchors]
            )
            episode["supporting_capped"] = True
            episode["supporting_total"] = total
        else:
            supporting = anchor_ids + member_ids

        anchor = episode["anchor"]
        steps_text = ", ".join(
            f"{s['category']} {s['action']} '{s['name']}' "
            f"({s['typical_offset_seconds']:+.0f}s)"
            for s in episode["typical_sequence"]
        )
        conclusion = (
            f"Repeated activity episode anchored by {anchor['category']} "
            f"{anchor['action']} '{anchor['name']}': {episode['occurrences']} "
            f"occurrences between {episode['first']} and {episode['last']}; "
            f"typical sequence: {steps_text}."
        )
        return Finding(
            id=ctx.next_finding_id(),
            finding_type=FindingType.ACTIVITY_EPISODE,
            analyzer=self.name,
            conclusion=conclusion,
            evidence_class=EVIDENCE_OBSERVED,
            rule_id="correlation.episode.v1",
            supporting_observations=supporting,
            details=episode,
        )


ANALYZER = CorrelationAnalyzer()
