"""Process association analyzer.

Scans historical observations that carry a process and counts how often that
process (grouped by basename) co-occurs on the same observation with a
scheduled action, service, principal, or remote peer. Pairs that co-occur at
least three times become ``process_association`` findings (CONTRACTS.md §4).
"""

from __future__ import annotations

from ..model import EVIDENCE_OBSERVED, Category, Finding, FindingType, Observation
from .base import AnalysisContext, Analyzer

# Historical activity categories only — current-state observations (running
# processes, configured services, ...) are not co-occurrence evidence.
_HISTORICAL_CATEGORIES = (
    Category.EVENT,
    Category.LOGON,
    Category.PROCESS_ACTIVITY,
    Category.SERVICE_ACTIVITY,
    Category.SCHEDULED_ACTIVITY,
    Category.SYSTEM_LIFECYCLE,
)

_MIN_PAIR_COUNT = 3
_SUPPORTING_CAP = 50

# Same principal filter as the frequency contract: well-known noise
# principals (with or without domain prefix) and machine accounts.
_NOISE_PRINCIPALS = {
    "system",
    "localsystem",
    "local service",
    "localservice",
    "network service",
    "networkservice",
    "anonymous logon",
}


def _is_noise_principal(name: str) -> bool:
    short = name.rsplit("\\", 1)[-1]
    if short.endswith("$"):
        return True
    return short.lower() in _NOISE_PRINCIPALS


def _basename(path: str) -> str:
    tail = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return tail or path


def _associates(obs: Observation) -> list[tuple[str, str]]:
    """(kind, name) pairs present on this observation, in a fixed order."""
    pairs: list[tuple[str, str]] = []
    if obs.scheduled_action:
        pairs.append(("scheduled_action", obs.scheduled_action))
    if obs.service:
        pairs.append(("service", obs.service))
    if obs.principal and not _is_noise_principal(obs.principal):
        pairs.append(("principal", obs.principal))
    if obs.remote_host:
        if obs.remote_port is not None:
            pairs.append(("peer", f"{obs.remote_host}:{obs.remote_port}"))
        else:
            pairs.append(("peer", obs.remote_host))
    return pairs


class AssociationsAnalyzer(Analyzer):
    name = "associations"
    required_categories = _HISTORICAL_CATEGORIES

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        # (process basename, kind, associated name) -> supporting obs ids
        pair_obs: dict[tuple[str, str, str], list[str]] = {}
        process_totals: dict[str, int] = {}
        path_counts: dict[str, dict[str, int]] = {}

        for obs in ctx.observations:  # already sorted (timestamp, id)
            if obs.category not in _HISTORICAL_CATEGORIES or not obs.process:
                continue
            proc = _basename(obs.process)
            process_totals[proc] = process_totals.get(proc, 0) + 1
            paths = path_counts.setdefault(proc, {})
            paths[obs.process] = paths.get(obs.process, 0) + 1
            for kind, assoc_name in _associates(obs):
                pair_obs.setdefault((proc, kind, assoc_name), []).append(obs.id)

        entries = [
            (proc, kind, assoc_name, obs_ids)
            for (proc, kind, assoc_name), obs_ids in pair_obs.items()
            if len(obs_ids) >= _MIN_PAIR_COUNT
        ]
        # count desc, process asc, associated name asc (kind as final tie-break)
        entries.sort(key=lambda e: (-len(e[3]), e[0], e[2], e[1]))

        findings: list[Finding] = []
        for proc, kind, assoc_name, obs_ids in entries:
            count = len(obs_ids)
            variants = path_counts.get(proc, {})
            process_path = None
            if variants:
                process_path = sorted(variants.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            details = {
                "process": proc,
                "process_path": process_path,
                "associated_with": {"kind": kind, "name": assoc_name, "count": count},
                "total_process_observations": process_totals[proc],
            }
            supporting = obs_ids[:_SUPPORTING_CAP]
            if len(obs_ids) > _SUPPORTING_CAP:
                details["supporting_capped"] = True
                details["supporting_total"] = len(obs_ids)
            findings.append(
                Finding(
                    id=ctx.next_finding_id(),
                    finding_type=FindingType.PROCESS_ASSOCIATION,
                    analyzer=self.name,
                    conclusion=(
                        f"Process '{proc}' co-occurred with {kind} '{assoc_name}' "
                        f"in {count} observations during the available history."
                    ),
                    evidence_class=EVIDENCE_OBSERVED,
                    supporting_observations=supporting,
                    details=details,
                )
            )
        return findings


ANALYZER = AssociationsAnalyzer()
