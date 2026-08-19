"""Frequency analyzer.

Produces exactly one frequency_summary finding: top-N counts of providers,
event IDs, principals, services, scheduled actions, processes, and remote
endpoints across the bundle. Purely descriptive — no interpretation.

Providers/event IDs are counted across all historical event categories.
Principals, services, scheduled actions, processes, and remote endpoints are
counted from the normalized fields wherever they appear (historical and
current-state observations alike). Machine accounts and well-known noise
principals are split into a separate system_principals list. Processes are
grouped by basename, with the most common full path per basename recorded in
process_paths.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

from ..model import (
    EVIDENCE_OBSERVED,
    Category,
    Finding,
    FindingType,
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

# Well-known noise principals, matched case-insensitively on the name part
# (with or without a domain prefix). Machine accounts end with "$".
_NOISE_PRINCIPALS = frozenset(
    {
        "SYSTEM",
        "LOCALSYSTEM",
        "LOCAL SERVICE",
        "LOCALSERVICE",
        "NETWORK SERVICE",
        "NETWORKSERVICE",
        "ANONYMOUS LOGON",
    }
)

_MAX_SUPPORTING = 50
_DEFAULT_TOP_N = 10


def _is_system_principal(principal: str) -> bool:
    short = principal.rsplit("\\", 1)[-1]
    return short.endswith("$") or short.upper() in _NOISE_PRINCIPALS


def _basename(path: str) -> str:
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    return base or path


def _as_opt_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _is_noise_host(host: str) -> bool:
    """Loopback / unspecified endpoints are local noise, not remote peers."""
    if not host or host == "-":
        return True
    try:
        addr = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return False  # hostname or unparseable address — keep it
    return addr.is_loopback or addr.is_unspecified


def _top(counter: Counter, n: int) -> list[list[Any]]:
    ranked = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return [[name, count] for name, count in ranked[:n]]


class FrequencyAnalyzer(Analyzer):
    name = "frequency"
    required_categories = ()  # always runs; empty bundle yields empty lists

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        top_n = _as_opt_int(ctx.options.get("top_n")) or _DEFAULT_TOP_N

        providers: Counter = Counter()
        event_ids: Counter = Counter()
        principals: Counter = Counter()
        system_principals: Counter = Counter()
        services: Counter = Counter()
        scheduled_actions: Counter = Counter()
        processes: Counter = Counter()
        path_variants: dict[str, Counter] = {}
        remote_hosts: Counter = Counter()
        remote_ports: Counter = Counter()
        supporting: list[str] = []
        historical_count = 0

        for obs in ctx.observations:
            contributed = False
            if obs.category in _HISTORICAL_CATEGORIES:
                historical_count += 1
                attrs = obs.attributes or {}
                provider = attrs.get("provider")
                if isinstance(provider, str) and provider:
                    providers[provider] += 1
                    contributed = True
                    event_id = _as_opt_int(attrs.get("event_id"))
                    if event_id is not None:
                        event_ids[f"{provider}:{event_id}"] += 1

            if isinstance(obs.principal, str) and obs.principal:
                if _is_system_principal(obs.principal):
                    system_principals[obs.principal] += 1
                else:
                    principals[obs.principal] += 1
                contributed = True

            if isinstance(obs.service, str) and obs.service:
                services[obs.service] += 1
                contributed = True

            if isinstance(obs.scheduled_action, str) and obs.scheduled_action:
                scheduled_actions[obs.scheduled_action] += 1
                contributed = True

            if isinstance(obs.process, str) and obs.process:
                base = _basename(obs.process)
                processes[base] += 1
                path_variants.setdefault(base, Counter())[obs.process] += 1
                contributed = True

            host_is_noise = (
                _is_noise_host(obs.remote_host)
                if isinstance(obs.remote_host, str)
                else False
            )
            if isinstance(obs.remote_host, str) and obs.remote_host and not host_is_noise:
                remote_hosts[obs.remote_host] += 1
                contributed = True
            if not host_is_noise:
                port = _as_opt_int(obs.remote_port)
                if port is not None:
                    remote_ports[str(port)] += 1
                    contributed = True

            if contributed:
                supporting.append(obs.id)

        top_processes = _top(processes, top_n)
        process_paths: dict[str, str] = {}
        for name, _count in top_processes:
            variants = path_variants.get(name)
            if variants:
                best = sorted(variants.items(), key=lambda kv: (-kv[1], kv[0]))
                process_paths[name] = best[0][0]

        details: dict[str, Any] = {
            "top_providers": _top(providers, top_n),
            "top_event_ids": _top(event_ids, top_n),
            "top_principals": _top(principals, top_n),
            "top_services": _top(services, top_n),
            "top_scheduled_actions": _top(scheduled_actions, top_n),
            "top_processes": top_processes,
            "top_remote_hosts": _top(remote_hosts, top_n),
            "top_remote_ports": _top(remote_ports, top_n),
            "system_principals": _top(system_principals, top_n),
            "process_paths": process_paths,
        }

        supporting_total = len(supporting)
        if supporting_total > _MAX_SUPPORTING:
            details["supporting_capped"] = True
            details["supporting_total"] = supporting_total
            supporting = supporting[:_MAX_SUPPORTING]

        total = len(ctx.observations)
        if total == 0:
            conclusion = (
                "No observations were available in this bundle; there is no "
                "activity to summarize."
            )
        else:
            conclusion = (
                f"Frequency summary over {total} observation(s), including "
                f"{historical_count} historical event(s)"
            )
            top_prov = details["top_providers"]
            if top_prov:
                conclusion += (
                    f"; most frequent event provider: {top_prov[0][0]} "
                    f"({top_prov[0][1]} events)"
                )
            conclusion += "."

        return [
            Finding(
                id=ctx.next_finding_id(),
                finding_type=FindingType.FREQUENCY_SUMMARY,
                analyzer=self.name,
                conclusion=conclusion,
                evidence_class=EVIDENCE_OBSERVED,
                supporting_observations=supporting,
                details=details,
            )
        ]


ANALYZER = FrequencyAnalyzer()
