"""Peer dependency analyzer.

Groups remote endpoints seen in current established sockets and in historical
activity into ``peer_dependency`` findings (CONTRACTS.md §4). Logon
observations are deliberately excluded — a logon's source address is inbound,
not an outbound dependency. Loopback, unspecified, and link-local addresses
are filtered out.
"""

from __future__ import annotations

import ipaddress

from ..model import EVIDENCE_OBSERVED, Category, Finding, FindingType
from .base import AnalysisContext, Analyzer

# Historical categories that may carry remote_host; logon is excluded by contract.
_HISTORICAL_CATEGORIES = (
    Category.EVENT,
    Category.PROCESS_ACTIVITY,
    Category.SERVICE_ACTIVITY,
    Category.SCHEDULED_ACTIVITY,
    Category.SYSTEM_LIFECYCLE,
)

_MAX_FINDINGS = 25
_MAX_PROCESSES = 5
_SUPPORTING_CAP = 50

# Exact well-known port map from CONTRACTS.md §4 — no additions.
_PORT_HINTS = {
    22: "ssh/sftp",
    25: "smtp",
    53: "dns",
    80: "http",
    88: "kerberos",
    135: "msrpc",
    389: "ldap",
    443: "https",
    445: "smb",
    587: "smtp",
    636: "ldaps",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5985: "winrm",
    5986: "winrm",
    6379: "redis",
    8080: "http-alt",
    9389: "adws",
    27017: "mongodb",
}

_EVIDENCE_TEXT = {
    "current": "currently connected at collection time",
    "historical": "seen in historical activity",
    "both": "currently connected and seen in historical activity",
}


def _is_filtered_address(host: str) -> bool:
    """True for loopback / unspecified / link-local (IPv4 and IPv6).

    Non-IP values (hostnames) are kept — they are still valid peers.
    """
    text = host.split("%", 1)[0].strip()  # drop IPv6 zone id if present
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_unspecified or addr.is_link_local


def _basename(path: str) -> str:
    tail = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return tail or path


class PeersAnalyzer(Analyzer):
    name = "peers"
    required_categories = (Category.SOCKET_STATE,) + _HISTORICAL_CATEGORIES

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        # (remote_host, remote_port|None) -> group data; null port is its own group
        groups: dict[tuple[str, int | None], dict] = {}

        for obs in ctx.observations:  # already sorted (timestamp, id)
            if obs.category == Category.SOCKET_STATE:
                if obs.action != "established":
                    continue
                evidence_kind = "current"
            elif obs.category in _HISTORICAL_CATEGORIES:
                evidence_kind = "historical"
            else:
                continue
            if not obs.remote_host or _is_filtered_address(obs.remote_host):
                continue
            key = (obs.remote_host, obs.remote_port)
            group = groups.setdefault(
                key,
                {"obs_ids": [], "current": False, "historical": False, "processes": {}},
            )
            group["obs_ids"].append(obs.id)
            group[evidence_kind] = True
            if obs.process:
                proc = _basename(obs.process)
                group["processes"][proc] = group["processes"].get(proc, 0) + 1

        def sort_key(item: tuple[tuple[str, int | None], dict]):
            (host, port), group = item
            # count desc, then host asc, then numeric port asc with null last
            return (
                -len(group["obs_ids"]),
                host,
                port is None,
                port if port is not None else 0,
            )

        ordered = sorted(groups.items(), key=sort_key)
        omitted = max(0, len(ordered) - _MAX_FINDINGS)
        emitted = ordered[:_MAX_FINDINGS]

        findings: list[Finding] = []
        for index, ((host, port), group) in enumerate(emitted):
            count = len(group["obs_ids"])
            if group["current"] and group["historical"]:
                evidence = "both"
            elif group["current"]:
                evidence = "current"
            else:
                evidence = "historical"
            processes = [
                name
                for name, _ in sorted(
                    group["processes"].items(), key=lambda kv: (-kv[1], kv[0])
                )[:_MAX_PROCESSES]
            ]
            hint = _PORT_HINTS.get(port) if port is not None else None
            details = {
                "remote_host": host,
                "remote_port": port,
                "count": count,
                "evidence": evidence,
                "processes": processes,
                "service_hint": hint,
            }
            supporting = group["obs_ids"][:_SUPPORTING_CAP]
            if count > _SUPPORTING_CAP:
                details["supporting_capped"] = True
                details["supporting_total"] = count
            if omitted and index == len(emitted) - 1:
                details["peers_omitted"] = omitted
            label = f"{host}:{port}" if port is not None else host
            hint_text = f" ({hint})" if hint else ""
            findings.append(
                Finding(
                    id=ctx.next_finding_id(),
                    finding_type=FindingType.PEER_DEPENDENCY,
                    analyzer=self.name,
                    conclusion=(
                        f"Remote peer {label}{hint_text}: {count} observation(s); "
                        f"{_EVIDENCE_TEXT[evidence]}."
                    ),
                    evidence_class=EVIDENCE_OBSERVED,
                    supporting_observations=supporting,
                    details=details,
                )
            )
        return findings


ANALYZER = PeersAnalyzer()
