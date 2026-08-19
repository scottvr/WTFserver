"""Configured-but-unobserved analyzer.

Flags services, scheduled tasks, and installed roles that are configured but
show no execution evidence during the available history (CONTRACTS.md §4
configured_but_unobserved). Dormancy can only be assessed when historical
event log evidence exists; without it the analyzer emits a single limitation
finding instead of item findings.
"""

from __future__ import annotations

from ..model import (
    EVIDENCE_CONFIGURED,
    EVIDENCE_UNKNOWN,
    Category,
    Finding,
    FindingType,
    parse_iso,
)
from .base import AnalysisContext, Analyzer, available_window_days

_MAX_FINDINGS = 15

_HISTORICAL_CATEGORIES = (
    Category.EVENT,
    Category.LOGON,
    Category.PROCESS_ACTIVITY,
    Category.SERVICE_ACTIVITY,
    Category.SCHEDULED_ACTIVITY,
    Category.SYSTEM_LIFECYCLE,
)

# Role -> (service name patterns, listening ports). A trailing "*" is a
# prefix wildcard; other patterns match the whole service name. A role is
# flagged only when NONE of its indicators are present: no matching running
# service, no matching listening port, no matching historical service start.
# Per contract, spooler running alone must never flag Print-Server (spooler
# runs everywhere; treat it as "cannot tell", not dormant) — the any-indicator
# rule gives that behavior. Keep this map small and literal.
_ROLE_INDICATORS = {
    "Web-Server": (("w3svc", "iis*"), (80, 443, 8080)),
    "Web-Ftp-Server": (("ftpsvc", "msftpsvc"), (21,)),
    "DNS": (("dns",), (53,)),
    "DHCP": (("dhcpserver",), ()),
    "Print-Server": (("spooler",), (515, 631)),
    "WDS": (("wdsserver",), ()),
    "WSUS": (("wsusservice",), (8530, 8531)),
}
_ROLE_PREFIX_INDICATORS = (("FS-DFS-", ("dfs*",), ()),)


def _window_phrase(window_days: float | None) -> str:
    if window_days is None:
        return "the available history"
    return f"the {window_days:.1f}-day available history"


def _service_pattern_match(name: str, patterns: tuple[str, ...]) -> bool:
    lowered = name.lower()
    for pattern in patterns:
        if pattern.endswith("*"):
            if lowered.startswith(pattern[:-1]):
                return True
        elif lowered == pattern:
            return True
    return False


class ConfiguredUnobservedAnalyzer(Analyzer):
    name = "configured_unobserved"
    required_categories = (
        Category.SERVICE_STATE,
        Category.SCHEDULED_TASK_STATE,
        Category.INSTALLED_ROLE,
    )

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        # Never overstate the window: available_window_days caps the requested
        # window at what the evidence actually retains (CONTRACTS.md §4).
        window_days = available_window_days(ctx)
        window_phrase = _window_phrase(window_days)

        # Any observation in a historical category counts as history,
        # regardless of source — analyzers never key on collector names.
        has_history = any(
            ctx.get(category) for category in _HISTORICAL_CATEGORIES
        )
        if not has_history:
            return [
                Finding(
                    id=ctx.next_finding_id(),
                    finding_type=FindingType.LIMITATION,
                    analyzer=self.name,
                    conclusion=(
                        "Configured services, scheduled tasks, and installed roles "
                        "cannot be assessed for dormancy: the bundle contains no "
                        "historical evidence."
                    ),
                    evidence_class=EVIDENCE_UNKNOWN,
                    details={"kind": "no_history", "subject": "configured_unobserved"},
                )
            ]

        activity_obs = ctx.get(Category.SERVICE_ACTIVITY) + ctx.get(Category.PROCESS_ACTIVITY)
        scheduled_paths = {
            obs.scheduled_action
            for obs in ctx.get(Category.SCHEDULED_ACTIVITY)
            if obs.scheduled_action
        }
        running_services = [
            obs.service
            for obs in ctx.get(Category.SERVICE_STATE)
            if obs.service and (obs.attributes.get("state") or "").lower() == "running"
        ]
        started_services = [
            obs.service
            for obs in ctx.get(Category.SERVICE_ACTIVITY)
            if obs.service and obs.action == "start"
        ]
        listening_ports = set()
        for obs in ctx.get(Category.SOCKET_STATE):
            if obs.action == "listening":
                port = obs.attributes.get("local_port")
                if isinstance(port, int):
                    listening_ports.add(port)

        def service_referenced(*names: str | None) -> bool:
            # Many platforms log service activity under the display name
            # rather than the short name (e.g. 'Windows Update' vs wuauserv),
            # so match every provided name case-insensitively against both
            # the activity's service field and its message.
            needles = [name.lower() for name in names if name]
            for obs in activity_obs:
                service = obs.service.lower() if obs.service else None
                message = obs.message.lower() if obs.message else None
                for needle in needles:
                    if service and needle in service:
                        return True
                    if message and needle in message:
                        return True
            return False

        # (priority, name-lower, kind, conclusion, details, supporting)
        candidates: list[tuple[int, str, str, str, dict, list[str]]] = []

        for obs in ctx.get(Category.SERVICE_STATE):
            name = obs.service
            if not name:
                continue
            start_mode = (obs.attributes.get("start_mode") or "").lower()
            state = (obs.attributes.get("state") or "").lower()
            if start_mode not in ("auto", "manual") or state != "stopped":
                continue
            display_name = obs.attributes.get("display_name")
            if not isinstance(display_name, str):
                display_name = None
            if service_referenced(name, display_name):
                continue
            details = {
                "kind": "service",
                "name": name,
                "configured_state": f"{start_mode}-start, stopped",
                "window_days": window_days,
                "note": None,
            }
            conclusion = (
                f"Service '{name}' is configured ({start_mode}-start) but stopped, "
                f"and no related service or process activity was observed during "
                f"{window_phrase}."
            )
            priority = 0 if start_mode == "auto" else 1
            candidates.append((priority, name.lower(), "service", conclusion, details, [obs.id]))

        for obs in ctx.get(Category.SCHEDULED_TASK_STATE):
            path = obs.scheduled_action
            if not path:
                continue
            if obs.attributes.get("enabled") is not True:
                continue
            if path in scheduled_paths:
                continue
            last_run = obs.attributes.get("last_run")
            if last_run is None:
                note = "task state reports no last run"
            else:
                if ctx.since is None:
                    # --since max: a recorded last_run means the task ran at
                    # some point; without a window start we cannot call it
                    # dormant, so do not flag (conservative).
                    continue
                last_run_dt = parse_iso(last_run)
                if last_run_dt is None or last_run_dt >= ctx.since:
                    continue
                note = f"last run {last_run} predates the analysis window"
            details = {
                "kind": "scheduled_action",
                "name": path,
                "configured_state": "enabled",
                "window_days": window_days,
                "note": note,
            }
            conclusion = (
                f"Scheduled task '{path}' is enabled but no execution was observed "
                f"during {window_phrase} ({note})."
            )
            candidates.append((1, path.lower(), "scheduled_action", conclusion, details, [obs.id]))

        for obs in ctx.get(Category.INSTALLED_ROLE):
            role_name = obs.attributes.get("name")
            if not role_name:
                continue
            indicators = _ROLE_INDICATORS.get(role_name)
            if indicators is None:
                for prefix, patterns, ports in _ROLE_PREFIX_INDICATORS:
                    if role_name.startswith(prefix):
                        indicators = (patterns, ports)
                        break
            if indicators is None:
                continue  # role not in the literal map: never flagged
            patterns, ports = indicators
            if any(_service_pattern_match(s, patterns) for s in running_services):
                continue
            if any(_service_pattern_match(s, patterns) for s in started_services):
                continue
            if any(port in listening_ports for port in ports):
                continue
            details = {
                "kind": "role",
                "name": role_name,
                "configured_state": "installed",
                "window_days": window_days,
                "note": "no matching running service, listening port, or service activity",
            }
            conclusion = (
                f"Role '{role_name}' is installed but no matching running service, "
                f"listening port, or service activity was observed during "
                f"{window_phrase}."
            )
            candidates.append((1, role_name.lower(), "role", conclusion, details, [obs.id]))

        candidates.sort(key=lambda item: (item[0], item[1], item[2]))
        omitted = max(0, len(candidates) - _MAX_FINDINGS)
        emitted = candidates[:_MAX_FINDINGS]

        findings: list[Finding] = []
        for index, (_prio, _key, _kind, conclusion, details, supporting) in enumerate(emitted):
            if omitted and index == len(emitted) - 1:
                details["omitted"] = omitted
                conclusion += (
                    f" {omitted} additional configured-but-unobserved item(s) "
                    f"omitted (cap {_MAX_FINDINGS})."
                )
            findings.append(
                Finding(
                    id=ctx.next_finding_id(),
                    finding_type=FindingType.CONFIGURED_BUT_UNOBSERVED,
                    analyzer=self.name,
                    conclusion=conclusion,
                    evidence_class=EVIDENCE_CONFIGURED,
                    supporting_observations=supporting,
                    details=details,
                )
            )
        return findings


ANALYZER = ConfiguredUnobservedAnalyzer()
