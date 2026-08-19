"""Role inference analyzer.

The only analyzer that reads prior findings. Implements exactly the eight
rules from CONTRACTS.md §4 (role_inference) — no additional cleverness. Every
finding is evidence_class inferred, carries its rule_id, and copies the
supporting observations of the findings/observations the rule built on.
"""

from __future__ import annotations

from typing import Any

from ..model import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    EVIDENCE_INFERRED,
    Category,
    Finding,
    FindingType,
    Observation,
)
from .base import AnalysisContext, Analyzer, available_window_days

_SUPPORTING_CAP = 50

_REGULAR_CADENCES = ("daily", "hourly", "interval", "weekdays")

# Built-in OS maintenance tasks recur on every host and are not evidence of a
# batch-processing purpose. Rule data for role.batch.v1, like the web-server
# service names; compared case-insensitively against the task path prefix.
_BUILTIN_TASK_PREFIX = "\\microsoft\\"

_DB_CLIENT_HINTS = ("mssql", "oracle", "mysql", "postgresql", "redis", "mongodb")
_TRANSFER_HINTS = ("ssh/sftp", "smtp")

# Known DB service name patterns from the contract; trailing * = prefix match,
# bare name = exact match. Case-insensitive.
_DB_SERVICE_PATTERNS = (
    "mssql*",
    "sqlserver*",
    "mysql*",
    "postgres*",
    "oracle*",
    "redis",
    "mongod*",
)

# DB service pattern -> canonical server port for role.db_server.v1.
_DB_SERVER_PORTS = (
    ("mssql*", 1433),
    ("sqlserver*", 1433),
    ("oracle*", 1521),
    ("mysql*", 3306),
    ("postgres*", 5432),
    ("redis", 6379),
    ("mongod*", 27017),
)

_WEB_PORTS = (80, 443, 8080, 8443)
_WEB_NAME_PREFIXES = ("w3wp", "iis", "w3svc", "httpd", "nginx", "tomcat", "apache")

_HISTORICAL_CATEGORIES = (
    Category.EVENT,
    Category.LOGON,
    Category.PROCESS_ACTIVITY,
    Category.SERVICE_ACTIVITY,
    Category.SCHEDULED_ACTIVITY,
    Category.SYSTEM_LIFECYCLE,
)


def _basename(path: str) -> str:
    tail = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return tail or path


def _matches_pattern(name: str, pattern: str) -> bool:
    lowered = name.lower()
    if pattern.endswith("*"):
        return lowered.startswith(pattern[:-1])
    return lowered == pattern


def _matches_any_pattern(name: str, patterns) -> bool:
    return any(_matches_pattern(name, p) for p in patterns)


def _int_or_zero(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


class RolesAnalyzer(Analyzer):
    name = "roles"
    # Works from prior findings; observations only refine — always run.
    required_categories = ()

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        batch = self._rule_batch(ctx)
        findings.extend(batch)
        findings.extend(self._rule_db_client(ctx))
        findings.extend(self._rule_transfer_client(ctx))
        findings.extend(self._rule_web_server(ctx))
        findings.extend(self._rule_db_server(ctx))
        findings.extend(self._rule_dc(ctx))
        findings.extend(self._rule_admin_host(ctx, batch_fired=bool(batch)))
        findings.extend(self._rule_quiet(ctx))
        return findings

    # --- shared helpers -------------------------------------------------

    def _finding(
        self,
        ctx: AnalysisContext,
        rule_id: str,
        role: str,
        conclusion: str,
        evidence_summary: list[str],
        supporting: list[str],
        confidence: str,
    ) -> Finding:
        details: dict[str, Any] = {"role": role, "evidence_summary": evidence_summary}
        ids = list(supporting)
        if len(ids) > _SUPPORTING_CAP:
            details["supporting_capped"] = True
            details["supporting_total"] = len(ids)
            ids = ids[:_SUPPORTING_CAP]
        return Finding(
            id=ctx.next_finding_id(),
            finding_type=FindingType.ROLE_INFERENCE,
            analyzer=self.name,
            conclusion=conclusion,
            evidence_class=EVIDENCE_INFERRED,
            rule_id=rule_id,
            confidence=confidence,
            supporting_observations=ids,
            details=details,
        )

    @staticmethod
    def _running_services(ctx: AnalysisContext) -> list[Observation]:
        out = []
        for obs in ctx.get(Category.SERVICE_STATE):
            if not obs.service:
                continue
            state = obs.attributes.get("state")
            if isinstance(state, str) and state.lower() == "running":
                out.append(obs)
        return out

    @staticmethod
    def _listening_by_port(ctx: AnalysisContext) -> dict[int, list[Observation]]:
        ports: dict[int, list[Observation]] = {}
        for obs in ctx.get(Category.SOCKET_STATE):
            if obs.action != "listening":
                continue
            port = obs.attributes.get("local_port")
            if isinstance(port, int) and not isinstance(port, bool):
                ports.setdefault(port, []).append(obs)
        return ports

    # --- role.batch.v1 --------------------------------------------------

    def _rule_batch(self, ctx: AnalysisContext) -> list[Finding]:
        qualifying = []
        for prior in ctx.findings_of_type(FindingType.RECURRING_SCHEDULED_ACTIVITY):
            details = prior.details or {}
            count = _int_or_zero(details.get("count"))
            cadence = details.get("cadence")
            if count < 5:
                continue
            if cadence is None or cadence == "irregular":
                continue
            if not details.get("principal") and not details.get("process"):
                continue
            task = details.get("scheduled_action")
            if (
                isinstance(task, str)
                and task.lower().startswith(_BUILTIN_TASK_PREFIX)
            ):
                continue  # built-in OS maintenance task, not a batch purpose
            qualifying.append(prior)
        if not qualifying:
            return []
        qualifying.sort(key=lambda f: str((f.details or {}).get("scheduled_action") or ""))

        # One role finding at most, listing every qualifying task.
        summary: list[str] = []
        supporting: list[str] = []
        seen_ids: set[str] = set()
        high = False
        task_names: list[str] = []
        for prior in qualifying:
            details = prior.details
            count = details["count"]
            cadence = details["cadence"]
            task = details.get("scheduled_action") or "(unknown task)"
            task_names.append(task)
            if count >= 10 and cadence in _REGULAR_CADENCES:
                high = True
            bullet = f"{task}: {count} runs, {cadence} cadence"
            if details.get("principal"):
                bullet += f", runs as {details['principal']}"
            if details.get("process"):
                bullet += f", executes {details['process']}"
            summary.append(bullet)
            for obs_id in prior.supporting_observations:
                if obs_id not in seen_ids:
                    seen_ids.add(obs_id)
                    supporting.append(obs_id)

        confidence = CONFIDENCE_HIGH if high else CONFIDENCE_MEDIUM
        if len(qualifying) == 1:
            details = qualifying[0].details
            conclusion = (
                f"Recurring scheduled activity ({task_names[0]}, "
                f"{details['count']} runs, {details['cadence']} cadence) "
                f"indicates a batch/scheduled processing host."
            )
        else:
            names = ", ".join(task_names)
            conclusion = (
                f"{len(qualifying)} recurring scheduled tasks ({names}) "
                f"indicate a batch/scheduled processing host."
            )
        return [
            self._finding(
                ctx,
                "role.batch.v1",
                "batch/scheduled processing host",
                conclusion,
                summary,
                supporting,
                confidence,
            )
        ]

    # --- role.db_client.v1 ----------------------------------------------

    def _rule_db_client(self, ctx: AnalysisContext) -> list[Finding]:
        peers = [
            f
            for f in ctx.findings_of_type(FindingType.PEER_DEPENDENCY)
            if (f.details or {}).get("service_hint") in _DB_CLIENT_HINTS
        ]
        if not peers:
            return []
        # Any running local DB-named service suppresses the rule (the traffic
        # may be its own database); a local listener on the same port
        # suppresses that specific peer.
        db_service_running = any(
            _matches_any_pattern(svc.service, _DB_SERVICE_PATTERNS)
            for svc in self._running_services(ctx)
        )
        if db_service_running:
            return []
        listening = self._listening_by_port(ctx)

        def peer_key(f: Finding):
            d = f.details or {}
            return (str(d.get("remote_host") or ""), _int_or_zero(d.get("remote_port")))

        out = []
        for prior in sorted(peers, key=peer_key):
            details = prior.details
            host = details.get("remote_host") or "(unknown host)"
            port = details.get("remote_port")
            if port in listening:
                continue
            hint = details["service_hint"]
            count = _int_or_zero(details.get("count"))
            evidence = details.get("evidence")
            # HIGH requires evidence repeated over time: a single current-state
            # snapshot can show a 5-socket connection pool — simultaneity is
            # not repetition, so current-only evidence is at most MEDIUM.
            confidence = (
                CONFIDENCE_HIGH
                if evidence == "both" or (evidence == "historical" and count >= 5)
                else CONFIDENCE_MEDIUM
            )
            role = f"database client (talks to {host}:{port})"
            summary = [
                f"peer {host}:{port} ({hint}), {count} observation(s), evidence {evidence}",
                "no local database service running",
                f"no local listener on port {port}",
            ]
            out.append(
                self._finding(
                    ctx,
                    "role.db_client.v1",
                    role,
                    (
                        f"Outbound {hint} connections to {host}:{port} with no "
                        f"matching local database service or listener indicate "
                        f"a database client (talks to {host}:{port})."
                    ),
                    summary,
                    list(prior.supporting_observations),
                    confidence,
                )
            )
        return out

    # --- role.transfer_client.v1 ----------------------------------------

    def _rule_transfer_client(self, ctx: AnalysisContext) -> list[Finding]:
        qualifying = []
        for prior in ctx.findings_of_type(FindingType.PEER_DEPENDENCY):
            details = prior.details or {}
            if details.get("service_hint") not in _TRANSFER_HINTS:
                continue
            if _int_or_zero(details.get("count")) < 2:
                continue
            qualifying.append(prior)

        def peer_key(f: Finding):
            d = f.details or {}
            return (str(d.get("remote_host") or ""), _int_or_zero(d.get("remote_port")))

        out = []
        for prior in sorted(qualifying, key=peer_key):
            details = prior.details
            host = details.get("remote_host") or "(unknown host)"
            port = details.get("remote_port")
            hint = details["service_hint"]
            count = _int_or_zero(details.get("count"))
            evidence = details.get("evidence")
            confidence = (
                CONFIDENCE_HIGH
                if count >= 5 and evidence == "both"
                else CONFIDENCE_MEDIUM
            )
            role = f"outbound file-transfer/messaging client ({hint} to {host})"
            summary = [
                f"peer {host}:{port} ({hint}), {count} observation(s), evidence {evidence}"
            ]
            out.append(
                self._finding(
                    ctx,
                    "role.transfer_client.v1",
                    role,
                    (
                        f"Repeated {hint} connections to {host} ({count} "
                        f"observation(s)) indicate an outbound "
                        f"file-transfer/messaging client ({hint} to {host})."
                    ),
                    summary,
                    list(prior.supporting_observations),
                    confidence,
                )
            )
        return out

    # --- role.web_server.v1 ---------------------------------------------

    def _rule_web_server(self, ctx: AnalysisContext) -> list[Finding]:
        listening = self._listening_by_port(ctx)
        web_listeners: list[Observation] = []
        for port in _WEB_PORTS:
            web_listeners.extend(listening.get(port, []))

        process_matched = [
            obs
            for obs in web_listeners
            if obs.process
            and _basename(obs.process).lower().startswith(_WEB_NAME_PREFIXES)
        ]
        matching_services = [
            svc
            for svc in self._running_services(ctx)
            if svc.service.lower().startswith(_WEB_NAME_PREFIXES)
        ]
        web_role_obs = [
            obs
            for obs in ctx.get(Category.INSTALLED_ROLE)
            if str(obs.attributes.get("name") or "").lower() == "web-server"
        ]
        w3svc_running = [
            svc
            for svc in self._running_services(ctx)
            if svc.service.lower() == "w3svc"
        ]

        condition_listen = bool(web_listeners) and bool(process_matched or matching_services)
        condition_installed = bool(web_role_obs) and bool(w3svc_running)
        if not condition_listen and not condition_installed:
            return []

        supporting: list[str] = []
        summary: list[str] = []
        if condition_listen:
            for obs in web_listeners:
                port = obs.attributes.get("local_port")
                proc = f" (process {_basename(obs.process)})" if obs.process else ""
                summary.append(f"listening on port {port}{proc}")
                supporting.append(obs.id)
            for svc in matching_services:
                summary.append(f"service {svc.service} running")
                supporting.append(svc.id)
        if condition_installed:
            summary.append("role Web-Server installed")
            supporting.extend(obs.id for obs in web_role_obs)
            for svc in w3svc_running:
                if svc.id not in supporting:
                    summary.append(f"service {svc.service} running")
                    supporting.append(svc.id)

        if condition_listen and matching_services:
            confidence = CONFIDENCE_HIGH
            ports = sorted(
                {obs.attributes.get("local_port") for obs in web_listeners}
            )
            names = ", ".join(sorted({svc.service for svc in matching_services}))
            conclusion = (
                f"A listener on port(s) {', '.join(str(p) for p in ports)} "
                f"together with running web service(s) {names} indicates a "
                f"web server."
            )
        elif condition_listen:
            confidence = CONFIDENCE_MEDIUM
            ports = sorted(
                {obs.attributes.get("local_port") for obs in process_matched}
            )
            procs = ", ".join(
                sorted({_basename(obs.process) for obs in process_matched})
            )
            conclusion = (
                f"A listener on port(s) {', '.join(str(p) for p in ports)} "
                f"owned by {procs} indicates a web server."
            )
        else:
            confidence = CONFIDENCE_MEDIUM
            conclusion = (
                "The installed Web-Server role with service w3svc running "
                "(no web-port listener observed) indicates a web server."
            )
        return [
            self._finding(
                ctx,
                "role.web_server.v1",
                "web server",
                conclusion,
                summary,
                supporting,
                confidence,
            )
        ]

    # --- role.db_server.v1 ----------------------------------------------

    def _rule_db_server(self, ctx: AnalysisContext) -> list[Finding]:
        listening = self._listening_by_port(ctx)
        running = self._running_services(ctx)
        by_port: dict[int, dict[str, Any]] = {}
        for pattern, port in _DB_SERVER_PORTS:
            if port not in listening:
                continue
            for svc in running:
                if not _matches_pattern(svc.service, pattern):
                    continue
                group = by_port.setdefault(port, {"services": [], "svc_ids": []})
                if svc.id not in group["svc_ids"]:
                    group["services"].append(svc.service)
                    group["svc_ids"].append(svc.id)

        out = []
        for port in sorted(by_port):
            group = by_port[port]
            names = ", ".join(sorted(group["services"]))
            summary = [f"service {name} running" for name in sorted(group["services"])]
            summary.append(f"listening on port {port}")
            supporting = list(group["svc_ids"]) + [obs.id for obs in listening[port]]
            out.append(
                self._finding(
                    ctx,
                    "role.db_server.v1",
                    "database server",
                    (
                        f"Running database service(s) {names} with a listener "
                        f"on port {port} indicate a database server."
                    ),
                    summary,
                    supporting,
                    CONFIDENCE_HIGH,
                )
            )
        return out

    # --- role.dc.v1 -----------------------------------------------------

    def _rule_dc(self, ctx: AnalysisContext) -> list[Finding]:
        identity_hits = []
        for obs in ctx.get(Category.HOST_IDENTITY):
            role = obs.attributes.get("domain_role")
            if not isinstance(role, str):
                continue
            normalized = role.lower().replace(" ", "").replace("_", "").replace("-", "")
            if "domaincontroller" in normalized:
                identity_hits.append(obs)

        running = self._running_services(ctx)
        ntds = [svc for svc in running if svc.service.lower() == "ntds"]
        kdc = [svc for svc in running if svc.service.lower() == "kdc"]
        services_hit = bool(ntds) and bool(kdc)

        if not identity_hits and not services_hit:
            return []

        supporting: list[str] = []
        summary: list[str] = []
        for obs in identity_hits:
            summary.append(f"host identity domain role: {obs.attributes.get('domain_role')}")
            supporting.append(obs.id)
        if services_hit:
            summary.append("services ntds and kdc running")
            supporting.extend(svc.id for svc in ntds + kdc)

        if identity_hits:
            domain_role = identity_hits[0].attributes.get("domain_role")
            conclusion = (
                f"Host identity reports domain role '{domain_role}', "
                f"indicating a domain controller / identity infrastructure host."
            )
        else:
            conclusion = (
                "Running directory services ntds and kdc indicate a domain "
                "controller / identity infrastructure host."
            )
        return [
            self._finding(
                ctx,
                "role.dc.v1",
                "domain controller / identity infrastructure",
                conclusion,
                summary,
                supporting,
                CONFIDENCE_HIGH,
            )
        ]

    # --- role.admin_host.v1 ---------------------------------------------

    def _rule_admin_host(self, ctx: AnalysisContext, batch_fired: bool) -> list[Finding]:
        if batch_fired:
            return []
        interactive = ctx.findings_of_type(FindingType.INTERACTIVE_USE)
        if not interactive:
            return []
        prior = interactive[0]
        details = prior.details or {}
        if details.get("classification") != "interactive":
            return []
        peer_count = len(ctx.findings_of_type(FindingType.PEER_DEPENDENCY))
        if peer_count > 3:
            return []
        remote_interactive = _int_or_zero(details.get("remote_interactive_logons"))
        local_interactive = _int_or_zero(details.get("interactive_logons"))
        confidence = CONFIDENCE_MEDIUM if remote_interactive >= 5 else CONFIDENCE_LOW
        summary = [
            (
                f"interactive use classification: interactive "
                f"({local_interactive} interactive, {remote_interactive} "
                f"remote-interactive logons)"
            ),
            "no batch/scheduled role inferred",
            f"{peer_count} outbound peer dependency finding(s)",
        ]
        conclusion = (
            f"Interactive use ({local_interactive} interactive, "
            f"{remote_interactive} remote-interactive logons) with no "
            f"recurring scheduled role and {peer_count} outbound peer "
            f"dependency finding(s) suggests an interactive administration "
            f"/ jump host."
        )
        return [
            self._finding(
                ctx,
                "role.admin_host.v1",
                "interactive administration / jump host",
                conclusion,
                summary,
                list(prior.supporting_observations),
                confidence,
            )
        ]

    # --- role.quiet.v1 --------------------------------------------------

    def _rule_quiet(self, ctx: AnalysisContext) -> list[Finding]:
        interactive = ctx.findings_of_type(FindingType.INTERACTIVE_USE)
        if not interactive:
            return []
        prior = interactive[0]
        details = prior.details or {}
        if details.get("classification") != "apparently_quiet":
            return []
        if ctx.findings_of_type(FindingType.RECURRING_SCHEDULED_ACTIVITY):
            return []
        historical = sum(len(ctx.get(cat)) for cat in _HISTORICAL_CATEGORIES)
        if historical >= 200:
            return []

        # Never overstate the window: available_window_days caps the requested
        # window at what the evidence actually retains (CONTRACTS.md §4).
        window_days = available_window_days(ctx)
        if window_days is not None:
            window_text = f"the {window_days:.1f}-day available history"
        else:
            window_text = "the available history (window length unknown)"

        summary = [
            "interactive use classification: apparently_quiet",
            "no recurring scheduled activity findings",
            f"{historical} historical observation(s) in window",
        ]
        conclusion = (
            f"Only {historical} historical observation(s) and no recurring or "
            f"interactive activity were seen during {window_text}; the host "
            f"appears quiet during the observed window, which is not evidence "
            f"that it is unused."
        )
        return [
            self._finding(
                ctx,
                "role.quiet.v1",
                "apparently quiet during observed window",
                conclusion,
                summary,
                list(prior.supporting_observations),
                CONFIDENCE_LOW,
            )
        ]


ANALYZER = RolesAnalyzer()
