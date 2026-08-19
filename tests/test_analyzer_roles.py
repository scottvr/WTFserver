"""Tests for the roles analyzer (role_inference findings, CONTRACTS.md §4)."""

from __future__ import annotations

import itertools
import json

from wtfserver.analyzers.roles import ANALYZER, RolesAnalyzer
from wtfserver.model import Category, Finding, FindingType

from helpers import build_ctx, make_obs

_finding_counter = itertools.count(1)


def prior(finding_type, analyzer, details, supporting=None):
    return Finding(
        id=f"p-{next(_finding_counter):04d}",
        finding_type=finding_type,
        analyzer=analyzer,
        conclusion="prior finding",
        evidence_class="observed",
        supporting_observations=list(supporting or []),
        details=details,
    )


def recurring_finding(
    scheduled_action="\\Vendor\\NightlyExport",
    count=21,
    cadence="daily",
    principal="CORP\\svc_batch",
    process="C:\\Vendor\\export.exe",
    supporting=("obs-r1", "obs-r2"),
):
    return prior(
        FindingType.RECURRING_SCHEDULED_ACTIVITY,
        "recurrence",
        {
            "scheduled_action": scheduled_action,
            "count": count,
            "first": "2026-08-01T01:00:00Z",
            "last": "2026-08-19T01:00:00Z",
            "cadence": cadence,
            "interval_seconds": 86400.0,
            "typical_time": "01:00",
            "jitter_seconds": 30.0,
            "principal": principal,
            "process": process,
            "failure_count": 0,
        },
        supporting,
    )


def peer_finding(
    host,
    port,
    hint,
    count=4,
    evidence="current",
    processes=(),
    supporting=("obs-p1",),
):
    return prior(
        FindingType.PEER_DEPENDENCY,
        "peers",
        {
            "remote_host": host,
            "remote_port": port,
            "count": count,
            "evidence": evidence,
            "processes": list(processes),
            "service_hint": hint,
        },
        supporting,
    )


def interactive_finding(classification, supporting=("obs-i1",), **overrides):
    details = {
        "classification": classification,
        "interactive_logons": 0,
        "remote_interactive_logons": 0,
        "batch_logons": 0,
        "service_logons": 0,
        "network_logons": 0,
        "failed_logons": 0,
        "interactive_principals": [],
        "first_interactive": None,
        "last_interactive": None,
        "window_days": 3.0,
    }
    details.update(overrides)
    return prior(FindingType.INTERACTIVE_USE, "interactive", details, supporting)


def service_obs(name, state="running", **kw):
    return make_obs(
        Category.SERVICE_STATE,
        action="configured",
        timestamp="2026-08-19T12:00:00Z",
        service=name,
        attributes={"display_name": name, "state": state, "start_mode": "auto", "raw_path": None},
        **kw,
    )


def listening_obs(port, process=None):
    return make_obs(
        Category.SOCKET_STATE,
        action="listening",
        timestamp="2026-08-19T12:00:00Z",
        process=process,
        attributes={"protocol": "tcp", "local_address": "0.0.0.0", "local_port": port, "pid": 4, "state": "LISTEN"},
    )


def channel_obs(oldest="2026-08-10T00:00:00Z"):
    # Evidence-channel retention record; oldest before the default window
    # start means the full requested window is actually available.
    return make_obs(
        Category.EVIDENCE_CHANNEL,
        source="eventlog",
        action="inventoried",
        timestamp="2026-08-19T12:01:00Z",
        attributes={
            "channel": "Security",
            "enabled": True,
            "record_count": 100,
            "oldest_record": oldest,
            "newest_record": "2026-08-19T12:00:00Z",
            "max_size_bytes": None,
            "collected_events": 100,
            "truncated": False,
        },
    )


def identity_obs(domain_role):
    return make_obs(
        Category.HOST_IDENTITY,
        action="identity",
        timestamp="2026-08-19T12:00:00Z",
        attributes={
            "hostname": "testhost",
            "fqdn": None,
            "os_name": "Windows Server 2019",
            "os_version": "10.0",
            "domain": "corp.example",
            "domain_role": domain_role,
            "interfaces": [],
            "dns_servers": [],
            "last_boot": None,
        },
    )


def run(observations, priors):
    ctx = build_ctx(observations)
    ctx.prior_findings = list(priors)
    return ANALYZER.analyze(ctx)


def by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


def test_module_exports_analyzer_instance():
    assert isinstance(ANALYZER, RolesAnalyzer)
    assert ANALYZER.name == "roles"


def test_no_priors_no_observations_yields_nothing():
    assert run([], []) == []


# --- role.batch.v1 -------------------------------------------------------


def test_batch_fires_high_and_copies_supporting():
    findings = run([], [recurring_finding(count=21, cadence="daily")])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "role.batch.v1"
    assert f.finding_type == FindingType.ROLE_INFERENCE
    assert f.evidence_class == "inferred"
    assert f.confidence == "HIGH"
    assert f.details["role"] == "batch/scheduled processing host"
    assert f.supporting_observations == ["obs-r1", "obs-r2"]
    assert "\\Vendor\\NightlyExport" in f.conclusion
    assert "21 runs" in f.conclusion
    assert "daily cadence" in f.conclusion
    assert "batch/scheduled processing host" in f.conclusion
    assert isinstance(f.details["evidence_summary"], list)
    assert f.details["evidence_summary"]


def test_batch_medium_when_count_between_5_and_9():
    findings = run([], [recurring_finding(count=6, cadence="interval")])
    assert len(findings) == 1
    assert findings[0].confidence == "MEDIUM"


def test_batch_not_fired_below_count_threshold():
    assert run([], [recurring_finding(count=4)]) == []


def test_batch_not_fired_for_irregular_cadence():
    assert run([], [recurring_finding(count=30, cadence="irregular")]) == []


def test_batch_not_fired_without_principal_or_process():
    assert run([], [recurring_finding(principal=None, process=None)]) == []


def test_batch_emits_single_finding_listing_tasks_sorted():
    # At most ONE role.batch.v1 finding, listing each qualifying task in
    # evidence_summary sorted by task path, supporting observations merged.
    findings = run(
        [],
        [
            recurring_finding(scheduled_action="\\Zeta\\Job", supporting=("obs-z",)),
            recurring_finding(scheduled_action="\\Alpha\\Job", supporting=("obs-a",)),
        ],
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "role.batch.v1"
    tasks = [line.split(":")[0] for line in f.details["evidence_summary"]]
    assert tasks == ["\\Alpha\\Job", "\\Zeta\\Job"]
    assert f.supporting_observations == ["obs-a", "obs-z"]
    assert "\\Alpha\\Job" in f.conclusion
    assert "\\Zeta\\Job" in f.conclusion


def test_batch_confidence_high_if_any_qualifier_is_strong():
    # One weak (6 runs) and one strong (21 runs, daily) qualifier: still one
    # finding, HIGH because at least one recurrence meets the HIGH bar.
    findings = run(
        [],
        [
            recurring_finding(scheduled_action="\\Vendor\\Weak", count=6, cadence="interval"),
            recurring_finding(scheduled_action="\\Vendor\\Strong", count=21, cadence="daily"),
        ],
    )
    assert len(findings) == 1
    assert findings[0].confidence == "HIGH"
    assert len(findings[0].details["evidence_summary"]) == 2


def test_batch_not_fired_for_builtin_microsoft_tasks_only():
    # Built-in OS maintenance tasks recur on every host: an idle stock server
    # must NOT become a batch/scheduled processing host. Case-insensitive.
    priors = [
        recurring_finding(
            scheduled_action="\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
            count=21,
            cadence="daily",
        ),
        recurring_finding(
            scheduled_action="\\microsoft\\windows\\servicing\\StartComponentCleanup",
            count=30,
            cadence="daily",
        ),
    ]
    assert run([], priors) == []


def test_batch_mixed_microsoft_and_vendor_names_only_vendor_task():
    findings = run(
        [],
        [
            recurring_finding(
                scheduled_action="\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
                count=30,
                cadence="daily",
                supporting=("obs-ms",),
            ),
            recurring_finding(
                scheduled_action="\\Vendor\\NightlyExport",
                count=21,
                cadence="daily",
                supporting=("obs-v",),
            ),
        ],
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "role.batch.v1"
    summary_text = " ".join(f.details["evidence_summary"])
    assert "\\Vendor\\NightlyExport" in summary_text
    assert "Microsoft" not in summary_text
    assert "Microsoft" not in f.conclusion
    assert f.supporting_observations == ["obs-v"]


# --- role.db_client.v1 ---------------------------------------------------


def test_db_client_fires_medium_when_low_count_current_only():
    findings = run([], [peer_finding("10.0.0.5", 1433, "mssql", count=3)])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "role.db_client.v1"
    assert f.confidence == "MEDIUM"
    assert f.details["role"] == "database client (talks to 10.0.0.5:1433)"
    assert f.supporting_observations == ["obs-p1"]


def test_db_client_high_when_evidence_both_or_historical_count_5():
    both = run([], [peer_finding("10.0.0.5", 1433, "mssql", count=2, evidence="both")])
    many = run(
        [], [peer_finding("10.0.0.6", 5432, "postgresql", count=5, evidence="historical")]
    )
    assert both[0].confidence == "HIGH"
    assert many[0].confidence == "HIGH"


def test_db_client_current_only_is_at_most_medium():
    # A single netstat snapshot can show a 5-socket connection pool:
    # simultaneity is not repetition, so current-only evidence caps at MEDIUM.
    findings = run(
        [], [peer_finding("10.0.0.5", 1433, "mssql", count=5, evidence="current")]
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "role.db_client.v1"
    assert findings[0].confidence == "MEDIUM"


def test_db_client_historical_below_count_5_is_medium():
    findings = run(
        [], [peer_finding("10.0.0.5", 1433, "mssql", count=4, evidence="historical")]
    )
    assert findings[0].confidence == "MEDIUM"


def test_db_client_suppressed_by_local_running_db_service():
    findings = run(
        [service_obs("MSSQLSERVER", state="running")],
        [peer_finding("10.0.0.5", 1433, "mssql", count=5)],
    )
    assert by_rule(findings, "role.db_client.v1") == []


def test_db_client_not_suppressed_by_stopped_db_service():
    findings = run(
        [service_obs("MSSQLSERVER", state="stopped")],
        [peer_finding("10.0.0.5", 1433, "mssql", count=5)],
    )
    assert len(by_rule(findings, "role.db_client.v1")) == 1


def test_db_client_suppressed_per_port_by_local_listener():
    findings = run(
        [listening_obs(1433)],
        [
            peer_finding("10.0.0.5", 1433, "mssql", count=5),
            peer_finding("10.0.0.6", 3306, "mysql", count=5, supporting=("obs-p2",)),
        ],
    )
    db = by_rule(findings, "role.db_client.v1")
    assert len(db) == 1
    assert db[0].details["role"] == "database client (talks to 10.0.0.6:3306)"


def test_db_client_ignores_non_db_hints():
    assert run([], [peer_finding("10.0.0.8", 443, "https", count=9)]) == []


def test_db_client_sorted_by_peer_host():
    findings = run(
        [],
        [
            peer_finding("10.0.0.9", 1433, "mssql", count=5),
            peer_finding("10.0.0.1", 3306, "mysql", count=5),
        ],
    )
    hosts = [f.details["role"] for f in findings]
    assert hosts == [
        "database client (talks to 10.0.0.1:3306)",
        "database client (talks to 10.0.0.9:1433)",
    ]


# --- role.transfer_client.v1 ---------------------------------------------


def test_transfer_client_fires_medium_at_count_2():
    findings = run([], [peer_finding("10.0.0.9", 22, "ssh/sftp", count=2)])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "role.transfer_client.v1"
    assert f.confidence == "MEDIUM"
    assert f.details["role"] == "outbound file-transfer/messaging client (ssh/sftp to 10.0.0.9)"


def test_transfer_client_high_needs_count_5_and_both():
    high = run([], [peer_finding("10.0.0.9", 22, "ssh/sftp", count=5, evidence="both")])
    only_count = run([], [peer_finding("10.0.0.9", 22, "ssh/sftp", count=5, evidence="current")])
    assert high[0].confidence == "HIGH"
    assert only_count[0].confidence == "MEDIUM"


def test_transfer_client_not_fired_below_count_2():
    assert run([], [peer_finding("10.0.0.9", 25, "smtp", count=1)]) == []


# --- role.web_server.v1 --------------------------------------------------


def test_web_server_high_with_listener_and_matching_service():
    findings = run(
        [listening_obs(443, process="w3wp.exe"), service_obs("W3SVC")],
        [],
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "role.web_server.v1"
    assert f.confidence == "HIGH"
    assert f.details["role"] == "web server"
    assert len(f.supporting_observations) == 2


def test_web_server_medium_when_installed_and_running_without_listener():
    role_obs = make_obs(
        Category.INSTALLED_ROLE,
        action="installed",
        timestamp="2026-08-19T12:00:00Z",
        message="Web Server (IIS)",
        attributes={"name": "Web-Server", "display_name": "Web Server (IIS)"},
    )
    findings = run([role_obs, service_obs("w3svc")], [])
    assert len(findings) == 1
    assert findings[0].confidence == "MEDIUM"
    assert findings[0].details["role"] == "web server"


def test_web_server_not_fired_for_unmatched_listener():
    findings = run([listening_obs(443, process="randomapp.exe")], [])
    assert findings == []


def test_web_server_not_fired_when_w3svc_stopped():
    role_obs = make_obs(
        Category.INSTALLED_ROLE,
        action="installed",
        timestamp="2026-08-19T12:00:00Z",
        attributes={"name": "Web-Server", "display_name": "Web Server (IIS)"},
    )
    findings = run([role_obs, service_obs("w3svc", state="stopped")], [])
    assert findings == []


# --- role.db_server.v1 ---------------------------------------------------


def test_db_server_fires_high_with_running_service_and_listener():
    findings = run([service_obs("MSSQLSERVER"), listening_obs(1433)], [])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "role.db_server.v1"
    assert f.confidence == "HIGH"
    assert f.details["role"] == "database server"
    assert len(f.supporting_observations) == 2


def test_db_server_not_fired_without_listener():
    assert run([service_obs("MSSQLSERVER")], []) == []


def test_db_server_not_fired_without_db_service():
    assert run([listening_obs(1433)], []) == []


# --- role.dc.v1 ----------------------------------------------------------


def test_dc_fires_on_domain_role_identity():
    findings = run([identity_obs("PrimaryDomainController")], [])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "role.dc.v1"
    assert f.confidence == "HIGH"
    assert f.details["role"] == "domain controller / identity infrastructure"


def test_dc_fires_on_ntds_plus_kdc_running():
    findings = run([service_obs("NTDS"), service_obs("Kdc")], [])
    assert len(findings) == 1
    assert findings[0].rule_id == "role.dc.v1"


def test_dc_not_fired_on_member_server_or_ntds_alone():
    assert run([identity_obs("MemberServer")], []) == []
    assert run([service_obs("NTDS")], []) == []


# --- role.admin_host.v1 --------------------------------------------------


def test_admin_host_medium_with_5_remote_interactive():
    findings = run(
        [],
        [interactive_finding("interactive", interactive_logons=2, remote_interactive_logons=6)],
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "role.admin_host.v1"
    assert f.confidence == "MEDIUM"
    assert f.details["role"] == "interactive administration / jump host"
    assert f.supporting_observations == ["obs-i1"]


def test_admin_host_low_with_few_remote_interactive():
    findings = run(
        [],
        [interactive_finding("interactive", interactive_logons=6, remote_interactive_logons=2)],
    )
    assert findings[0].confidence == "LOW"


def test_admin_host_suppressed_when_batch_role_fired():
    findings = run(
        [],
        [
            recurring_finding(count=21, cadence="daily"),
            interactive_finding("interactive", remote_interactive_logons=6),
        ],
    )
    assert len(by_rule(findings, "role.batch.v1")) == 1
    assert by_rule(findings, "role.admin_host.v1") == []


def test_admin_host_suppressed_by_more_than_3_peer_findings():
    peers = [
        peer_finding(f"10.0.0.{i}", 443, "https", count=2, supporting=(f"obs-p{i}",))
        for i in range(4)
    ]
    findings = run([], peers + [interactive_finding("interactive", remote_interactive_logons=6)])
    assert by_rule(findings, "role.admin_host.v1") == []


def test_admin_host_not_fired_for_other_classifications():
    assert run([], [interactive_finding("mixed", remote_interactive_logons=9)]) == []


# --- role.quiet.v1 -------------------------------------------------------


def _quiet_history(n=3):
    return [
        make_obs(
            Category.LOGON,
            action="logon",
            timestamp=f"2026-08-17T0{i}:00:00Z",
            principal="CORP\\admin",
            attributes={"logon_kind": "network"},
        )
        for i in range(n)
    ]


def test_quiet_fires_low_names_window_and_disclaims_unused():
    # channel_obs: full retention, so the requested 3-day window is available.
    findings = run(
        _quiet_history() + [channel_obs()], [interactive_finding("apparently_quiet")]
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "role.quiet.v1"
    assert f.confidence == "LOW"
    assert f.details["role"] == "apparently quiet during observed window"
    assert "3.0-day" in f.conclusion
    assert "not evidence" in f.conclusion
    # No unconditional claim of disuse: "unused" only appears negated.
    assert "is unused" not in f.conclusion.replace("not evidence that it is unused", "")


def test_quiet_window_text_capped_by_evidence_retention():
    # Requested window is 3 days, but the only channel retains ~2 hours of
    # history: the conclusion must quote ~0.1 days, never 3.0.
    history = [
        make_obs(
            Category.LOGON,
            action="logon",
            timestamp="2026-08-19T11:00:00Z",
            principal="CORP\\admin",
            attributes={"logon_kind": "network"},
        )
    ]
    findings = run(
        history + [channel_obs(oldest="2026-08-19T10:05:00Z")],
        [interactive_finding("apparently_quiet", window_days=3.0)],
    )
    assert len(findings) == 1
    assert "0.1-day" in findings[0].conclusion
    assert "3.0-day" not in findings[0].conclusion


def test_quiet_not_fired_with_recurring_findings():
    findings = run(
        _quiet_history(),
        [
            interactive_finding("apparently_quiet"),
            recurring_finding(count=2, cadence="irregular", principal=None, process=None),
        ],
    )
    assert by_rule(findings, "role.quiet.v1") == []


def test_quiet_not_fired_with_200_or_more_historical_observations():
    history = [
        make_obs(Category.EVENT, timestamp="2026-08-17T01:00:00Z", message="noise")
        for _ in range(200)
    ]
    findings = run(history, [interactive_finding("apparently_quiet")])
    assert by_rule(findings, "role.quiet.v1") == []


def test_quiet_not_fired_for_other_classifications():
    assert run(_quiet_history(), [interactive_finding("unknown")]) == []


# --- cross-cutting -------------------------------------------------------


def test_malformed_prior_findings_do_not_crash_or_fire():
    priors = [
        prior(FindingType.RECURRING_SCHEDULED_ACTIVITY, "recurrence", {}),
        prior(FindingType.PEER_DEPENDENCY, "peers", {}),
        prior(FindingType.INTERACTIVE_USE, "interactive", {}),
        prior(
            FindingType.RECURRING_SCHEDULED_ACTIVITY,
            "recurrence",
            {"scheduled_action": "\\X", "count": "21", "cadence": "daily", "principal": "a"},
        ),
    ]
    assert run([], priors) == []


def test_malformed_observations_do_not_crash():
    obs = [
        make_obs(Category.SOCKET_STATE, action="listening", attributes={}),
        make_obs(Category.SOCKET_STATE, action="listening", attributes={"local_port": "443"}),
        make_obs(Category.SERVICE_STATE, action="configured", service=None, attributes={"state": "running"}),
        make_obs(Category.SERVICE_STATE, action="configured", service="w3svc", attributes={}),
        make_obs(Category.HOST_IDENTITY, action="identity", attributes={"domain_role": 5}),
    ]
    assert run(obs, []) == []


def test_supporting_observations_capped_at_50():
    supporting = tuple(f"obs-{i:04d}" for i in range(60))
    findings = run([], [recurring_finding(supporting=supporting)])
    f = findings[0]
    assert len(f.supporting_observations) == 50
    assert f.details["supporting_capped"] is True
    assert f.details["supporting_total"] == 60


def test_rule_emission_order_matches_contract():
    # Note: db_client and db_server cannot fire together — a running local
    # DB-named service suppresses db_client by contract.
    observations = [
        service_obs("W3SVC"),
        listening_obs(443, process="w3wp.exe"),
        identity_obs("BackupDomainController"),
    ]
    priors = [
        peer_finding("10.0.0.9", 22, "ssh/sftp", count=2, supporting=("obs-t1",)),
        peer_finding("10.0.0.5", 1433, "mssql", count=5, supporting=("obs-d1",)),
        recurring_finding(count=21, cadence="daily"),
    ]
    findings = run(observations, priors)
    rules = [f.rule_id for f in findings]
    assert rules == [
        "role.batch.v1",
        "role.db_client.v1",
        "role.transfer_client.v1",
        "role.web_server.v1",
        "role.dc.v1",
    ]
    assert [f.id for f in findings] == [f"f-{i:04d}" for i in range(1, 6)]


def test_db_server_rule_precedes_dc_rule():
    findings = run(
        [service_obs("MSSQLSERVER"), listening_obs(1433), identity_obs("PrimaryDomainController")],
        [],
    )
    assert [f.rule_id for f in findings] == ["role.db_server.v1", "role.dc.v1"]


def test_deterministic_output():
    observations = [
        service_obs("W3SVC"),
        listening_obs(443, process="w3wp.exe"),
        identity_obs("PrimaryDomainController"),
    ]
    priors = [
        recurring_finding(count=21, cadence="daily"),
        peer_finding("10.0.0.5", 1433, "mssql", count=5),
        peer_finding("10.0.0.9", 22, "ssh/sftp", count=3),
    ]

    def once():
        findings = run(observations, priors)
        return json.dumps([f.to_json_dict() for f in findings], sort_keys=True)

    assert once() == once()
