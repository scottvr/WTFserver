"""Tests for the frequency analyzer (frequency_summary finding)."""

from __future__ import annotations

import json
from typing import Any

from wtfserver.analyzers.frequency import ANALYZER, FrequencyAnalyzer
from wtfserver.model import EVIDENCE_OBSERVED, Category, FindingType

from helpers import build_ctx, make_obs

DETAIL_KEYS = (
    "top_providers",
    "top_event_ids",
    "top_principals",
    "top_services",
    "top_scheduled_actions",
    "top_processes",
    "top_remote_hosts",
    "top_remote_ports",
    "system_principals",
    "process_paths",
)


def run(observations, options=None):
    ctx = build_ctx(observations, options=options)
    findings = ANALYZER.analyze(ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == FindingType.FREQUENCY_SUMMARY
    return finding


def logon(principal: str, i: int = 0, **kwargs: Any):
    defaults: dict[str, Any] = {
        "source": "eventlog",
        "action": "logon",
        "principal": principal,
        "timestamp": f"2026-08-18T0{i % 10}:00:00Z",
        "attributes": {
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4624,
            "level": None,
            "logon_kind": "network",
            "logon_type": 3,
        },
    }
    defaults.update(kwargs)
    return make_obs(Category.LOGON, **defaults)


def event(provider: str, event_id: Any, **kwargs: Any):
    defaults: dict[str, Any] = {
        "source": "eventlog",
        "timestamp": "2026-08-18T03:00:00Z",
        "attributes": {
            "channel": "System",
            "provider": provider,
            "event_id": event_id,
            "level": None,
        },
    }
    defaults.update(kwargs)
    return make_obs(Category.EVENT, **defaults)


def test_analyzer_identity():
    assert isinstance(ANALYZER, FrequencyAnalyzer)
    assert ANALYZER.name == "frequency"
    assert ANALYZER.required_categories == ()


def test_detail_shape_and_evidence_class():
    finding = run(
        [
            event("Service Control Manager", 7036),
            logon("CORP\\alice"),
            make_obs(
                Category.SERVICE_STATE,
                source="services",
                action="configured",
                service="Spooler",
                principal="LocalSystem",
                process="C:\\Windows\\System32\\spoolsv.exe",
                timestamp="2026-08-19T12:01:00Z",
                attributes={"state": "running", "start_mode": "auto"},
            ),
        ]
    )
    assert finding.evidence_class == EVIDENCE_OBSERVED
    for key in DETAIL_KEYS:
        assert key in finding.details, key
    assert finding.details["top_services"] == [["Spooler", 1]]
    # Result must be JSON serializable.
    json.dumps(finding.to_json_dict())


def test_providers_counted_across_all_historical_categories():
    obs = [
        event("ProvA", 1),
        logon("CORP\\alice"),  # provider Microsoft-Windows-Security-Auditing
        make_obs(
            Category.SERVICE_ACTIVITY,
            source="eventlog",
            action="state_change",
            service="Foo",
            timestamp="2026-08-18T05:00:00Z",
            attributes={
                "channel": "System",
                "provider": "Service Control Manager",
                "event_id": 7036,
                "level": None,
            },
        ),
        make_obs(
            Category.SYSTEM_LIFECYCLE,
            source="eventlog",
            action="boot",
            timestamp="2026-08-18T00:00:00Z",
            attributes={
                "channel": "System",
                "provider": "EventLog",
                "event_id": 6005,
                "level": None,
            },
        ),
    ]
    details = run(obs).details
    providers = dict((name, count) for name, count in details["top_providers"])
    assert providers == {
        "ProvA": 1,
        "Microsoft-Windows-Security-Auditing": 1,
        "Service Control Manager": 1,
        "EventLog": 1,
    }
    assert ["Microsoft-Windows-Security-Auditing:4624", 1] in details["top_event_ids"]
    assert ["Service Control Manager:7036", 1] in details["top_event_ids"]


def test_event_id_key_format_provider_colon_id():
    details = run([event("ProvX", 1234), event("ProvX", 1234)]).details
    assert details["top_event_ids"] == [["ProvX:1234", 2]]


def test_tie_break_count_desc_then_name_asc():
    obs = [
        event("Zeta", 1),
        event("Zeta", 1),
        event("Alpha", 2),
        event("Alpha", 2),
        event("Mid", 3),
        event("Mid", 3),
        event("Mid", 3),
    ]
    details = run(obs).details
    assert details["top_providers"] == [["Mid", 3], ["Alpha", 2], ["Zeta", 2]]
    assert details["top_event_ids"] == [["Mid:3", 3], ["Alpha:2", 2], ["Zeta:1", 2]]


def test_noise_principals_filtered_into_system_principals():
    obs = [
        logon("CORP\\alice", 1),
        logon("CORP\\alice", 2),
        logon("NT AUTHORITY\\SYSTEM", 3),
        logon("CORP\\WEB01$", 4),
        logon("LOCAL SERVICE", 5),
        logon("NT AUTHORITY\\NETWORK SERVICE", 6),
        logon("ANONYMOUS LOGON", 7),
    ]
    details = run(obs).details
    assert details["top_principals"] == [["CORP\\alice", 2]]
    system = dict((name, count) for name, count in details["system_principals"])
    assert system == {
        "NT AUTHORITY\\SYSTEM": 1,
        "CORP\\WEB01$": 1,
        "LOCAL SERVICE": 1,
        "NT AUTHORITY\\NETWORK SERVICE": 1,
        "ANONYMOUS LOGON": 1,
    }


def test_human_principal_not_filtered():
    # Counterexample: a real user whose name merely contains "system".
    details = run([logon("CORP\\systemsmith")]).details
    assert details["top_principals"] == [["CORP\\systemsmith", 1]]
    assert details["system_principals"] == []


def test_process_basename_grouping_and_paths():
    obs = [
        make_obs(
            Category.PROCESS_ACTIVITY,
            source="eventlog",
            action="start",
            process="C:\\Windows\\System32\\cmd.exe",
            timestamp="2026-08-18T01:00:00Z",
            attributes={"channel": "Security", "provider": "P", "event_id": 4688, "level": None},
        ),
        make_obs(
            Category.PROCESS_ACTIVITY,
            source="eventlog",
            action="start",
            process="C:\\Windows\\System32\\cmd.exe",
            timestamp="2026-08-18T02:00:00Z",
            attributes={"channel": "Security", "provider": "P", "event_id": 4688, "level": None},
        ),
        make_obs(
            Category.PROCESS_ACTIVITY,
            source="eventlog",
            action="start",
            process="D:\\Tools\\cmd.exe",
            timestamp="2026-08-18T03:00:00Z",
            attributes={"channel": "Security", "provider": "P", "event_id": 4688, "level": None},
        ),
    ]
    details = run(obs).details
    assert details["top_processes"] == [["cmd.exe", 3]]
    assert details["process_paths"] == {"cmd.exe": "C:\\Windows\\System32\\cmd.exe"}


def test_process_path_tie_breaks_lexicographically():
    obs = [
        make_obs(Category.PROCESS_STATE, source="processes", action="running",
                 process="D:\\b\\tool.exe", timestamp="2026-08-19T12:01:00Z"),
        make_obs(Category.PROCESS_STATE, source="processes", action="running",
                 process="C:\\a\\tool.exe", timestamp="2026-08-19T12:01:00Z"),
    ]
    details = run(obs).details
    assert details["process_paths"] == {"tool.exe": "C:\\a\\tool.exe"}


def test_top_n_option_caps_lists():
    obs = [event(f"Prov{i:02d}", i) for i in range(15)]
    details = run(obs, options={"top_n": 3}).details
    assert len(details["top_providers"]) == 3
    assert len(details["top_event_ids"]) == 3
    # Default is 10.
    details = run(obs).details
    assert len(details["top_providers"]) == 10


def test_loopback_and_unspecified_remote_endpoints_excluded():
    obs = [
        make_obs(Category.SOCKET_STATE, source="network", action="established",
                 remote_host="10.0.0.5", remote_port=1433,
                 timestamp="2026-08-19T12:01:00Z",
                 attributes={"protocol": "tcp", "local_address": "10.0.0.1",
                             "local_port": 50001, "pid": 4321, "state": "Established"}),
        make_obs(Category.SOCKET_STATE, source="network", action="established",
                 remote_host="127.0.0.1", remote_port=445,
                 timestamp="2026-08-19T12:01:00Z",
                 attributes={"protocol": "tcp", "local_address": "127.0.0.1",
                             "local_port": 50002, "pid": 4321, "state": "Established"}),
        make_obs(Category.SOCKET_STATE, source="network", action="established",
                 remote_host="::1", remote_port=5985,
                 timestamp="2026-08-19T12:01:00Z",
                 attributes={"protocol": "tcp", "local_address": "::1",
                             "local_port": 50003, "pid": 4321, "state": "Established"}),
        make_obs(Category.SOCKET_STATE, source="network", action="established",
                 remote_host="0.0.0.0", remote_port=0,
                 timestamp="2026-08-19T12:01:00Z",
                 attributes={"protocol": "tcp", "local_address": "0.0.0.0",
                             "local_port": 50004, "pid": 4321, "state": "Listen"}),
    ]
    details = run(obs).details
    assert details["top_remote_hosts"] == [["10.0.0.5", 1]]
    assert details["top_remote_ports"] == [["1433", 1]]


def test_remote_port_is_string_name():
    obs = [
        make_obs(Category.SOCKET_STATE, source="network", action="established",
                 remote_host="10.0.0.9", remote_port=443,
                 timestamp="2026-08-19T12:01:00Z", attributes={"protocol": "tcp"}),
    ]
    (name, count), = run(obs).details["top_remote_ports"]
    assert name == "443" and isinstance(name, str)
    assert count == 1


def test_empty_bundle_emits_finding_with_empty_lists():
    finding = run([])
    for key in DETAIL_KEYS[:-1]:
        assert finding.details[key] == [], key
    assert finding.details["process_paths"] == {}
    assert finding.supporting_observations == []
    assert "supporting_capped" not in finding.details
    assert finding.evidence_class == EVIDENCE_OBSERVED


def test_malformed_attributes_are_skipped_not_fatal():
    obs = [
        # provider missing entirely, event_id garbage
        make_obs(Category.EVENT, source="eventlog",
                 timestamp="2026-08-18T00:00:00Z", attributes={}),
        event("GoodProv", "not-an-int"),
        event(None, 5),
        event("GoodProv", 7036),
    ]
    details = run(obs).details
    assert details["top_providers"] == [["GoodProv", 2]]
    # only the parseable event_id appears
    assert details["top_event_ids"] == [["GoodProv:7036", 1]]


def test_supporting_observations_capped_at_50():
    obs = [logon("CORP\\alice", i) for i in range(60)]
    finding = run(obs)
    assert len(finding.supporting_observations) == 50
    assert finding.details["supporting_capped"] is True
    assert finding.details["supporting_total"] == 60


def test_determinism_identical_output():
    obs = [
        event("ProvB", 2),
        event("ProvA", 1),
        logon("CORP\\alice"),
        logon("NT AUTHORITY\\SYSTEM"),
        make_obs(Category.SOCKET_STATE, source="network", action="established",
                 remote_host="10.0.0.5", remote_port=1433,
                 timestamp="2026-08-19T12:01:00Z", attributes={"protocol": "tcp"}),
    ]
    first = run(list(obs)).to_json_dict()
    second = run(list(obs)).to_json_dict()
    assert json.dumps(first) == json.dumps(second)
