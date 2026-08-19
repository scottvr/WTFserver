"""Tests for the interactive-use analyzer (CONTRACTS.md §4 interactive_use)."""

from __future__ import annotations

import json

from wtfserver.analyzers.interactive import ANALYZER, InteractiveAnalyzer
from wtfserver.model import EVIDENCE_OBSERVED, EVIDENCE_UNKNOWN, Category, FindingType

from helpers import build_ctx, make_manifest, make_obs


def _logon(kind, principal="CORP\\alice", action="logon", timestamp="2026-08-17T09:00:00Z", **kw):
    attributes = kw.pop("attributes", {})
    if kind is not None:
        attributes = {"logon_kind": kind, **attributes}
    return make_obs(
        Category.LOGON,
        source="eventlog",
        action=action,
        principal=principal,
        timestamp=timestamp,
        attributes=attributes,
        **kw,
    )


def _channel(oldest="2026-08-10T00:00:00Z"):
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


def _run(observations, manifest=None):
    ctx = build_ctx(observations, manifest=manifest)
    return ANALYZER.analyze(ctx)


def test_module_exports_analyzer_instance():
    assert isinstance(ANALYZER, InteractiveAnalyzer)
    assert ANALYZER.name == "interactive"


def test_no_logon_evidence_is_unknown():
    findings = _run([make_obs(Category.SERVICE_STATE, service="Spooler")])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == FindingType.INTERACTIVE_USE
    assert finding.evidence_class == EVIDENCE_UNKNOWN
    assert finding.details["classification"] == "unknown"
    assert finding.conclusion.startswith("No logon evidence available")
    assert finding.details["interactive_logons"] == 0
    assert finding.details["first_interactive"] is None
    assert finding.supporting_observations == []


def test_interactive_classification_counts_and_window():
    obs = (
        [_logon("interactive", timestamp=f"2026-08-17T0{i}:00:00Z") for i in range(6)]
        + [_logon("batch", principal="CORP\\svc_batch", timestamp="2026-08-17T10:00:00Z")]
        + [_channel()]  # full retention: the requested 3-day window is available
    )
    findings = _run(obs)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence_class == EVIDENCE_OBSERVED
    details = finding.details
    assert details["classification"] == "interactive"
    assert details["interactive_logons"] == 6
    assert details["batch_logons"] == 1
    assert details["interactive_principals"] == [["CORP\\alice", 6]]
    assert details["first_interactive"] == "2026-08-17T00:00:00Z"
    assert details["last_interactive"] == "2026-08-17T05:00:00Z"
    # default manifest window: 2026-08-16T12:00Z .. 2026-08-19T12:05Z
    assert details["window_days"] == 3.0
    # conclusion states counts and the window
    assert "6 interactive" in finding.conclusion
    assert "3.0-day" in finding.conclusion


def test_batch_scheduled_classification():
    # Distinct times (hours apart): these are 21 separate logons, not
    # duplicate records of one.
    obs = [
        _logon(
            "batch",
            principal="CORP\\svc_batch",
            timestamp=f"2026-08-{17 + i // 12}T{i % 12:02d}:30:00Z",
        )
        for i in range(21)
    ] + [_logon("interactive")]
    findings = _run(obs)
    assert findings[0].details["classification"] == "batch_scheduled"


def test_service_driven_classification():
    obs = [
        _logon(
            "service",
            principal="CORP\\svc_app",
            timestamp=f"2026-08-17T{i:02d}:00:00Z",
        )
        for i in range(10)
    ]
    findings = _run(obs)
    assert findings[0].details["classification"] == "service_driven"
    assert findings[0].details["service_logons"] == 10


def test_mixed_classification():
    # ir=3 fails the interactive rule; batch=5 fails 2x rule (5 < 6) -> mixed
    obs = [
        _logon("interactive", timestamp=f"2026-08-17T0{i}:00:00Z") for i in range(3)
    ] + [
        _logon(
            "batch",
            principal="CORP\\svc_batch",
            timestamp=f"2026-08-17T1{i}:00:00Z",
        )
        for i in range(5)
    ]
    findings = _run(obs)
    assert findings[0].details["classification"] == "mixed"


def test_two_interactive_logons_do_not_classify_interactive():
    # Counterexample: the interactive rule needs >=5; 2 must NOT fire it.
    obs = [_logon("interactive"), _logon("remote_interactive"), _channel()]
    findings = _run(obs)
    finding = findings[0]
    assert finding.details["classification"] == "apparently_quiet"
    assert finding.evidence_class == EVIDENCE_OBSERVED
    # negative statement is scoped to the window, not absolute
    assert "3.0-day" in finding.conclusion


def test_principal_filter_excludes_machine_and_noise_accounts():
    obs = (
        [
            _logon(
                "interactive",
                principal="NT AUTHORITY\\SYSTEM",
                timestamp=f"2026-08-17T0{i}:00:00Z",
            )
            for i in range(3)
        ]
        + [
            _logon(
                "interactive",
                principal="CORP\\WEB01$",
                timestamp=f"2026-08-17T0{i + 3}:00:00Z",
            )
            for i in range(2)
        ]
        + [_logon("remote_interactive", principal="CORP\\bob")]
    )
    findings = _run(obs)
    details = findings[0].details
    # all six logons counted...
    assert details["interactive_logons"] == 5
    assert details["remote_interactive_logons"] == 1
    # ...but only the human appears in interactive_principals
    assert details["interactive_principals"] == [["CORP\\bob", 1]]


def test_principal_tie_broken_by_name():
    obs = [
        _logon("interactive", principal="CORP\\zed"),
        _logon("interactive", principal="CORP\\ann"),
    ]
    findings = _run(obs)
    assert findings[0].details["interactive_principals"] == [["CORP\\ann", 1], ["CORP\\zed", 1]]


def test_failed_logons_counted_and_logoffs_ignored_for_kinds():
    obs = [
        _logon(None, action="logon_failed", attributes={"logon_type": 3}),
        _logon(None, action="logon_failed"),
        _logon("interactive", action="logoff"),
    ]
    findings = _run(obs)
    details = findings[0].details
    assert details["failed_logons"] == 2
    assert details["interactive_logons"] == 0
    # logon evidence exists, so not unknown
    assert details["classification"] == "apparently_quiet"
    assert findings[0].evidence_class == EVIDENCE_OBSERVED


def test_malformed_logon_observations_do_not_crash():
    # missing logon_kind, missing principal, missing timestamp
    obs = [
        _logon(None, principal=None, timestamp=None),
        _logon("interactive", principal=None, timestamp=None),
        make_obs(Category.LOGON, source="eventlog", action="logon", attributes={}),
    ]
    findings = _run(obs)
    details = findings[0].details
    assert details["interactive_logons"] == 1
    assert details["interactive_principals"] == []
    assert details["first_interactive"] is None


def test_supporting_observations_capped_at_50():
    obs = [_logon("network", principal="CORP\\svc") for _ in range(60)]
    findings = _run(obs)
    finding = findings[0]
    assert len(finding.supporting_observations) == 50
    assert finding.details["supporting_capped"] is True
    assert finding.details["supporting_total"] == 60


def test_window_days_from_history_span_when_since_is_max():
    # --since max, no evidence-channel retention data: the window falls back
    # to oldest historical observation .. collection_end (2026-08-17T00:00Z ..
    # 2026-08-19T12:05Z ~= 2.5 days).
    manifest = make_manifest(requested_since="max", since_resolved=None)
    obs = [
        _logon("interactive", timestamp="2026-08-17T00:00:00Z"),
        _logon("interactive", timestamp="2026-08-19T00:00:00Z"),
    ]
    findings = _run(obs, manifest=manifest)
    assert findings[0].details["window_days"] == 2.5


def test_window_days_capped_by_evidence_retention():
    # Requested window is 3 days, but the only channel retains ~2 hours of
    # history: the conclusion must quote ~0.1 days, never 3.0.
    obs = [
        _logon("interactive", timestamp="2026-08-19T11:00:00Z"),
        _channel(oldest="2026-08-19T10:05:00Z"),
    ]
    findings = _run(obs)
    assert findings[0].details["window_days"] == 0.1
    assert "0.1-day" in findings[0].conclusion
    assert "3.0-day" not in findings[0].conclusion


def test_dedupe_counts_paired_records_once():
    # Three physical RDP sessions, each recorded twice (audit log + session
    # manager log) within seconds: count 3, not 6.
    obs = []
    for hour in (1, 5, 9):
        obs.append(
            _logon(
                "remote_interactive",
                principal="CORP\\alice",
                timestamp=f"2026-08-17T0{hour}:00:00Z",
            )
        )
        obs.append(
            _logon(
                "remote_interactive",
                principal="CORP\\alice",
                timestamp=f"2026-08-17T0{hour}:00:02Z",
            )
        )
    findings = _run(obs)
    finding = findings[0]
    details = finding.details
    assert details["remote_interactive_logons"] == 3
    assert details["classification"] == "apparently_quiet"
    assert details["interactive_principals"] == [["CORP\\alice", 3]]
    # Duplicates stay in supporting_observations.
    assert len(finding.supporting_observations) == 6


def test_dedupe_counterexample_ten_minutes_apart_counts_twice():
    obs = [
        _logon("remote_interactive", timestamp="2026-08-17T09:00:00Z"),
        _logon("remote_interactive", timestamp="2026-08-17T09:10:00Z"),
    ]
    findings = _run(obs)
    assert findings[0].details["remote_interactive_logons"] == 2
    assert findings[0].details["interactive_principals"] == [["CORP\\alice", 2]]


def test_dedupe_principal_match_is_case_insensitive():
    obs = [
        _logon("remote_interactive", principal="CORP\\Alice", timestamp="2026-08-17T09:00:00Z"),
        _logon("remote_interactive", principal="corp\\alice", timestamp="2026-08-17T09:00:03Z"),
    ]
    findings = _run(obs)
    assert findings[0].details["remote_interactive_logons"] == 1
    assert findings[0].details["interactive_principals"] == [["CORP\\Alice", 1]]


def test_dedupe_not_applied_across_principals_or_kinds():
    obs = [
        # Same second, different principals: two logons.
        _logon("remote_interactive", principal="CORP\\alice", timestamp="2026-08-17T09:00:00Z"),
        _logon("remote_interactive", principal="CORP\\bob", timestamp="2026-08-17T09:00:00Z"),
        # Same principal and time as the first, different kind: counted.
        _logon("network", principal="CORP\\alice", timestamp="2026-08-17T09:00:00Z"),
    ]
    details = _run(obs)[0].details
    assert details["remote_interactive_logons"] == 2
    assert details["network_logons"] == 1


def test_deterministic_output():
    obs = [
        _logon("interactive", principal="CORP\\alice"),
        _logon("remote_interactive", principal="CORP\\bob"),
        _logon("batch", principal="CORP\\svc_batch"),
        _logon(None, action="logon_failed"),
    ]
    first = [f.to_json_dict() for f in _run(obs)]
    second = [f.to_json_dict() for f in _run(obs)]
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
