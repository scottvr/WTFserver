"""Tests for the associations analyzer (process_association findings)."""

from __future__ import annotations

import json

from wtfserver.analyzers.associations import ANALYZER, AssociationsAnalyzer
from wtfserver.model import Category, FindingType

from helpers import build_ctx, make_obs


def _sched_obs(n, process="C:\\Apps\\export.exe", task="\\Vendor\\Nightly", **kw):
    return [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            action="action_start",
            timestamp=f"2026-08-{16 + i}T01:00:00Z",
            process=process,
            scheduled_action=task,
            **kw,
        )
        for i in range(n)
    ]


def test_module_exports_analyzer_instance():
    assert isinstance(ANALYZER, AssociationsAnalyzer)
    assert ANALYZER.name == "associations"


def test_pair_at_threshold_fires():
    obs = _sched_obs(3)
    findings = ANALYZER.analyze(build_ctx(obs))
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == FindingType.PROCESS_ASSOCIATION
    assert f.evidence_class == "observed"
    assert f.details["process"] == "export.exe"
    assert f.details["process_path"] == "C:\\Apps\\export.exe"
    assert f.details["associated_with"] == {
        "kind": "scheduled_action",
        "name": "\\Vendor\\Nightly",
        "count": 3,
    }
    assert f.details["total_process_observations"] == 3
    assert len(f.supporting_observations) == 3
    assert "supporting_capped" not in f.details


def test_pair_below_threshold_does_not_fire():
    obs = _sched_obs(2)
    assert ANALYZER.analyze(build_ctx(obs)) == []


def test_noise_principals_and_machine_accounts_excluded():
    obs = []
    for principal in ("NT AUTHORITY\\SYSTEM", "LOCAL SERVICE", "CORP\\HOST01$"):
        for i in range(3):
            obs.append(
                make_obs(
                    Category.PROCESS_ACTIVITY,
                    action="start",
                    timestamp=f"2026-08-17T0{i}:00:00Z",
                    process="C:\\Windows\\System32\\svchost.exe",
                    principal=principal,
                )
            )
    # A real service account must still associate.
    for i in range(3):
        obs.append(
            make_obs(
                Category.PROCESS_ACTIVITY,
                action="start",
                timestamp=f"2026-08-17T1{i}:00:00Z",
                process="C:\\Apps\\export.exe",
                principal="CORP\\svc_batch",
            )
        )
    findings = ANALYZER.analyze(build_ctx(obs))
    assert len(findings) == 1
    assert findings[0].details["associated_with"]["name"] == "CORP\\svc_batch"


def test_current_state_observations_do_not_count():
    # Same process/service pairing three times, but as current state — no finding.
    obs = [
        make_obs(
            Category.SERVICE_STATE,
            action="configured",
            timestamp="2026-08-19T12:00:00Z",
            process="C:\\Apps\\agent.exe",
            service="VendorAgent",
        )
        for _ in range(3)
    ]
    assert ANALYZER.analyze(build_ctx(obs)) == []


def test_missing_associates_counted_in_total_but_no_pair():
    # Process-only observations (no scheduled_action/service/principal/peer)
    # produce no pairs but do raise the process total.
    obs = _sched_obs(3) + [
        make_obs(
            Category.PROCESS_ACTIVITY,
            action="start",
            timestamp="2026-08-18T05:00:00Z",
            process="C:\\Apps\\export.exe",
        )
    ]
    findings = ANALYZER.analyze(build_ctx(obs))
    assert len(findings) == 1
    assert findings[0].details["associated_with"]["count"] == 3
    assert findings[0].details["total_process_observations"] == 4


def test_process_path_is_most_common_variant():
    obs = _sched_obs(2, process="C:\\Apps\\export.exe") + _sched_obs(
        3, process="D:\\Other\\export.exe"
    )
    findings = ANALYZER.analyze(build_ctx(obs))
    assert len(findings) == 1
    assert findings[0].details["associated_with"]["count"] == 5
    assert findings[0].details["process_path"] == "D:\\Other\\export.exe"


def test_peer_association_uses_host_port_name():
    obs = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            action="action_start",
            timestamp=f"2026-08-1{6 + i}T01:00:00Z",
            process="C:\\Apps\\sync.exe",
            remote_host="10.0.0.5",
            remote_port=1433,
        )
        for i in range(3)
    ]
    findings = ANALYZER.analyze(build_ctx(obs))
    assert len(findings) == 1
    assert findings[0].details["associated_with"] == {
        "kind": "peer",
        "name": "10.0.0.5:1433",
        "count": 3,
    }


def test_ordering_count_desc_then_process_then_name():
    obs = []
    # 4 co-occurrences: zeta.exe + service Bravo
    for i in range(4):
        obs.append(
            make_obs(
                Category.SERVICE_ACTIVITY,
                action="start",
                timestamp=f"2026-08-17T0{i}:10:00Z",
                process="C:\\z\\zeta.exe",
                service="Bravo",
            )
        )
    # 3 co-occurrences each, equal counts: alpha.exe+ServiceB, alpha.exe+ServiceA,
    # beta.exe+ServiceA — expect alpha/ServiceA, alpha/ServiceB, beta/ServiceA.
    for svc in ("ServiceB", "ServiceA"):
        for i in range(3):
            obs.append(
                make_obs(
                    Category.SERVICE_ACTIVITY,
                    action="start",
                    timestamp=f"2026-08-18T0{i}:00:00Z",
                    process="C:\\a\\alpha.exe",
                    service=svc,
                )
            )
    for i in range(3):
        obs.append(
            make_obs(
                Category.SERVICE_ACTIVITY,
                action="start",
                timestamp=f"2026-08-18T1{i}:00:00Z",
                process="C:\\b\\beta.exe",
                service="ServiceA",
            )
        )
    findings = ANALYZER.analyze(build_ctx(obs))
    keys = [(f.details["process"], f.details["associated_with"]["name"]) for f in findings]
    assert keys == [
        ("zeta.exe", "Bravo"),
        ("alpha.exe", "ServiceA"),
        ("alpha.exe", "ServiceB"),
        ("beta.exe", "ServiceA"),
    ]


def test_supporting_observations_capped_at_50():
    obs = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            action="action_start",
            timestamp=f"2026-08-17T{i // 60:02d}:{i % 60:02d}:00Z",
            process="C:\\Apps\\export.exe",
            scheduled_action="\\Vendor\\Nightly",
        )
        for i in range(60)
    ]
    findings = ANALYZER.analyze(build_ctx(obs))
    assert len(findings) == 1
    f = findings[0]
    assert len(f.supporting_observations) == 50
    assert f.details["supporting_capped"] is True
    assert f.details["supporting_total"] == 60


def test_deterministic_output():
    obs = _sched_obs(5) + _sched_obs(3, process="C:\\b\\beta.exe", task="\\Other\\Task")

    def run():
        findings = ANALYZER.analyze(build_ctx(obs))
        return json.dumps([f.to_json_dict() for f in findings], sort_keys=True)

    first = run()
    # Finding IDs restart with each fresh context, so full output must match.
    assert first == run()
