"""Tests for the peers analyzer (peer_dependency findings)."""

from __future__ import annotations

import json

from wtfserver.analyzers.peers import ANALYZER, PeersAnalyzer
from wtfserver.model import Category, FindingType

from helpers import build_ctx, make_obs


def _socket(host, port, process=None, action="established"):
    return make_obs(
        Category.SOCKET_STATE,
        action=action,
        timestamp="2026-08-19T12:00:00Z",
        remote_host=host,
        remote_port=port,
        process=process,
        attributes={"protocol": "tcp", "local_address": "10.0.0.2", "local_port": 50000},
    )


def _historical(host, port=None, category=Category.SCHEDULED_ACTIVITY, **kw):
    defaults = {"action": "action_start", "timestamp": "2026-08-17T01:00:00Z"}
    defaults.update(kw)
    return make_obs(category, remote_host=host, remote_port=port, **defaults)


def test_module_exports_analyzer_instance():
    assert isinstance(ANALYZER, PeersAnalyzer)
    assert ANALYZER.name == "peers"


def test_loopback_unspecified_linklocal_filtered():
    obs = [
        _socket("127.0.0.1", 445),
        _socket("127.9.9.9", 445),
        _socket("::1", 445),
        _socket("0.0.0.0", 445),
        _socket("::", 445),
        _socket("169.254.10.20", 445),
        _socket("fe80::1", 445),
        _socket("fe80::1%eth0", 445),
    ]
    assert ANALYZER.analyze(build_ctx(obs)) == []


def test_hostname_remote_host_is_kept():
    obs = [_socket("db01.corp.example", 1433)]
    findings = ANALYZER.analyze(build_ctx(obs))
    assert len(findings) == 1
    assert findings[0].details["remote_host"] == "db01.corp.example"


def test_service_hint_map():
    obs = [
        _socket("10.0.0.5", 1433),
        _socket("10.0.0.6", 22),
        _socket("10.0.0.7", 4444),
    ]
    findings = ANALYZER.analyze(build_ctx(obs))
    hints = {f.details["remote_host"]: f.details["service_hint"] for f in findings}
    assert hints == {"10.0.0.5": "mssql", "10.0.0.6": "ssh/sftp", "10.0.0.7": None}


def test_evidence_current_historical_both():
    obs = [
        _socket("10.0.0.5", 1433, process="C:\\Apps\\sync.exe"),
        _historical("10.0.0.5", 1433),
        _socket("10.0.0.8", 443),
        _historical("10.0.0.9", 22),
    ]
    findings = ANALYZER.analyze(build_ctx(obs))
    for f in findings:
        assert f.finding_type == FindingType.PEER_DEPENDENCY
        assert f.evidence_class == "observed"
    by_host = {f.details["remote_host"]: f.details for f in findings}
    assert by_host["10.0.0.5"]["evidence"] == "both"
    assert by_host["10.0.0.5"]["count"] == 2
    assert by_host["10.0.0.8"]["evidence"] == "current"
    assert by_host["10.0.0.9"]["evidence"] == "historical"


def test_logon_remote_host_is_not_a_peer():
    obs = [
        make_obs(
            Category.LOGON,
            action="logon",
            timestamp=f"2026-08-17T0{i}:00:00Z",
            principal="CORP\\admin",
            remote_host="10.0.0.50",
        )
        for i in range(3)
    ]
    assert ANALYZER.analyze(build_ctx(obs)) == []


def test_null_port_grouped_separately():
    obs = [
        _historical("10.0.0.9", None),
        _historical("10.0.0.9", None),
        _historical("10.0.0.9", 443),
    ]
    findings = ANALYZER.analyze(build_ctx(obs))
    assert len(findings) == 2
    keyed = {
        (f.details["remote_host"], f.details["remote_port"]): f.details["count"]
        for f in findings
    }
    assert keyed == {("10.0.0.9", None): 2, ("10.0.0.9", 443): 1}


def test_missing_remote_host_and_listening_sockets_skipped():
    obs = [
        _socket(None, None, action="established"),
        _socket("10.0.0.1", None, action="listening"),
        make_obs(Category.EVENT, timestamp="2026-08-17T01:00:00Z", remote_host=""),
    ]
    assert ANALYZER.analyze(build_ctx(obs)) == []


def test_processes_top5_by_frequency():
    obs = []
    procs = ["a.exe"] * 3 + ["b.exe"] * 2 + ["c.exe", "d.exe", "e.exe", "f.exe"]
    for i, proc in enumerate(procs):
        obs.append(
            _historical(
                "10.0.0.5",
                1433,
                category=Category.PROCESS_ACTIVITY,
                action="start",
                timestamp=f"2026-08-17T0{i}:00:00Z",
                process=f"C:\\Apps\\{proc}",
            )
        )
    findings = ANALYZER.analyze(build_ctx(obs))
    assert len(findings) == 1
    # frequency desc, then name asc, capped at 5 basenames
    assert findings[0].details["processes"] == ["a.exe", "b.exe", "c.exe", "d.exe", "e.exe"]


def test_sorted_by_count_desc_then_host():
    obs = (
        [_historical("10.0.0.2", 443, timestamp=f"2026-08-17T0{i}:00:00Z") for i in range(3)]
        + [_historical("10.0.0.1", 443, timestamp=f"2026-08-17T1{i}:00:00Z") for i in range(2)]
        + [_historical("10.0.0.3", 443, timestamp="2026-08-17T20:00:00Z")]
        + [_historical("10.0.0.0", 443, timestamp="2026-08-17T21:00:00Z")]
    )
    findings = ANALYZER.analyze(build_ctx(obs))
    hosts = [f.details["remote_host"] for f in findings]
    assert hosts == ["10.0.0.2", "10.0.0.1", "10.0.0.0", "10.0.0.3"]


def test_cap_at_25_with_omitted_noted_on_last_finding():
    obs = []
    for i in range(30):
        # host 10.0.i.1 seen (30 - i) times: distinct counts force stable order
        for j in range(30 - i):
            obs.append(
                _historical(
                    f"10.0.{i}.1",
                    443,
                    timestamp=f"2026-08-17T{j % 24:02d}:{i:02d}:00Z",
                )
            )
    findings = ANALYZER.analyze(build_ctx(obs))
    assert len(findings) == 25
    counts = [f.details["count"] for f in findings]
    assert counts == list(range(30, 5, -1))
    assert all("peers_omitted" not in f.details for f in findings[:-1])
    assert findings[-1].details["peers_omitted"] == 5


def test_no_omission_note_when_under_cap():
    findings = ANALYZER.analyze(build_ctx([_socket("10.0.0.5", 1433)]))
    assert len(findings) == 1
    assert "peers_omitted" not in findings[0].details


def test_deterministic_output():
    obs = [
        _socket("10.0.0.5", 1433, process="C:\\Apps\\sync.exe"),
        _historical("10.0.0.5", 1433),
        _historical("10.0.0.9", None),
        _historical("10.0.0.9", None),
    ]

    def run():
        findings = ANALYZER.analyze(build_ctx(obs))
        return json.dumps([f.to_json_dict() for f in findings], sort_keys=True)

    first = run()
    assert first == run()
