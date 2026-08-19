"""Tests for the network collector (socket_state observations)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from wtfserver.collectors.base import CollectionContext
from wtfserver.collectors.windows.network import COLLECTOR, NetworkCollector
from wtfserver.collectors.windows.powershell import PowerShellError
from wtfserver.model import Category

from helpers import FakePowerShell

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)
NOW_ISO = "2026-08-19T12:00:00Z"


def make_ctx(runner, raws=None):
    store = raws if raws is not None else {}

    def add_raw(name, content):
        store[name] = content
        return f"raw/{name}"

    return CollectionContext(since=None, now=NOW, runner=runner, add_raw=add_raw)


def tcp_entry(**overrides):
    entry = {
        "local_address": "0.0.0.0",
        "local_port": 443,
        "remote_address": "0.0.0.0",
        "remote_port": 0,
        "state": "Listen",
        "pid": 4000,
        "process_name": "w3wp",
    }
    entry.update(overrides)
    return entry


def udp_entry(**overrides):
    entry = {"local_address": "0.0.0.0", "local_port": 161, "pid": 2100,
             "process_name": "snmp"}
    entry.update(overrides)
    return entry


def test_module_exports_collector_instance():
    assert isinstance(COLLECTOR, NetworkCollector)
    assert COLLECTOR.name == "network"
    assert COLLECTOR.platforms == ("windows",)
    assert Category.SOCKET_STATE in COLLECTOR.categories


def test_tcp_states_mapped_and_transients_counted_in_stats():
    tcp = [
        tcp_entry(),
        tcp_entry(local_address="10.1.1.5", local_port=52011,
                  remote_address="10.9.9.20", remote_port=1433,
                  state="Established", pid=5100, process_name="exporter"),
        tcp_entry(state="TimeWait", pid=None, process_name=None),
        tcp_entry(state="TimeWait", pid=None, process_name=None),
        tcp_entry(state="CloseWait"),
    ]
    raws = {}
    runner = FakePowerShell([
        ("Get-NetTCPConnection", tcp),
        ("Get-NetUDPEndpoint", []),
    ])
    result = COLLECTOR.collect(make_ctx(runner, raws))

    assert result.errors == []
    assert len(result.observations) == 2

    listening, established = result.observations
    assert listening.action == "listening"
    assert listening.timestamp == NOW_ISO
    assert listening.process == "w3wp"
    assert listening.remote_host is None
    assert listening.remote_port is None
    assert listening.attributes == {
        "protocol": "tcp",
        "local_address": "0.0.0.0",
        "local_port": 443,
        "pid": 4000,
        "state": "Listen",
    }
    assert listening.raw_reference == "raw/network_tcp.json"

    assert established.action == "established"
    assert established.remote_host == "10.9.9.20"
    assert established.remote_port == 1433
    assert established.process == "exporter"
    assert established.attributes["state"] == "Established"

    assert result.stats["tcp_total"] == 5
    assert result.stats["udp_total"] == 0
    assert result.stats["tcp_ignored_states"] == {"CloseWait": 1, "TimeWait": 2}
    assert json.loads(raws["network_tcp.json"])[0]["state"] == "Listen"


def test_udp_listeners_and_loopback_are_collected():
    runner = FakePowerShell([
        ("Get-NetTCPConnection", [tcp_entry(local_address="127.0.0.1", local_port=8500)]),
        ("Get-NetUDPEndpoint", [udp_entry(), udp_entry(local_address="127.0.0.1",
                                                       local_port=53, pid=None,
                                                       process_name=None)]),
    ])
    result = COLLECTOR.collect(make_ctx(runner))

    assert result.errors == []
    assert len(result.observations) == 3
    # Loopback TCP listener is kept — analyzers filter, collectors do not.
    assert result.observations[0].attributes["local_address"] == "127.0.0.1"

    udp_obs = [o for o in result.observations if o.attributes["protocol"] == "udp"]
    assert len(udp_obs) == 2
    for obs in udp_obs:
        assert obs.action == "listening"
        assert obs.attributes["state"] is None
        assert obs.raw_reference == "raw/network_udp.json"
    assert udp_obs[0].process == "snmp"
    assert udp_obs[1].process is None
    assert udp_obs[1].attributes["pid"] is None


def test_single_object_collapse_and_ipv6():
    tcp = tcp_entry(local_address="::", local_port=5985, state="Listen",
                    process_name="svchost")
    udp = udp_entry(local_address="fe80::1%4", local_port=546)
    runner = FakePowerShell([
        ("Get-NetTCPConnection", tcp),  # bare object, not a list
        ("Get-NetUDPEndpoint", udp),
    ])
    result = COLLECTOR.collect(make_ctx(runner))

    assert result.errors == []
    assert len(result.observations) == 2
    assert result.observations[0].attributes["local_address"] == "::"
    assert result.observations[1].attributes["local_address"] == "fe80::1%4"
    assert result.observations[1].attributes["local_port"] == 546


def test_ipv6_established_remote():
    tcp = [tcp_entry(local_address="2001:db8::10", local_port=51000,
                     remote_address="2001:db8::5", remote_port=443,
                     state="Established")]
    runner = FakePowerShell([
        ("Get-NetTCPConnection", tcp),
        ("Get-NetUDPEndpoint", []),
    ])
    result = COLLECTOR.collect(make_ctx(runner))
    obs = result.observations[0]
    assert obs.remote_host == "2001:db8::5"
    assert obs.remote_port == 443


def test_one_subquery_failure_gives_partial_result():
    runner = FakePowerShell([
        ("Get-NetTCPConnection", PowerShellError("Get-NetTCPConnection not found")),
        ("Get-NetUDPEndpoint", [udp_entry()]),
    ])
    result = COLLECTOR.collect(make_ctx(runner))

    assert len(result.observations) == 1
    assert result.observations[0].attributes["protocol"] == "udp"
    assert len(result.errors) == 1
    assert not result.errors[0].fatal
    assert "TCP" in result.errors[0].message


def test_both_subqueries_failing_is_fatal():
    runner = FakePowerShell([
        ("Get-NetTCPConnection", PowerShellError("boom tcp")),
        ("Get-NetUDPEndpoint", PowerShellError("boom udp")),
    ])
    result = COLLECTOR.collect(make_ctx(runner))
    assert result.observations == []
    assert len(result.errors) == 2
    assert all(e.fatal for e in result.errors)


def test_malformed_entries_are_skipped_not_fatal():
    tcp = [
        tcp_entry(),
        "garbage",
        {"state": "Listen"},  # local_port missing
    ]
    runner = FakePowerShell([
        ("Get-NetTCPConnection", tcp),
        ("Get-NetUDPEndpoint", ["junk", udp_entry()]),
    ])
    result = COLLECTOR.collect(make_ctx(runner))

    assert len(result.observations) == 2  # one good TCP + one good UDP
    assert len(result.errors) == 3
    assert not any(e.fatal for e in result.errors)
