"""Tests for the host_identity collector (single host_identity observation)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from wtfserver.collectors.base import CollectionContext
from wtfserver.collectors.windows.host_identity import COLLECTOR, HostIdentityCollector
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


def responses(computer_system=None, operating_system=None, ip_addresses=None,
              dns_servers=None):
    return [
        ("Win32_ComputerSystem", computer_system if computer_system is not None
         else {"Name": "APP01", "Domain": "corp.example.com",
               "PartOfDomain": True, "DomainRole": 3}),
        ("Win32_OperatingSystem", operating_system if operating_system is not None
         else {"Caption": "Microsoft Windows Server 2019 Standard",
               "Version": "10.0.17763",
               "LastBootUpTime": "2026-08-01T04:12:33.5551234Z"}),
        ("Get-NetIPAddress", ip_addresses if ip_addresses is not None
         else [
             {"InterfaceAlias": "Ethernet0", "IPAddress": "10.1.1.5",
              "AddressFamily": 2},
             {"InterfaceAlias": "Ethernet0", "IPAddress": "fe80::20c:29ff:fe11:2233",
              "AddressFamily": 23},
             {"InterfaceAlias": "Ethernet0", "IPAddress": "169.254.10.99",
              "AddressFamily": 2},  # APIPA, must be skipped
             {"InterfaceAlias": "Loopback Pseudo-Interface 1",
              "IPAddress": "127.0.0.1", "AddressFamily": 2},
         ]),
        ("Get-DnsClientServerAddress", dns_servers if dns_servers is not None
         else [
             {"InterfaceAlias": "Ethernet0",
              "ServerAddresses": ["10.1.1.10", "10.1.1.11"]},
             {"InterfaceAlias": "Loopback Pseudo-Interface 1",
              "ServerAddresses": []},
             {"InterfaceAlias": "Ethernet1", "ServerAddresses": ["10.1.1.10"]},
         ]),
    ]


def test_module_exports_collector_instance():
    assert isinstance(COLLECTOR, HostIdentityCollector)
    assert COLLECTOR.name == "host_identity"
    assert COLLECTOR.platforms == ("windows",)
    assert Category.HOST_IDENTITY in COLLECTOR.categories


def test_domain_member_full_identity():
    raws = {}
    runner = FakePowerShell(responses())
    result = COLLECTOR.collect(make_ctx(runner, raws))

    assert result.errors == []
    assert len(result.observations) == 1  # exactly one, per contract
    obs = result.observations[0]
    assert obs.source == "host_identity"
    assert obs.category == Category.HOST_IDENTITY
    assert obs.action == "identity"
    assert obs.timestamp == NOW_ISO
    assert obs.raw_reference == "raw/host_identity.json"

    attrs = obs.attributes
    assert attrs["hostname"] == "APP01"
    assert attrs["fqdn"] == "APP01.corp.example.com"
    assert attrs["domain"] == "corp.example.com"
    assert attrs["domain_role"] == "member"
    assert attrs["os_name"] == "Microsoft Windows Server 2019 Standard"
    assert attrs["os_version"] == "10.0.17763"
    assert attrs["last_boot"] == "2026-08-01T04:12:33Z"  # renormalized to Z form
    # APIPA excluded; IPv6 kept; interfaces sorted by name.
    assert attrs["interfaces"] == [
        {"name": "Ethernet0",
         "addresses": ["10.1.1.5", "fe80::20c:29ff:fe11:2233"]},
        {"name": "Loopback Pseudo-Interface 1", "addresses": ["127.0.0.1"]},
    ]
    # Flattened and deduplicated across interfaces.
    assert attrs["dns_servers"] == ["10.1.1.10", "10.1.1.11"]
    assert json.loads(raws["host_identity.json"])["computer_system"]["Name"] == "APP01"


def test_workgroup_host_has_no_domain():
    runner = FakePowerShell(responses(
        computer_system={"Name": "LAB7", "Domain": "WORKGROUP",
                         "PartOfDomain": False, "DomainRole": 2},
    ))
    result = COLLECTOR.collect(make_ctx(runner))
    attrs = result.observations[0].attributes
    assert attrs["hostname"] == "LAB7"
    assert attrs["domain"] is None
    assert attrs["fqdn"] is None
    assert attrs["domain_role"] == "standalone"


def test_domain_controller_role_mapping():
    runner = FakePowerShell(responses(
        computer_system={"Name": "DC01", "Domain": "corp.example.com",
                         "PartOfDomain": True, "DomainRole": 5},
    ))
    attrs = COLLECTOR.collect(make_ctx(runner)).observations[0].attributes
    assert attrs["domain_role"] == "domain_controller"


def test_unknown_domain_role_is_null():
    runner = FakePowerShell(responses(
        computer_system={"Name": "X1", "Domain": "corp.example.com",
                         "PartOfDomain": True, "DomainRole": 99},
    ))
    attrs = COLLECTOR.collect(make_ctx(runner)).observations[0].attributes
    assert attrs["domain_role"] is None


def test_single_object_collapse_in_list_subqueries():
    runner = FakePowerShell(responses(
        ip_addresses={"InterfaceAlias": "Ethernet0", "IPAddress": "10.0.0.9",
                      "AddressFamily": 2},
        dns_servers={"InterfaceAlias": "Ethernet0",
                     "ServerAddresses": "10.0.0.53"},  # collapsed to bare string
    ))
    attrs = COLLECTOR.collect(make_ctx(runner)).observations[0].attributes
    assert attrs["interfaces"] == [{"name": "Ethernet0", "addresses": ["10.0.0.9"]}]
    assert attrs["dns_servers"] == ["10.0.0.53"]


def test_one_subquery_failure_gives_partial_observation():
    runner = FakePowerShell(responses(
        ip_addresses=PowerShellError("Get-NetIPAddress unavailable"),
    ))
    result = COLLECTOR.collect(make_ctx(runner))

    assert len(result.observations) == 1
    assert len(result.errors) == 1
    assert not result.errors[0].fatal
    attrs = result.observations[0].attributes
    assert attrs["hostname"] == "APP01"  # rest of the identity survives
    assert attrs["interfaces"] == []


def test_all_subqueries_failing_is_fatal():
    err = PowerShellError("no PowerShell")
    runner = FakePowerShell(responses(
        computer_system=err, operating_system=err, ip_addresses=err,
        dns_servers=err,
    ))
    result = COLLECTOR.collect(make_ctx(runner))
    assert result.observations == []
    assert len(result.errors) == 4
    assert all(e.fatal for e in result.errors)


def test_malformed_computer_system_payload_still_yields_observation():
    runner = FakePowerShell(responses(computer_system="garbage-not-an-object"))
    result = COLLECTOR.collect(make_ctx(runner))

    assert len(result.observations) == 1
    attrs = result.observations[0].attributes
    assert attrs["hostname"] is None
    assert attrs["domain"] is None
    assert attrs["domain_role"] is None
    # The healthy sub-queries still populate their fields.
    assert attrs["os_version"] == "10.0.17763"
    assert attrs["dns_servers"] == ["10.1.1.10", "10.1.1.11"]
