"""Tests for the services collector (service_state observations)."""

from datetime import datetime, timezone

import pytest

from helpers import FakePowerShell
from wtfserver.collectors.base import CollectionContext
from wtfserver.collectors.windows.powershell import PowerShellError
from wtfserver.collectors.windows.services import COLLECTOR, extract_executable
from wtfserver.model import Category

SCRIPT_KEY = "Win32_Service"


def make_ctx(runner):
    raw = {}

    def add_raw(name, content):
        raw[name] = content
        return f"raw/{name}"

    ctx = CollectionContext(
        since=None,
        now=datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc),
        runner=runner,
        add_raw=add_raw,
        options={},
    )
    return ctx, raw


REALISTIC_SERVICES = [
    {
        "Name": "VendorSync",
        "DisplayName": "Vendor Sync Service",
        "State": "Running",
        "StartMode": "Auto",
        "StartName": "CORP\\svc_sync",
        "PathName": '"C:\\Program Files\\Vendor\\syncsvc.exe" -config prod',
    },
    {
        "Name": "Dnscache",
        "DisplayName": "DNS Client",
        "State": "Running",
        "StartMode": "Manual",
        "StartName": "NT AUTHORITY\\NetworkService",
        "PathName": "C:\\Windows\\system32\\svchost.exe -k NetworkService -p",
    },
    {
        "Name": "OldAgent",
        "DisplayName": "Old Agent",
        "State": "Stopped",
        "StartMode": "Disabled",
        "StartName": "LocalSystem",
        "PathName": None,
    },
]


def test_normalizes_services():
    ctx, raw = make_ctx(FakePowerShell([(SCRIPT_KEY, REALISTIC_SERVICES)]))
    result = COLLECTOR.collect(ctx)

    assert not result.errors
    assert len(result.observations) == 3
    assert result.stats["services"] == 3

    first = result.observations[0]
    assert first.category == Category.SERVICE_STATE
    assert first.source == "services"
    assert first.action == "configured"
    assert first.timestamp == "2026-08-19T12:00:00Z"
    assert first.service == "VendorSync"
    assert first.principal == "CORP\\svc_sync"
    assert first.process == "C:\\Program Files\\Vendor\\syncsvc.exe"
    assert first.attributes["display_name"] == "Vendor Sync Service"
    assert first.attributes["state"] == "running"
    assert first.attributes["start_mode"] == "auto"
    assert (
        first.attributes["raw_path"]
        == '"C:\\Program Files\\Vendor\\syncsvc.exe" -config prod'
    )
    assert first.raw_reference == "raw/services.json#0"

    second = result.observations[1]
    assert second.process == "C:\\Windows\\system32\\svchost.exe"
    assert second.attributes["start_mode"] == "manual"
    assert second.raw_reference == "raw/services.json#1"

    third = result.observations[2]
    assert third.process is None
    assert third.attributes["raw_path"] is None
    assert third.attributes["state"] == "stopped"
    assert third.attributes["start_mode"] == "disabled"

    assert "services.json" in raw


def test_single_object_payload_is_handled():
    # ConvertTo-Json collapses one-element arrays to a bare object.
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, REALISTIC_SERVICES[0])]))
    result = COLLECTOR.collect(ctx)
    assert not result.errors
    assert len(result.observations) == 1
    assert result.observations[0].service == "VendorSync"
    assert result.observations[0].raw_reference == "raw/services.json#0"


def test_empty_payload_yields_no_observations():
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, None)]))
    result = COLLECTOR.collect(ctx)
    assert result.observations == []
    assert result.errors == []


def test_missing_fields_tolerated():
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [{"Name": "Bare"}])]))
    result = COLLECTOR.collect(ctx)
    assert not result.errors
    obs = result.observations[0]
    assert obs.service == "Bare"
    assert obs.principal is None
    assert obs.process is None
    assert obs.attributes["display_name"] is None
    assert obs.attributes["state"] is None
    assert obs.attributes["start_mode"] is None
    assert obs.attributes["raw_path"] is None


def test_entry_without_name_is_error_but_others_survive():
    payload = [{"DisplayName": "No name here"}, REALISTIC_SERVICES[1]]
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, payload)]))
    result = COLLECTOR.collect(ctx)
    assert len(result.observations) == 1
    assert result.observations[0].service == "Dnscache"
    # Original payload index is preserved in the raw reference.
    assert result.observations[0].raw_reference == "raw/services.json#1"
    assert len(result.errors) == 1
    assert not result.errors[0].fatal


def test_non_object_entry_is_error_not_crash():
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, ["garbage", REALISTIC_SERVICES[0]])]))
    result = COLLECTOR.collect(ctx)
    assert len(result.observations) == 1
    assert len(result.errors) == 1


def test_runner_exception_becomes_fatal_collector_error():
    ctx, _ = make_ctx(
        FakePowerShell([(SCRIPT_KEY, PowerShellError("access is denied"))])
    )
    result = COLLECTOR.collect(ctx)
    assert result.observations == []
    assert len(result.errors) == 1
    assert result.errors[0].fatal
    assert "access is denied" in result.errors[0].message


def test_malformed_payload_type_is_fatal_error():
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, "not json objects")]))
    result = COLLECTOR.collect(ctx)
    assert result.observations == []
    assert len(result.errors) == 1
    assert result.errors[0].fatal


@pytest.mark.parametrize(
    ("raw_path", "expected"),
    [
        ('"C:\\Program Files\\App\\app.exe" -x y', "C:\\Program Files\\App\\app.exe"),
        (
            "C:\\Windows\\system32\\svchost.exe -k netsvcs",
            "C:\\Windows\\system32\\svchost.exe",
        ),
        ("C:\\WINDOWS\\system32\\lsass.exe", "C:\\WINDOWS\\system32\\lsass.exe"),
        (
            "C:\\Program Files\\Foo Bar\\agent.exe /service",
            "C:\\Program Files\\Foo Bar\\agent.exe",
        ),
        ("C:\\UPPER\\SVC.EXE -k thing", "C:\\UPPER\\SVC.EXE"),
        ('"C:\\odd\\unterminated.exe', "C:\\odd\\unterminated.exe"),
        ("C:\\tools\\runner.cmd nightly", "C:\\tools\\runner.cmd"),
        ("noext -flag", "noext"),
        (None, None),
        ("", None),
        ("   ", None),
        # Earliest extension boundary wins: a .exe in the ARGUMENTS must not
        # beat a lower-priority extension that ends the actual executable.
        (
            "C:\\App\\launcher.bat --exec C:\\App\\worker.exe",
            "C:\\App\\launcher.bat",
        ),
        ("C:\\scripts\\job.cmd arg.exe", "C:\\scripts\\job.cmd"),
        ("C:\\APP\\RUN.BAT cleanup.exe", "C:\\APP\\RUN.BAT"),
        # Must NOT truncate at an extension substring that is not followed by
        # end-of-string or whitespace (directory named *.exe.d).
        ("C:\\apps.exe.d\\tool.exe -x", "C:\\apps.exe.d\\tool.exe"),
        # Extension at end of string, no arguments, lower-priority extension.
        ("C:\\jobs\\nightly.bat", "C:\\jobs\\nightly.bat"),
    ],
)
def test_extract_executable(raw_path, expected):
    assert extract_executable(raw_path) == expected
