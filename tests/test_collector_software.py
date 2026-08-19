"""Tests for the software collector (installed_role / installed_software)."""

from datetime import datetime, timezone

import pytest

from helpers import FakePowerShell
from wtfserver.collectors.base import CollectionContext
from wtfserver.collectors.windows.powershell import PowerShellError
from wtfserver.collectors.windows.software import COLLECTOR, parse_install_date
from wtfserver.model import Category

ROLES_KEY = "Get-WindowsFeature"
SOFTWARE_KEY = "Uninstall"


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


ROLES = [
    {"Name": "Web-Server", "DisplayName": "Web Server (IIS)"},
    {"Name": "FS-FileServer", "DisplayName": "File Server"},
]

SOFTWARE = [
    {
        "DisplayName": "7-Zip 22.01 (x64)",
        "DisplayVersion": "22.01",
        "Publisher": "Igor Pavlov",
        "InstallDate": "20230514",
    },
    {
        # Patch/component key without DisplayName: silently skipped.
        "DisplayName": None,
        "DisplayVersion": "1.0",
        "Publisher": "Microsoft",
        "InstallDate": None,
    },
    {
        "DisplayName": "Vendor Agent",
        "DisplayVersion": None,
        "Publisher": None,
        "InstallDate": "not-a-date",
    },
]


def test_normalizes_roles_and_software():
    runner = FakePowerShell([(ROLES_KEY, ROLES), (SOFTWARE_KEY, SOFTWARE)])
    ctx, raw = make_ctx(runner)
    result = COLLECTOR.collect(ctx)

    assert not result.errors
    roles = [o for o in result.observations if o.category == Category.INSTALLED_ROLE]
    software = [
        o for o in result.observations if o.category == Category.INSTALLED_SOFTWARE
    ]
    assert len(roles) == 2
    assert len(software) == 2
    assert result.stats == {"installed_roles": 2, "installed_software": 2}

    web = roles[0]
    assert web.source == "software"
    assert web.action == "installed"
    assert web.timestamp == "2026-08-19T12:00:00Z"
    assert web.attributes == {"name": "Web-Server", "display_name": "Web Server (IIS)"}
    assert web.message == "Web Server (IIS)"
    assert web.raw_reference == "raw/roles.json#0"

    zip_obs = software[0]
    assert zip_obs.action == "installed"
    assert zip_obs.message == "7-Zip 22.01 (x64)"
    assert zip_obs.attributes == {
        "name": "7-Zip 22.01 (x64)",
        "version": "22.01",
        "vendor": "Igor Pavlov",
        "install_date": "2023-05-14T00:00:00Z",
    }
    assert zip_obs.raw_reference == "raw/software.json#0"

    agent = software[1]
    assert agent.attributes["version"] is None
    assert agent.attributes["vendor"] is None
    assert agent.attributes["install_date"] is None  # unparseable date
    # Raw index counts skipped entries, so this is payload index 2.
    assert agent.raw_reference == "raw/software.json#2"

    assert "roles.json" in raw
    assert "software.json" in raw


def test_get_windowsfeature_absent_is_nonfatal_error():
    # Client SKUs have no Get-WindowsFeature; the script reports a marker.
    runner = FakePowerShell([(ROLES_KEY, {"unavailable": True}), (SOFTWARE_KEY, SOFTWARE)])
    ctx, _ = make_ctx(runner)
    result = COLLECTOR.collect(ctx)

    assert len(result.errors) == 1
    assert not result.errors[0].fatal
    assert "Get-WindowsFeature" in result.errors[0].message
    assert all(
        o.category == Category.INSTALLED_SOFTWARE for o in result.observations
    )
    assert len(result.observations) == 2


def test_roles_runner_exception_software_still_collected():
    runner = FakePowerShell(
        [(ROLES_KEY, PowerShellError("boom")), (SOFTWARE_KEY, SOFTWARE)]
    )
    ctx, _ = make_ctx(runner)
    result = COLLECTOR.collect(ctx)
    assert len(result.observations) == 2
    assert len(result.errors) == 1
    assert not result.errors[0].fatal


def test_both_queries_failing_is_fatal():
    runner = FakePowerShell(
        [(ROLES_KEY, PowerShellError("boom")), (SOFTWARE_KEY, PowerShellError("bang"))]
    )
    ctx, _ = make_ctx(runner)
    result = COLLECTOR.collect(ctx)
    assert result.observations == []
    assert any(e.fatal for e in result.errors)


def test_single_object_payloads_are_handled():
    # ConvertTo-Json collapses one-element arrays to a bare object.
    runner = FakePowerShell([(ROLES_KEY, ROLES[0]), (SOFTWARE_KEY, SOFTWARE[0])])
    ctx, _ = make_ctx(runner)
    result = COLLECTOR.collect(ctx)
    assert not result.errors
    categories = sorted(o.category for o in result.observations)
    assert categories == [Category.INSTALLED_ROLE, Category.INSTALLED_SOFTWARE]


def test_empty_payloads_yield_nothing():
    runner = FakePowerShell([(ROLES_KEY, []), (SOFTWARE_KEY, None)])
    ctx, _ = make_ctx(runner)
    result = COLLECTOR.collect(ctx)
    assert result.observations == []
    assert result.errors == []


def test_software_without_display_name_skipped_silently():
    runner = FakePowerShell(
        [(ROLES_KEY, []), (SOFTWARE_KEY, [{"DisplayVersion": "1.0"}, {"DisplayName": ""}])]
    )
    ctx, _ = make_ctx(runner)
    result = COLLECTOR.collect(ctx)
    assert result.observations == []
    assert result.errors == []


def test_malformed_software_payload_is_error_roles_survive():
    runner = FakePowerShell([(ROLES_KEY, ROLES), (SOFTWARE_KEY, "garbage")])
    ctx, _ = make_ctx(runner)
    result = COLLECTOR.collect(ctx)
    assert len(result.observations) == 2
    assert all(o.category == Category.INSTALLED_ROLE for o in result.observations)
    assert len(result.errors) == 1
    assert not result.errors[0].fatal


def test_role_entry_without_name_is_error_but_others_survive():
    runner = FakePowerShell(
        [(ROLES_KEY, [{"DisplayName": "nameless"}, ROLES[1]]), (SOFTWARE_KEY, [])]
    )
    ctx, _ = make_ctx(runner)
    result = COLLECTOR.collect(ctx)
    assert len(result.observations) == 1
    assert result.observations[0].attributes["name"] == "FS-FileServer"
    assert result.observations[0].raw_reference == "raw/roles.json#1"
    assert len(result.errors) == 1
    assert not result.errors[0].fatal


def test_role_without_display_name_falls_back_to_name():
    runner = FakePowerShell([(ROLES_KEY, [{"Name": "DNS"}]), (SOFTWARE_KEY, [])])
    ctx, _ = make_ctx(runner)
    result = COLLECTOR.collect(ctx)
    obs = result.observations[0]
    assert obs.message == "DNS"
    assert obs.attributes == {"name": "DNS", "display_name": None}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("20230514", "2023-05-14T00:00:00Z"),
        ("19991231", "1999-12-31T00:00:00Z"),
        ("20230532", None),  # invalid day
        ("2023-05-14", None),  # wrong format
        ("", None),
        (None, None),
        (20230514, None),  # non-string
    ],
)
def test_parse_install_date(value, expected):
    assert parse_install_date(value) == expected
