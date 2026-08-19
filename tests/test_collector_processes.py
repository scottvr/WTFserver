"""Tests for the processes collector (process_state observations)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from wtfserver.collectors.base import CollectionContext
from wtfserver.collectors.windows.powershell import PowerShellError
from wtfserver.collectors.windows.processes import COLLECTOR, ProcessesCollector
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


def proc_entry(**overrides):
    entry = {
        "pid": 4321,
        "parent_pid": 800,
        "name": "export.exe",
        "path": "C:\\Apps\\export.exe",
        "command_line": "C:\\Apps\\export.exe --nightly",
        "start_time": "2026-08-19T01:00:02.1234567Z",
        "owner": {"user": "svc_batch", "domain": "CORP"},
    }
    entry.update(overrides)
    return entry


def test_module_exports_collector_instance():
    assert isinstance(COLLECTOR, ProcessesCollector)
    assert COLLECTOR.name == "processes"
    assert COLLECTOR.platforms == ("windows",)
    assert Category.PROCESS_STATE in COLLECTOR.categories


def test_normal_payload_normalization():
    raws = {}
    runner = FakePowerShell([("Win32_Process", [proc_entry()])])
    result = COLLECTOR.collect(make_ctx(runner, raws))

    assert result.errors == []
    assert len(result.observations) == 1
    obs = result.observations[0]
    assert obs.source == "processes"
    assert obs.category == Category.PROCESS_STATE
    assert obs.action == "running"
    assert obs.timestamp == NOW_ISO
    assert obs.process == "C:\\Apps\\export.exe"
    assert obs.principal == "CORP\\svc_batch"
    assert obs.attributes["pid"] == 4321
    assert obs.attributes["parent_pid"] == 800
    assert obs.attributes["command_line"] == "C:\\Apps\\export.exe --nightly"
    # PS round-trip ISO ('o' format) is renormalized to the model's Z form.
    assert obs.attributes["start_time"] == "2026-08-19T01:00:02Z"
    assert obs.raw_reference == "raw/processes.json"
    assert json.loads(raws["processes.json"])[0]["pid"] == 4321
    assert result.stats["process_count"] == 1


def test_single_object_collapse_is_tolerated():
    # ConvertTo-Json collapses one-element arrays to a bare object.
    runner = FakePowerShell([("Win32_Process", proc_entry())])
    result = COLLECTOR.collect(make_ctx(runner))
    assert len(result.observations) == 1
    assert result.errors == []


def test_missing_owner_and_missing_path():
    entries = [
        proc_entry(pid=4, owner=None, path=None, name="System",
                   command_line=None, start_time=None),
        proc_entry(pid=5, owner={"user": "LocalAdmin", "domain": None}),
    ]
    runner = FakePowerShell([("Win32_Process", entries)])
    result = COLLECTOR.collect(make_ctx(runner))

    assert result.errors == []
    system, local = result.observations
    assert system.principal is None
    assert system.process == "System"  # fell back to name
    assert system.attributes["command_line"] is None
    assert system.attributes["start_time"] is None
    # Bare user when the domain part is absent.
    assert local.principal == "LocalAdmin"


def test_malformed_entries_are_skipped_not_fatal():
    entries = [
        proc_entry(pid=100),
        "garbage",  # not an object
        {"name": "nopid.exe"},  # pid missing
        proc_entry(pid="notanumber"),
    ]
    runner = FakePowerShell([("Win32_Process", entries)])
    result = COLLECTOR.collect(make_ctx(runner))

    assert len(result.observations) == 1
    assert result.observations[0].attributes["pid"] == 100
    assert len(result.errors) == 3
    assert not any(e.fatal for e in result.errors)
    assert result.stats["skipped_entries"] == 3
    assert result.stats["process_count"] == 1


def test_runner_failure_is_fatal():
    runner = FakePowerShell([("Win32_Process", PowerShellError("access denied"))])
    result = COLLECTOR.collect(make_ctx(runner))
    assert result.observations == []
    assert len(result.errors) == 1
    assert result.errors[0].fatal
    assert "access denied" in result.errors[0].message


def test_empty_payload_yields_no_observations_and_no_errors():
    runner = FakePowerShell([("Win32_Process", None)])
    result = COLLECTOR.collect(make_ctx(runner))
    assert result.observations == []
    assert result.errors == []
    assert result.stats["process_count"] == 0
