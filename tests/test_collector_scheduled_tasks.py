"""Tests for the scheduled_tasks collector (scheduled_task_state observations)."""

from datetime import datetime, timezone

import pytest

from helpers import FakePowerShell
from wtfserver.collectors.base import CollectionContext
from wtfserver.collectors.windows.powershell import PowerShellError
from wtfserver.collectors.windows.scheduled_tasks import (
    _TASKS_SCRIPT,
    COLLECTOR,
    parse_duration_seconds,
)
from wtfserver.model import Category

SCRIPT_KEY = "Get-ScheduledTask"


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


NIGHTLY_TASK = {
    "TaskPath": "\\Vendor\\",
    "TaskName": "NightlyExport",
    "State": "Ready",
    "Principal": "CORP\\svc_batch",
    "Enabled": True,
    "Hidden": False,
    "Actions": [{"Execute": "C:\\Vendor\\export.exe", "Arguments": "/full"}],
    "Triggers": [
        {
            "Class": "MSFT_TaskDailyTrigger",
            "StartBoundary": "2024-01-01T03:00:00",
            "RepetitionInterval": None,
        }
    ],
    "LastRunTime": "2026-08-18T03:00:05.1234567Z",
    "NextRunTime": "2026-08-19T03:00:00.0000000Z",
    "LastTaskResult": 0,
    "NumberOfMissedRuns": 0,
}


def test_normalizes_full_task():
    ctx, raw = make_ctx(FakePowerShell([(SCRIPT_KEY, [NIGHTLY_TASK])]))
    result = COLLECTOR.collect(ctx)

    assert not result.errors
    assert len(result.observations) == 1
    obs = result.observations[0]
    assert obs.category == Category.SCHEDULED_TASK_STATE
    assert obs.source == "scheduled_tasks"
    assert obs.action == "configured"
    assert obs.timestamp == "2026-08-19T12:00:00Z"
    assert obs.scheduled_action == "\\Vendor\\NightlyExport"
    assert obs.principal == "CORP\\svc_batch"
    assert obs.process == "C:\\Vendor\\export.exe"
    assert obs.attributes["enabled"] is True
    assert obs.attributes["state"] == "Ready"
    assert obs.attributes["actions"] == [
        {"execute": "C:\\Vendor\\export.exe", "arguments": "/full"}
    ]
    assert obs.attributes["triggers"] == [
        {"type": "daily", "start": "2024-01-01T03:00:00", "interval": None}
    ]
    assert obs.attributes["last_run"] == "2026-08-18T03:00:05Z"
    assert obs.attributes["next_run"] == "2026-08-19T03:00:00Z"
    assert obs.attributes["last_result"] == 0
    assert obs.attributes["missed_runs"] == 0
    assert obs.attributes["hidden"] is False
    assert obs.raw_reference == "raw/scheduled_tasks.json#0"
    assert "scheduled_tasks.json" in raw


def test_trigger_type_mapping():
    task = dict(
        NIGHTLY_TASK,
        Triggers=[
            # Class mapping wins over repetition-interval fallback.
            {
                "Class": "MSFT_TaskTimeTrigger",
                "StartBoundary": "2024-01-01T08:00:00",
                "RepetitionInterval": "PT15M",
            },
            {"Class": "MSFT_TaskBootTrigger", "StartBoundary": None, "RepetitionInterval": None},
            {"Class": "MSFT_TaskLogonTrigger", "StartBoundary": None, "RepetitionInterval": None},
            # Unknown class with repetition interval -> interval.
            {
                "Class": "MSFT_TaskSessionStateChangeTrigger",
                "StartBoundary": None,
                "RepetitionInterval": "PT1H",
            },
            # Unknown class, no interval -> other.
            {"Class": "MSFT_TaskIdleTrigger", "StartBoundary": None, "RepetitionInterval": None},
            # Unmapped class + unparseable duration: still "interval" (presence
            # decides the type), raw string kept as the interval value.
            {"Class": "MSFT_TaskWeeklyTrigger", "StartBoundary": None, "RepetitionInterval": "P1W"},
        ],
    )
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)
    triggers = result.observations[0].attributes["triggers"]
    assert [t["type"] for t in triggers] == [
        "time",
        "boot",
        "logon",
        "interval",
        "other",
        "interval",
    ]
    assert triggers[0]["interval"] == 900
    assert triggers[3]["interval"] == 3600
    assert triggers[5]["interval"] == "P1W"


def test_never_ran_year_1899_becomes_null():
    task = dict(
        NIGHTLY_TASK,
        LastRunTime="1899-12-30T00:00:00.0000000Z",
        NextRunTime=None,
        LastTaskResult=267011,
    )
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)
    obs = result.observations[0]
    assert obs.attributes["last_run"] is None
    assert obs.attributes["next_run"] is None
    assert obs.attributes["last_result"] == 267011


def test_null_last_run_stays_null():
    task = dict(NIGHTLY_TASK, LastRunTime=None)
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)
    assert result.observations[0].attributes["last_run"] is None


def test_quoted_execute_stripped_for_process_but_raw_in_actions():
    task = dict(
        NIGHTLY_TASK,
        Actions=[{"Execute": '"C:\\Program Files\\App\\job.exe"', "Arguments": None}],
    )
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)
    obs = result.observations[0]
    assert obs.process == "C:\\Program Files\\App\\job.exe"
    assert obs.attributes["actions"][0]["execute"] == '"C:\\Program Files\\App\\job.exe"'


def test_no_actions_means_null_process():
    task = dict(NIGHTLY_TASK, Actions=[])
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)
    obs = result.observations[0]
    assert obs.process is None
    assert obs.attributes["actions"] == []


def test_single_object_payload_is_handled():
    # ConvertTo-Json collapses one-element arrays to a bare object.
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, NIGHTLY_TASK)]))
    result = COLLECTOR.collect(ctx)
    assert not result.errors
    assert len(result.observations) == 1


def test_single_action_and_trigger_collapsed_to_objects():
    # Nested one-element arrays can also arrive as bare objects.
    task = dict(
        NIGHTLY_TASK,
        Actions={"Execute": "C:\\Vendor\\export.exe", "Arguments": None},
        Triggers={
            "Class": "MSFT_TaskDailyTrigger",
            "StartBoundary": "2024-01-01T03:00:00",
            "RepetitionInterval": None,
        },
    )
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)
    obs = result.observations[0]
    assert obs.process == "C:\\Vendor\\export.exe"
    assert obs.attributes["triggers"][0]["type"] == "daily"


def test_phantom_all_null_triggers_and_actions_dropped():
    # In PowerShell, $null | ForEach-Object runs the block once, so the old
    # script emitted one all-null trigger/action for on-demand tasks (whose
    # Triggers/Actions CIM properties are $null). Such rows must normalize to
    # empty lists, never a phantom {"type": "other", ...} entry.
    task = dict(
        NIGHTLY_TASK,
        Actions=[{"Execute": None, "Arguments": None}],
        Triggers=[{"Class": None, "StartBoundary": None, "RepetitionInterval": None}],
    )
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)

    assert not result.errors
    obs = result.observations[0]
    assert obs.attributes["actions"] == []
    assert obs.attributes["triggers"] == []
    assert obs.process is None


def test_phantom_all_null_collapsed_bare_objects_dropped():
    # Same phantom shape, but collapsed by ConvertTo-Json to bare objects.
    task = dict(
        NIGHTLY_TASK,
        Actions={"Execute": None, "Arguments": None},
        Triggers={"Class": None, "StartBoundary": None, "RepetitionInterval": None},
    )
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)
    obs = result.observations[0]
    assert obs.attributes["actions"] == []
    assert obs.attributes["triggers"] == []


def test_partially_null_triggers_and_actions_are_kept():
    # The all-null filter must NOT drop entries that carry any information:
    # a boot trigger legitimately has null StartBoundary/RepetitionInterval,
    # and an action may have an Execute with null Arguments.
    task = dict(
        NIGHTLY_TASK,
        Actions=[{"Execute": "C:\\Vendor\\export.exe", "Arguments": None}],
        Triggers=[
            {"Class": "MSFT_TaskBootTrigger", "StartBoundary": None, "RepetitionInterval": None}
        ],
    )
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)
    obs = result.observations[0]
    assert obs.attributes["actions"] == [
        {"execute": "C:\\Vendor\\export.exe", "arguments": None}
    ]
    assert obs.attributes["triggers"] == [{"type": "boot", "start": None, "interval": None}]
    assert obs.process == "C:\\Vendor\\export.exe"


def test_script_filters_null_before_projecting_triggers_and_actions():
    # $null piped through ForEach-Object runs the block once; the script must
    # filter nulls out BEFORE projecting, for both Triggers and Actions.
    null_filter = "Where-Object { $null -ne $_ } | ForEach-Object"
    assert f"$t.Actions | {null_filter}" in _TASKS_SCRIPT
    assert f"$t.Triggers | {null_filter}" in _TASKS_SCRIPT


def test_empty_payload_yields_no_observations():
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [])]))
    result = COLLECTOR.collect(ctx)
    assert result.observations == []
    assert result.errors == []


def test_disabled_state_without_enabled_field():
    task = {"TaskPath": "\\", "TaskName": "OldJob", "State": "Disabled"}
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)
    obs = result.observations[0]
    assert obs.attributes["enabled"] is False
    assert obs.scheduled_action == "\\OldJob"


def test_missing_optional_fields_tolerated():
    task = {"TaskPath": "\\Micro\\", "TaskName": "Bare"}
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, [task])]))
    result = COLLECTOR.collect(ctx)
    assert not result.errors
    obs = result.observations[0]
    assert obs.scheduled_action == "\\Micro\\Bare"
    assert obs.principal is None
    assert obs.process is None
    assert obs.attributes["enabled"] is True  # tasks default to enabled
    assert obs.attributes["state"] is None
    assert obs.attributes["actions"] == []
    assert obs.attributes["triggers"] == []
    assert obs.attributes["last_run"] is None
    assert obs.attributes["next_run"] is None
    assert obs.attributes["last_result"] is None
    assert obs.attributes["missed_runs"] is None
    assert obs.attributes["hidden"] is None


def test_missing_task_name_is_error_but_others_survive():
    payload = [{"TaskPath": "\\Vendor\\"}, NIGHTLY_TASK]
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, payload)]))
    result = COLLECTOR.collect(ctx)
    assert len(result.observations) == 1
    assert result.observations[0].raw_reference == "raw/scheduled_tasks.json#1"
    assert len(result.errors) == 1
    assert not result.errors[0].fatal


def test_runner_exception_becomes_fatal_collector_error():
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, PowerShellError("task service down"))]))
    result = COLLECTOR.collect(ctx)
    assert result.observations == []
    assert len(result.errors) == 1
    assert result.errors[0].fatal


def test_malformed_payload_type_is_fatal_error():
    ctx, _ = make_ctx(FakePowerShell([(SCRIPT_KEY, 42)]))
    result = COLLECTOR.collect(ctx)
    assert result.observations == []
    assert len(result.errors) == 1
    assert result.errors[0].fatal


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("PT15M", 900),
        ("PT1H", 3600),
        ("PT90S", 90),
        ("PT5M30S", 330),
        ("P1DT2H", 93600),
        ("P2D", 172800),
        ("P1W", None),  # week durations not handled; raw string is kept upstream
        ("garbage", None),
        ("", None),
        (None, None),
        ("P", None),
    ],
)
def test_parse_duration_seconds(value, expected):
    assert parse_duration_seconds(value) == expected
