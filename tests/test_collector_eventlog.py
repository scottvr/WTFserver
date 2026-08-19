"""Tests for the Windows event log collector (Python side, via FakePowerShell)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from helpers import FakePowerShell

from wtfserver.collectors.base import CollectionContext
from wtfserver.collectors.windows.eventlog import COLLECTOR, EventLogCollector

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)
SINCE = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)

TASKS_CH = "Microsoft-Windows-TaskScheduler/Operational"
TSLSM_CH = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"


def make_ctx(responses, since=None, options=None):
    fake = FakePowerShell(responses)
    raws: dict[str, str] = {}

    def add_raw(name: str, content: Any) -> str:
        ref = f"raw/{name}"
        raws[ref] = content
        return ref

    ctx = CollectionContext(
        since=since, now=NOW, runner=fake, add_raw=add_raw, options=options or {}
    )
    return ctx, fake, raws


def chan(name, enabled=True, record_count=10, max_size_bytes=1048576):
    return {
        "name": name,
        "enabled": enabled,
        "record_count": record_count,
        "max_size_bytes": max_size_bytes,
    }


def ev(t, event_id, provider, channel, props=(), level="Information", msg=None, record_id=1):
    return {
        "t": t,
        "id": event_id,
        "provider": provider,
        "channel": channel,
        "level": level,
        "record_id": record_id,
        "props": list(props),
        "msg": msg,
    }


def one_channel(channel, rows, record_count=None):
    """Canned responses for a single healthy channel."""
    rc = record_count if record_count is not None else max(len(rows), 1)
    return [
        ("-ListLog *", [chan(channel, record_count=rc)]),
        (f"-LogName '{channel}' -MaxEvents 1 -Oldest", {"t": "2026-08-01T00:00:00.0000000Z"}),
        (f"-LogName '{channel}' -MaxEvents 1", {"t": "2026-08-19T10:00:00.0000000Z"}),
        (f"@{{LogName='{channel}'", rows),
    ]


def collect(responses, since=None, options=None):
    ctx, fake, raws = make_ctx(responses, since=since, options=options)
    result = COLLECTOR.collect(ctx)
    return result, fake, raws


def events_of(result, category):
    return [o for o in result.observations if o.category == category]


def sec_4624_props(user="alice", domain="CORP", logon_type="2", ip="10.0.0.5",
                   process="C:\\Windows\\System32\\winlogon.exe"):
    props = [""] * 20
    props[5] = user
    props[6] = domain
    props[8] = logon_type
    props[17] = process
    props[18] = ip
    return props


def test_module_exports():
    assert isinstance(COLLECTOR, EventLogCollector)
    assert COLLECTOR.name == "eventlog"
    assert COLLECTOR.platforms == ("windows",)


def test_4624_logon_kinds_and_remote_host_filtering():
    rows = [
        ev("2026-08-18T09:00:00.0000000Z", 4624, "Microsoft-Windows-Security-Auditing",
           "Security", sec_4624_props(logon_type="2", ip="-")),
        ev("2026-08-18T09:01:00.0000000Z", 4624, "Microsoft-Windows-Security-Auditing",
           "Security", sec_4624_props(logon_type="10", ip="10.1.2.3")),
        ev("2026-08-18T09:02:00.0000000Z", 4624, "Microsoft-Windows-Security-Auditing",
           "Security", sec_4624_props(logon_type="3", ip="127.0.0.1")),
        ev("2026-08-18T09:03:00.0000000Z", 4624, "Microsoft-Windows-Security-Auditing",
           "Security", sec_4624_props(logon_type="9", ip="::1")),
    ]
    result, _, _ = collect(one_channel("Security", rows))
    logons = events_of(result, "logon")
    assert len(logons) == 4
    interactive, remote, network, other = logons

    assert interactive.action == "logon"
    assert interactive.principal == "CORP\\alice"
    assert interactive.attributes["logon_kind"] == "interactive"
    assert interactive.attributes["logon_type"] == 2
    assert interactive.remote_host is None  # '-' filtered
    assert interactive.process == "C:\\Windows\\System32\\winlogon.exe"
    assert interactive.timestamp == "2026-08-18T09:00:00Z"
    assert interactive.attributes["channel"] == "Security"
    assert interactive.attributes["provider"] == "Microsoft-Windows-Security-Auditing"
    assert interactive.attributes["event_id"] == 4624
    assert interactive.attributes["level"] == "Information"
    assert interactive.raw_reference == "raw/events_Security.jsonl"

    assert remote.attributes["logon_kind"] == "remote_interactive"
    assert remote.remote_host == "10.1.2.3"

    assert network.attributes["logon_kind"] == "network"
    assert network.remote_host is None  # loopback filtered

    assert other.attributes["logon_kind"] == "other"
    assert other.remote_host is None  # ::1 filtered


def test_4625_4634_normalization():
    p4625 = [""] * 20
    p4625[5] = "bob"
    p4625[6] = "CORP"
    p4625[10] = "3"
    p4625[19] = "10.9.9.9"
    p4634 = ["S-1-5-21-1", "alice", "CORP", "0x3e7", "2"]
    rows = [
        ev("2026-08-18T10:00:00.0000000Z", 4625, "Microsoft-Windows-Security-Auditing",
           "Security", p4625),
        ev("2026-08-18T11:00:00.0000000Z", 4634, "Microsoft-Windows-Security-Auditing",
           "Security", p4634),
    ]
    result, _, _ = collect(one_channel("Security", rows))
    failed, logoff = events_of(result, "logon")
    assert failed.action == "logon_failed"
    assert failed.principal == "CORP\\bob"
    assert failed.attributes["logon_type"] == 3
    assert failed.remote_host == "10.9.9.9"
    assert logoff.action == "logoff"
    assert logoff.principal == "CORP\\alice"
    assert logoff.attributes["logon_type"] == 2


def test_4688_process_start():
    props = [""] * 14
    props[1] = "svc_batch"
    props[2] = "CORP"
    props[5] = "C:\\App\\export.exe"
    props[8] = '"C:\\App\\export.exe" /nightly'
    props[13] = "C:\\Windows\\System32\\svchost.exe"
    rows = [
        ev("2026-08-18T01:00:00.0000000Z", 4688, "Microsoft-Windows-Security-Auditing",
           "Security", props),
    ]
    result, _, _ = collect(one_channel("Security", rows))
    (proc,) = events_of(result, "process_activity")
    assert proc.action == "start"
    assert proc.process == "C:\\App\\export.exe"
    assert proc.principal == "CORP\\svc_batch"
    assert proc.attributes["command_line"] == '"C:\\App\\export.exe" /nightly'
    assert proc.attributes["parent_process"] == "C:\\Windows\\System32\\svchost.exe"
    assert proc.attributes["event_id"] == 4688


def test_4688_missing_optional_props():
    # Pre-2016 shape: no command line, no parent process captured.
    props = [""] * 7
    props[1] = "svc_batch"
    props[2] = "CORP"
    props[5] = "C:\\App\\export.exe"
    rows = [
        ev("2026-08-18T01:00:00.0000000Z", 4688, "Microsoft-Windows-Security-Auditing",
           "Security", props),
    ]
    result, _, _ = collect(one_channel("Security", rows))
    (proc,) = events_of(result, "process_activity")
    assert proc.process == "C:\\App\\export.exe"
    assert proc.attributes["command_line"] is None
    assert proc.attributes["parent_process"] is None


def test_7036_running_stopped_and_localized():
    rows = [
        ev("2026-08-18T02:00:00.0000000Z", 7036, "Service Control Manager", "System",
           ["Print Spooler", "running"]),
        ev("2026-08-18T02:01:00.0000000Z", 7036, "Service Control Manager", "System",
           ["Print Spooler", "stopped"]),
        ev("2026-08-18T02:02:00.0000000Z", 7036, "Service Control Manager", "System",
           ["Druckwarteschlange", "wird ausgef\u00fchrt"]),
        ev("2026-08-18T02:03:00.0000000Z", 7045, "Service Control Manager", "System",
           ["VendorAgent", "C:\\Vendor\\agent.exe", "user mode service", "auto start", "LocalSystem"]),
    ]
    result, _, _ = collect(one_channel("System", rows))
    svc = events_of(result, "service_activity")
    assert [o.action for o in svc] == ["start", "stop", "state_change", "installed"]
    assert svc[0].service == "Print Spooler"
    assert svc[0].attributes["state"] == "running"
    assert svc[2].service == "Druckwarteschlange"
    # Localized state text is preserved raw; action stays state_change.
    assert svc[2].attributes["state"] == "wird ausgef\u00fchrt"
    assert svc[3].service == "VendorAgent"
    assert svc[3].attributes["state"] is None


def test_system_lifecycle():
    rows = [
        ev("2026-08-18T03:00:00.0000000Z", 6005, "EventLog", "System"),
        ev("2026-08-18T03:01:00.0000000Z", 6006, "EventLog", "System"),
        ev("2026-08-18T03:02:00.0000000Z", 6008, "EventLog", "System"),
    ]
    result, _, _ = collect(one_channel("System", rows))
    life = events_of(result, "system_lifecycle")
    assert [o.action for o in life] == ["boot", "shutdown", "unexpected_shutdown"]


def test_taskscheduler_100_and_201():
    rows = [
        ev("2026-08-18T01:00:00.0000000Z", 100, "Microsoft-Windows-TaskScheduler",
           TASKS_CH, ["\\Vendor\\NightlyExport", "CORP\\svc_batch", "{guid-1}"]),
        ev("2026-08-18T01:00:05.0000000Z", 200, "Microsoft-Windows-TaskScheduler",
           TASKS_CH, ["\\Vendor\\NightlyExport", "C:\\App\\export.exe", "{guid-1}", "512"]),
        ev("2026-08-18T01:04:00.0000000Z", 201, "Microsoft-Windows-TaskScheduler",
           TASKS_CH, ["\\Vendor\\NightlyExport", "{guid-1}", "C:\\App\\export.exe", "0"]),
    ]
    result, _, _ = collect(one_channel(TASKS_CH, rows))
    sched = events_of(result, "scheduled_activity")
    start, action_start, action_complete = sched
    assert start.action == "start"
    assert start.scheduled_action == "\\Vendor\\NightlyExport"
    assert start.principal == "CORP\\svc_batch"
    assert start.attributes["result_code"] is None
    assert action_start.action == "action_start"
    assert action_start.process == "C:\\App\\export.exe"
    assert action_complete.action == "action_complete"
    assert action_complete.process == "C:\\App\\export.exe"
    assert action_complete.attributes["result_code"] == 0
    assert action_complete.raw_reference == (
        "raw/events_Microsoft-Windows-TaskScheduler_Operational.jsonl"
    )


def test_tslsm_21_remote_logon():
    rows = [
        ev("2026-08-18T08:00:00.0000000Z", 21, "Microsoft-Windows-TerminalServices-LocalSessionManager",
           TSLSM_CH, ["CORP\\admin", "2", "192.0.2.10"]),
        ev("2026-08-18T08:05:00.0000000Z", 21, "Microsoft-Windows-TerminalServices-LocalSessionManager",
           TSLSM_CH, ["CORP\\admin", "3", "LOCAL"]),
        ev("2026-08-18T08:10:00.0000000Z", 24, "Microsoft-Windows-TerminalServices-LocalSessionManager",
           TSLSM_CH, ["CORP\\admin", "2"]),
    ]
    result, _, _ = collect(one_channel(TSLSM_CH, rows))
    logons = events_of(result, "logon")
    assert len(logons) == 2
    assert logons[0].action == "logon"
    assert logons[0].principal == "CORP\\admin"
    assert logons[0].attributes["logon_kind"] == "remote_interactive"
    assert logons[0].remote_host == "192.0.2.10"
    assert logons[1].remote_host is None  # "LOCAL" filtered
    # 24 stays a generic event with a disconnect note.
    (generic,) = events_of(result, "event")
    assert generic.attributes["event_id"] == 24
    assert generic.message is not None and "disconnect" in generic.message.lower()


def test_unmapped_event_fallback():
    rows = [
        ev("2026-08-18T04:00:00.0000000Z", 1000, "MyVendorApp", "Application",
           ["p0"], level="Error", msg="x" * 400),
    ]
    result, _, _ = collect(one_channel("Application", rows))
    (generic,) = events_of(result, "event")
    assert generic.action is None
    assert generic.message == "x" * 300  # defensive client-side truncation
    assert generic.attributes == {
        "channel": "Application",
        "provider": "MyVendorApp",
        "event_id": 1000,
        "level": "Error",
    }


def test_disabled_and_empty_channels_still_inventoried():
    responses = [
        ("-ListLog *", [
            chan("Security", enabled=False, record_count=100),
            chan("EmptyLog", enabled=True, record_count=0, max_size_bytes=None),
        ]),
        # Disabled-but-populated channels still get edge queries for coverage.
        ("-LogName 'Security' -MaxEvents 1 -Oldest", {"t": "2026-07-01T00:00:00.0000000Z"}),
        ("-LogName 'Security' -MaxEvents 1", {"t": "2026-08-10T00:00:00.0000000Z"}),
    ]
    result, fake, _ = collect(responses)
    chans = events_of(result, "evidence_channel")
    assert len(chans) == 2
    assert len(result.observations) == 2  # nothing but inventory
    empty, security = chans  # sorted by channel name
    assert security.attributes["channel"] == "Security"
    assert security.attributes["enabled"] is False
    assert security.attributes["record_count"] == 100
    assert security.attributes["oldest_record"] == "2026-07-01T00:00:00Z"
    assert security.attributes["newest_record"] == "2026-08-10T00:00:00Z"
    assert security.attributes["collected_events"] == 0
    assert security.attributes["truncated"] is False
    assert "error" not in security.attributes
    assert empty.attributes["channel"] == "EmptyLog"
    assert empty.attributes["record_count"] == 0
    assert empty.attributes["oldest_record"] is None
    assert empty.attributes["max_size_bytes"] is None
    assert empty.action == "inventoried"
    assert empty.timestamp == "2026-08-19T12:00:00Z"
    # No history read was attempted from either channel.
    assert not any("FilterHashtable" in c for c in fake.calls)
    assert result.errors == []


def test_channel_read_failure_yields_error_not_exception():
    responses = [
        ("-ListLog *", [chan("Bad", record_count=5), chan("Good", record_count=1)]),
        ("-LogName 'Bad' -MaxEvents 1 -Oldest", {"t": "2026-08-01T00:00:00.0000000Z"}),
        ("-LogName 'Bad' -MaxEvents 1", {"t": "2026-08-18T00:00:00.0000000Z"}),
        ("@{LogName='Bad'", RuntimeError("Attempted to perform an unauthorized operation.")),
        ("-LogName 'Good' -MaxEvents 1 -Oldest", {"t": "2026-08-01T00:00:00.0000000Z"}),
        ("-LogName 'Good' -MaxEvents 1", {"t": "2026-08-18T00:00:00.0000000Z"}),
        ("@{LogName='Good'", [
            ev("2026-08-18T04:00:00.0000000Z", 42, "GoodApp", "Good"),
        ]),
    ]
    result, _, _ = collect(responses)
    bad, good = events_of(result, "evidence_channel")
    assert bad.attributes["channel"] == "Bad"
    assert "unauthorized" in bad.attributes["error"]
    assert bad.attributes["collected_events"] == 0
    assert good.attributes["channel"] == "Good"
    assert "error" not in good.attributes
    assert good.attributes["collected_events"] == 1
    assert len(events_of(result, "event")) == 1  # Good still collected
    assert len(result.errors) == 1
    assert result.errors[0].fatal is False
    assert "Bad" in result.errors[0].message


def test_malformed_event_rows_skipped_and_counted():
    rows = [
        "not an object",
        {"provider": "X", "channel": "Security"},  # missing t and id
        ev("not-a-timestamp", 4624, "X", "Security", sec_4624_props()),
        ev("2026-08-18T09:00:00.0000000Z", 4624,
           "Microsoft-Windows-Security-Auditing", "Security", sec_4624_props()),
    ]
    result, _, _ = collect(one_channel("Security", rows))
    assert len(events_of(result, "logon")) == 1
    (chan_obs,) = events_of(result, "evidence_channel")
    assert chan_obs.attributes["collected_events"] == 1
    assert result.stats["malformed_rows"] == 3
    assert result.errors == []


def test_truncation_flag_and_cap_in_script():
    rows = [
        ev("2026-08-18T04:00:00.0000000Z", 42, "App", "Application"),
        ev("2026-08-18T03:00:00.0000000Z", 42, "App", "Application"),
    ]
    result, fake, _ = collect(
        one_channel("Application", rows, record_count=1000),
        options={"max_events_per_channel": 2},
    )
    (chan_obs,) = events_of(result, "evidence_channel")
    assert chan_obs.attributes["truncated"] is True
    assert chan_obs.attributes["collected_events"] == 2
    assert any("-MaxEvents 2 " in c and "FilterHashtable" in c for c in fake.calls)

    # Counterexample: cap not reached -> not truncated.
    result2, _, _ = collect(
        one_channel("Application", rows[:1], record_count=1000),
        options={"max_events_per_channel": 2},
    )
    (chan_obs2,) = events_of(result2, "evidence_channel")
    assert chan_obs2.attributes["truncated"] is False


def test_since_filtering_client_side_and_in_script():
    rows = [
        ev("2026-08-17T00:00:00.0000000Z", 42, "App", "Application"),
        ev("2026-08-15T00:00:00.0000000Z", 42, "App", "Application"),  # older than since
    ]
    result, fake, _ = collect(one_channel("Application", rows), since=SINCE)
    generics = events_of(result, "event")
    assert len(generics) == 1
    assert generics[0].timestamp == "2026-08-17T00:00:00Z"
    assert result.stats["skipped_old"] == 1
    (chan_obs,) = events_of(result, "evidence_channel")
    assert chan_obs.attributes["collected_events"] == 1
    events_call = next(c for c in fake.calls if "FilterHashtable" in c)
    assert "StartTime" in events_call
    assert "2026-08-16T12:00:00Z" in events_call


def test_since_none_means_max_history():
    rows = [ev("2020-01-01T00:00:00.0000000Z", 42, "App", "Application")]
    result, fake, _ = collect(one_channel("Application", rows), since=None)
    assert len(events_of(result, "event")) == 1  # ancient event kept
    events_call = next(c for c in fake.calls if "FilterHashtable" in c)
    assert "StartTime" not in events_call


def test_channel_enumeration_failure_is_fatal():
    responses = [("-ListLog *", RuntimeError("Get-WinEvent unavailable"))]
    result, _, _ = collect(responses)
    assert result.observations == []
    assert len(result.errors) == 1
    assert result.errors[0].fatal is True


def test_edge_query_failure_tolerated():
    responses = [
        ("-ListLog *", [chan("Application", record_count=1)]),
        ("-LogName 'Application' -MaxEvents 1 -Oldest", RuntimeError("boom")),
        ("-LogName 'Application' -MaxEvents 1", {"t": "2026-08-18T00:00:00.0000000Z"}),
        ("@{LogName='Application'", [
            ev("2026-08-18T04:00:00.0000000Z", 42, "App", "Application"),
        ]),
    ]
    result, _, _ = collect(responses)
    (chan_obs,) = events_of(result, "evidence_channel")
    assert chan_obs.attributes["oldest_record"] is None
    assert chan_obs.attributes["newest_record"] == "2026-08-18T00:00:00Z"
    assert chan_obs.attributes["collected_events"] == 1
    assert "error" not in chan_obs.attributes
    assert result.errors == []


def test_raw_files_written():
    rows = [ev("2026-08-18T04:00:00.0000000Z", 42, "App", "Application")]
    result, _, raws = collect(one_channel("Application", rows))
    assert "raw/eventlog_channels.jsonl" in raws
    assert "raw/events_Application.jsonl" in raws
    lines = [l for l in raws["raw/events_Application.jsonl"].splitlines() if l]
    assert len(lines) == 1
    assert '"id": 42' in lines[0]
    (chan_obs,) = events_of(result, "evidence_channel")
    assert chan_obs.raw_reference == "raw/events_Application.jsonl"


def test_evidence_channel_attribute_keys_exact():
    rows = [ev("2026-08-18T04:00:00.0000000Z", 42, "App", "Application")]
    result, _, _ = collect(one_channel("Application", rows))
    (chan_obs,) = events_of(result, "evidence_channel")
    assert set(chan_obs.attributes.keys()) == {
        "channel", "enabled", "record_count", "oldest_record", "newest_record",
        "max_size_bytes", "collected_events", "truncated",
    }
    assert chan_obs.source == "eventlog"
    assert chan_obs.action == "inventoried"
