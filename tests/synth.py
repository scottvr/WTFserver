"""Deterministic synthetic-bundle builders for the validation experiment.

Three archetype bundles (docs/WTFServer_First_Build.md section 17):

    batch01  known batch/integration server (nightly vendor export)
    web01    known web/application server (IIS + database client)
    idle01   known mostly-idle administration box

Each ``build_<name>()`` returns ``(manifest, observations)`` with a FIXED
base time (never the wall clock), sequential observation ids
(``obs-000001``...), and realistic Windows-shaped values in the normalized
observation model. All three bundles carry the stock Microsoft maintenance
scheduled task recurrences (every real Windows server has them) so analyzer
rules are exercised against realistic clutter, plus generic ``event`` noise.

``write_directory_bundle`` writes a bundle as a plain directory
(manifest.json + observations.jsonl), which ``wtfserver.bundle.Bundle.load``
accepts alongside .wtf zips. Run this module directly to materialize the
bundles for manual inspection:

    python tests/synth.py <output-dir>
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from wtfserver.model import Category, Observation, to_iso

_UTC = timezone.utc

# Windows-shaped constants shared by all three archetypes.
_SEC_CHANNEL = "Security"
_SEC_PROVIDER = "Microsoft-Windows-Security-Auditing"
_RAW_SEC = "raw/events_Security.jsonl"
_TS_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"
_TS_PROVIDER = "Microsoft-Windows-TaskScheduler"
_RAW_TS = "raw/events_Microsoft-Windows-TaskScheduler_Operational.jsonl"
_LSM_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
_LSM_PROVIDER = "Microsoft-Windows-TerminalServices-LocalSessionManager"
_RAW_LSM = (
    "raw/events_Microsoft-Windows-TerminalServices-LocalSessionManager_Operational.jsonl"
)

DEFENDER_TASK = "\\Microsoft\\Windows\\Windows Defender\\Scheduled Scan"
DEFENDER_EXE = "C:\\Program Files\\Windows Defender\\MpCmdRun.exe"
DEFRAG_TASK = "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"

VENDOR_TASK = "\\Vendor\\NightlyExport"
VENDOR_EXE = "D:\\Vendor\\export.exe"
BATCH01_DB_IP = "10.20.30.40"
BATCH01_SFTP_HOST = "sftp.vendor.example"
WEB01_DB_IP = "10.20.30.41"


class _Builder:
    """Accumulates observations with sequential ids, like BundleWriter does."""

    def __init__(self) -> None:
        self._obs: list[Observation] = []

    def add(self, category: str, source: str, **fields: Any) -> Observation:
        obs = Observation(
            id=f"obs-{len(self._obs) + 1:06d}",
            source=source,
            category=category,
            **fields,
        )
        self._obs.append(obs)
        return obs

    def observations(self) -> list[Observation]:
        return list(self._obs)


def _event_attrs(
    channel: str, provider: str, event_id: int, level: str = "Information", **extra: Any
) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "channel": channel,
        "provider": provider,
        "event_id": event_id,
        "level": level,
    }
    attrs.update(extra)
    return attrs


def _add_channel(
    b: _Builder,
    ts: str,
    channel: str,
    enabled: bool,
    record_count: int,
    oldest: str | None,
    newest: str | None,
    collected: int,
    truncated: bool = False,
    max_size: int = 20971520,
) -> None:
    b.add(
        Category.EVIDENCE_CHANNEL,
        "eventlog",
        timestamp=ts,
        action="inventoried",
        attributes={
            "channel": channel,
            "enabled": enabled,
            "record_count": record_count,
            "oldest_record": oldest,
            "newest_record": newest,
            "max_size_bytes": max_size,
            "collected_events": collected,
            "truncated": truncated,
        },
    )


def _add_rdp_session(
    b: _Builder,
    logon_dt: datetime,
    principal: str,
    source_ip: str,
    logoff_dt: datetime,
) -> None:
    """One physical RDP session recorded by TWO evidence sources.

    The Security audit log (4624 type 10) and the TerminalServices session
    manager log (event 21) both record the same logon, two seconds apart and
    with different principal casing. The interactive analyzer's counting rule
    must deduplicate these into ONE remote-interactive logon.
    """
    b.add(
        Category.LOGON,
        "eventlog",
        timestamp=to_iso(logon_dt),
        action="logon",
        principal=principal,
        remote_host=source_ip,
        attributes=_event_attrs(
            _SEC_CHANNEL, _SEC_PROVIDER, 4624,
            logon_kind="remote_interactive", logon_type=10,
        ),
        raw_reference=_RAW_SEC,
    )
    b.add(
        Category.LOGON,
        "eventlog",
        timestamp=to_iso(logon_dt + timedelta(seconds=2)),
        action="logon",
        principal=principal.lower(),  # session manager reports its own casing
        remote_host=source_ip,
        attributes=_event_attrs(
            _LSM_CHANNEL, _LSM_PROVIDER, 21,
            logon_kind="remote_interactive", logon_type=None,
        ),
        raw_reference=_RAW_LSM,
        message="Remote Desktop Services: Session logon succeeded.",
    )
    b.add(
        Category.LOGON,
        "eventlog",
        timestamp=to_iso(logoff_dt),
        action="logoff",
        principal=principal,
        attributes=_event_attrs(
            _SEC_CHANNEL, _SEC_PROVIDER, 4634,
            logon_kind="remote_interactive", logon_type=10,
        ),
        raw_reference=_RAW_SEC,
    )


def _add_defender_scan_run(b: _Builder, start_dt: datetime) -> None:
    """One stock Microsoft maintenance run: Defender scheduled scan."""
    b.add(
        Category.SCHEDULED_ACTIVITY,
        "eventlog",
        timestamp=to_iso(start_dt),
        action="start",
        scheduled_action=DEFENDER_TASK,
        attributes=_event_attrs(_TS_CHANNEL, _TS_PROVIDER, 100),
        raw_reference=_RAW_TS,
    )
    b.add(
        Category.SCHEDULED_ACTIVITY,
        "eventlog",
        timestamp=to_iso(start_dt + timedelta(seconds=3)),
        action="action_start",
        scheduled_action=DEFENDER_TASK,
        process=DEFENDER_EXE,
        attributes=_event_attrs(_TS_CHANNEL, _TS_PROVIDER, 129),
        raw_reference=_RAW_TS,
    )
    b.add(
        Category.SCHEDULED_ACTIVITY,
        "eventlog",
        timestamp=to_iso(start_dt + timedelta(seconds=1140)),
        action="complete",
        scheduled_action=DEFENDER_TASK,
        attributes=_event_attrs(_TS_CHANNEL, _TS_PROVIDER, 102, result_code=0),
        raw_reference=_RAW_TS,
    )


def _add_noise_event(
    b: _Builder,
    ts: str,
    channel: str,
    provider: str,
    event_id: int,
    message: str,
    level: str = "Information",
) -> None:
    raw = f"raw/events_{channel.replace('/', '_').replace(chr(92), '_')}.jsonl"
    b.add(
        Category.EVENT,
        "eventlog",
        timestamp=ts,
        message=message,
        attributes=_event_attrs(channel, provider, event_id, level),
        raw_reference=raw,
    )


def _add_service(
    b: _Builder,
    ts: str,
    name: str,
    display: str,
    state: str,
    start_mode: str,
    principal: str = "LocalSystem",
    path: str | None = None,
    raw_path: str | None = None,
) -> None:
    b.add(
        Category.SERVICE_STATE,
        "services",
        timestamp=ts,
        action="configured",
        principal=principal,
        process=path,
        service=name,
        attributes={
            "display_name": display,
            "state": state,
            "start_mode": start_mode,
            "raw_path": raw_path or path,
        },
        raw_reference="raw/services.json",
    )


def _add_task_state(
    b: _Builder,
    ts: str,
    path: str,
    *,
    principal: str | None = None,
    execute: str | None = None,
    arguments: str | None = None,
    trigger: dict[str, Any] | None = None,
    last_run: str | None = None,
    next_run: str | None = None,
    last_result: int | None = None,
) -> None:
    b.add(
        Category.SCHEDULED_TASK_STATE,
        "scheduled_tasks",
        timestamp=ts,
        action="configured",
        principal=principal,
        process=execute,
        scheduled_action=path,
        attributes={
            "enabled": True,
            "state": "Ready",
            "actions": (
                [{"execute": execute, "arguments": arguments}] if execute else []
            ),
            "triggers": [trigger] if trigger else [],
            "last_run": last_run,
            "next_run": next_run,
            "last_result": last_result,
            "missed_runs": 0,
            "hidden": False,
        },
        raw_reference="raw/scheduled_tasks.json",
    )


def _add_process(
    b: _Builder,
    ts: str,
    path: str,
    pid: int,
    principal: str | None = None,
    parent_pid: int | None = None,
    command_line: str | None = None,
    start_time: str | None = None,
) -> None:
    b.add(
        Category.PROCESS_STATE,
        "processes",
        timestamp=ts,
        action="running",
        principal=principal,
        process=path,
        attributes={
            "pid": pid,
            "parent_pid": parent_pid,
            "command_line": command_line,
            "start_time": start_time,
        },
        raw_reference="raw/processes.json",
    )


def _add_listen(
    b: _Builder, ts: str, port: int, process: str, pid: int, local: str = "0.0.0.0"
) -> None:
    b.add(
        Category.SOCKET_STATE,
        "network",
        timestamp=ts,
        action="listening",
        process=process,
        attributes={
            "protocol": "tcp",
            "local_address": local,
            "local_port": port,
            "pid": pid,
            "state": "Listen",
        },
        raw_reference="raw/network.json",
    )


def _add_established(
    b: _Builder,
    ts: str,
    remote_host: str,
    remote_port: int,
    process: str,
    pid: int,
    local_ip: str,
    local_port: int,
) -> None:
    b.add(
        Category.SOCKET_STATE,
        "network",
        timestamp=ts,
        action="established",
        process=process,
        remote_host=remote_host,
        remote_port=remote_port,
        attributes={
            "protocol": "tcp",
            "local_address": local_ip,
            "local_port": local_port,
            "pid": pid,
            "state": "Established",
        },
        raw_reference="raw/network.json",
    )


def _add_identity(
    b: _Builder,
    ts: str,
    hostname: str,
    fqdn: str,
    os_name: str,
    os_version: str,
    addresses: list[str],
    last_boot: str,
) -> None:
    b.add(
        Category.HOST_IDENTITY,
        "host_identity",
        timestamp=ts,
        action="identity",
        attributes={
            "hostname": hostname,
            "fqdn": fqdn,
            "os_name": os_name,
            "os_version": os_version,
            "domain": "corp.example",
            "domain_role": "MemberServer",
            "interfaces": [{"name": "Ethernet0", "addresses": addresses}],
            "dns_servers": ["10.20.30.10"],
            "last_boot": last_boot,
        },
        raw_reference="raw/host_identity.json",
    )


def _add_role(b: _Builder, ts: str, name: str, display: str) -> None:
    b.add(
        Category.INSTALLED_ROLE,
        "software",
        timestamp=ts,
        action="installed",
        message=display,
        attributes={"name": name, "display_name": display},
        raw_reference="raw/roles.json",
    )


def _add_software(
    b: _Builder, ts: str, name: str, version: str, vendor: str, install_date: str | None
) -> None:
    b.add(
        Category.INSTALLED_SOFTWARE,
        "software",
        timestamp=ts,
        action="installed",
        message=name,
        attributes={
            "name": name,
            "version": version,
            "vendor": vendor,
            "install_date": install_date,
        },
        raw_reference="raw/software.json",
    )


def _manifest(
    hostname: str,
    collection_start: datetime,
    collection_end: datetime,
    requested_since: str,
    since_resolved: datetime,
    observations: list[Observation],
) -> dict[str, Any]:
    by_source = Counter(obs.source for obs in observations)
    return {
        "bundle_format": "wtf-bundle",
        "schema_version": 1,
        "tool": "wtfserver/whatami",
        "tool_version": "0.1.0",
        "hostname": hostname,
        "platform": "windows",
        "collection_start": to_iso(collection_start),
        "collection_end": to_iso(collection_end),
        "requested_since": requested_since,
        "since_resolved": to_iso(since_resolved),
        "collectors": [
            {
                "name": name,
                "status": "ok",
                "observations": by_source.get(name, 0),
                "errors": [],
            }
            for name in (
                "eventlog",
                "services",
                "scheduled_tasks",
                "processes",
                "network",
                "host_identity",
                "software",
            )
        ],
        "observation_count": len(observations),
    }


# ---------------------------------------------------------------------------
# batch01 — nightly integration host
# ---------------------------------------------------------------------------


def build_batch01() -> tuple[dict[str, Any], list[Observation]]:
    """Nightly integration server.

    \\Vendor\\NightlyExport runs daily at ~01:00 UTC (deterministic +/-44s
    jitter), 21 runs across 23 calendar days (two skipped nights). Each run:
    svc-account batch logon 1s before the task fires, action_start of
    D:\\Vendor\\export.exe, vendor Application-log events reaching db01
    (10.20.30.40:1433) then sftp.vendor.example:22, completion with result 0.
    A resident vendor agent still holds one DB socket at collection time
    (evidence "both" for the db peer). IIS is installed but dormant (W3SVC
    auto-start yet stopped, Web-Server role with no listener). Two admin RDP
    sessions are each recorded by BOTH the audit log and the session-manager
    log (dedupe must count 2, not 4).
    """
    collection_start = datetime(2026, 3, 24, 8, 0, 0, tzinfo=_UTC)
    collection_end = datetime(2026, 3, 24, 8, 5, 0, tzinfo=_UTC)
    since = datetime(2026, 2, 22, 8, 0, 0, tzinfo=_UTC)
    inv_ts = to_iso(datetime(2026, 3, 24, 8, 1, 0, tzinfo=_UTC))
    state_ts = to_iso(datetime(2026, 3, 24, 8, 2, 0, tzinfo=_UTC))

    b = _Builder()

    # Event log channel inventory with believable retention. TaskScheduler
    # retention starts inside the requested window (retention shortfall);
    # PowerShell/Operational is disabled, as on most stock servers.
    _add_channel(b, inv_ts, _SEC_CHANNEL, True, 48211,
                 "2026-02-21T03:12:44Z", "2026-03-24T07:58:01Z", 3120)
    _add_channel(b, inv_ts, "System", True, 19404,
                 "2026-01-05T09:30:12Z", "2026-03-24T07:55:40Z", 850)
    _add_channel(b, inv_ts, "Application", True, 12876,
                 "2026-02-02T18:04:59Z", "2026-03-24T07:41:22Z", 610)
    _add_channel(b, inv_ts, _TS_CHANNEL, True, 8112,
                 "2026-02-26T00:00:11Z", "2026-03-24T02:49:41Z", 460)
    _add_channel(b, inv_ts, _LSM_CHANNEL, True, 312,
                 "2025-10-14T07:22:10Z", "2026-03-18T10:02:33Z", 12)
    _add_channel(b, inv_ts, "Microsoft-Windows-PowerShell/Operational", False, 0,
                 None, None, 0)
    _add_channel(b, inv_ts, "Windows PowerShell", True, 220,
                 "2025-09-02T12:00:00Z", "2026-03-20T04:11:00Z", 6)

    # One boot inside the window (matches host_identity last_boot).
    b.add(
        Category.SYSTEM_LIFECYCLE,
        "eventlog",
        timestamp="2026-02-25T04:12:09Z",
        action="boot",
        message="The Event log service was started.",
        attributes=_event_attrs("System", "EventLog", 6005),
        raw_reference="raw/events_System.jsonl",
    )

    # Stock Microsoft maintenance: Defender scheduled scan, daily 02:30,
    # from the start of TaskScheduler retention. Must NOT feed role.batch.v1.
    defender_base = datetime(2026, 2, 26, 2, 30, 0, tzinfo=_UTC)
    for i in range(27):
        _add_defender_scan_run(b, defender_base + timedelta(days=i))

    # The vendor task was registered when the integration went live.
    b.add(
        Category.SCHEDULED_ACTIVITY,
        "eventlog",
        timestamp="2026-03-01T16:44:03Z",
        action="registered",
        scheduled_action=VENDOR_TASK,
        principal="CORP\\ajones",
        attributes=_event_attrs(_TS_CHANNEL, _TS_PROVIDER, 106),
        raw_reference=_RAW_TS,
    )

    # 21 nightly runs across 23 calendar days (nights 7 and 15 skipped).
    run_base = datetime(2026, 3, 2, 1, 0, 0, tzinfo=_UTC)
    for day in range(23):
        if day in (7, 15):
            continue
        jitter = ((day * 37) % 89) - 44  # deterministic seconds of start jitter
        t0 = run_base + timedelta(days=day, seconds=jitter)
        b.add(
            Category.LOGON,
            "eventlog",
            timestamp=to_iso(t0 - timedelta(seconds=1)),
            action="logon",
            principal="CORP\\svc_batch",
            attributes=_event_attrs(
                _SEC_CHANNEL, _SEC_PROVIDER, 4624, logon_kind="batch", logon_type=4
            ),
            raw_reference=_RAW_SEC,
        )
        b.add(
            Category.SCHEDULED_ACTIVITY,
            "eventlog",
            timestamp=to_iso(t0),
            action="start",
            scheduled_action=VENDOR_TASK,
            principal="CORP\\svc_batch",
            attributes=_event_attrs(_TS_CHANNEL, _TS_PROVIDER, 100),
            raw_reference=_RAW_TS,
        )
        b.add(
            Category.SCHEDULED_ACTIVITY,
            "eventlog",
            timestamp=to_iso(t0 + timedelta(seconds=2)),
            action="action_start",
            scheduled_action=VENDOR_TASK,
            principal="CORP\\svc_batch",
            process=VENDOR_EXE,
            attributes=_event_attrs(_TS_CHANNEL, _TS_PROVIDER, 129),
            raw_reference=_RAW_TS,
        )
        b.add(
            Category.EVENT,
            "eventlog",
            timestamp=to_iso(t0 + timedelta(seconds=34)),
            process=VENDOR_EXE,
            remote_host=BATCH01_DB_IP,
            remote_port=1433,
            message=(
                "NightlyExport: opened database session to db01.corp.example "
                "(10.20.30.40:1433)."
            ),
            attributes=_event_attrs("Application", "VendorExport", 5201),
            raw_reference="raw/events_Application.jsonl",
        )
        b.add(
            Category.EVENT,
            "eventlog",
            timestamp=to_iso(t0 + timedelta(seconds=142)),
            process=VENDOR_EXE,
            remote_host=BATCH01_SFTP_HOST,
            remote_port=22,
            message="NightlyExport: extract uploaded to sftp.vendor.example:22.",
            attributes=_event_attrs("Application", "VendorExport", 5210),
            raw_reference="raw/events_Application.jsonl",
        )
        b.add(
            Category.SCHEDULED_ACTIVITY,
            "eventlog",
            timestamp=to_iso(t0 + timedelta(seconds=238)),
            action="complete",
            scheduled_action=VENDOR_TASK,
            attributes=_event_attrs(_TS_CHANNEL, _TS_PROVIDER, 102, result_code=0),
            raw_reference=_RAW_TS,
        )

    # Two admin RDP sessions, each recorded twice (audit + session manager).
    _add_rdp_session(
        b,
        datetime(2026, 3, 10, 14, 3, 11, tzinfo=_UTC),
        "CORP\\ajones",
        "10.20.8.55",
        datetime(2026, 3, 10, 14, 41, 2, tzinfo=_UTC),
    )
    _add_rdp_session(
        b,
        datetime(2026, 3, 18, 9, 41, 7, tzinfo=_UTC),
        "CORP\\ajones",
        "10.20.8.55",
        datetime(2026, 3, 18, 10, 2, 33, tzinfo=_UTC),
    )

    # A little inbound network-logon and failed-logon clutter.
    for ts, principal, source in (
        ("2026-03-05T06:15:40Z", "CORP\\FILESRV01$", "10.20.30.12"),
        ("2026-03-12T06:15:37Z", "CORP\\FILESRV01$", "10.20.30.12"),
        ("2026-03-16T21:04:12Z", "CORP\\svc_monitor", "10.20.30.14"),
    ):
        b.add(
            Category.LOGON,
            "eventlog",
            timestamp=ts,
            action="logon",
            principal=principal,
            remote_host=source,
            attributes=_event_attrs(
                _SEC_CHANNEL, _SEC_PROVIDER, 4624, logon_kind="network", logon_type=3
            ),
            raw_reference=_RAW_SEC,
        )
    b.add(
        Category.LOGON,
        "eventlog",
        timestamp="2026-03-12T11:02:19Z",
        action="logon_failed",
        principal="CORP\\jdoe",
        remote_host="10.20.8.61",
        attributes=_event_attrs(
            _SEC_CHANNEL, _SEC_PROVIDER, 4625,
            logon_kind="remote_interactive", logon_type=10, level="Warning",
        ),
        raw_reference=_RAW_SEC,
    )

    # Generic event noise so analyzers face realistic clutter.
    for ts, channel, provider, event_id, level, message in (
        ("2026-02-27T00:00:02Z", "System", "Microsoft-Windows-Time-Service", 35,
         "Information", "The time service is now synchronizing the system time."),
        ("2026-03-01T09:00:14Z", "System", "Microsoft-Windows-GroupPolicy", 1502,
         "Information", "The Group Policy settings for the computer were processed successfully."),
        ("2026-03-03T02:12:51Z", "Application", "Microsoft-Windows-Defrag", 258,
         "Information", "The storage optimizer successfully completed retrim on (C:)."),
        ("2026-03-05T13:40:00Z", "System", "Microsoft-Windows-DNS-Client", 1014,
         "Warning", "Name resolution for the name wpad.corp.example timed out."),
        ("2026-03-08T04:02:33Z", "Application", "SceCli", 1704,
         "Information", "Security policy in the Group policy objects has been applied successfully."),
        ("2026-03-11T18:22:09Z", "System", "Microsoft-Windows-Kernel-General", 16,
         "Information", "The access history in hive was cleared updating 1348 keys."),
        ("2026-03-14T00:00:05Z", "System", "Microsoft-Windows-Time-Service", 35,
         "Information", "The time service is now synchronizing the system time."),
        ("2026-03-15T09:00:20Z", "System", "Microsoft-Windows-GroupPolicy", 1502,
         "Information", "The Group Policy settings for the computer were processed successfully."),
        ("2026-03-19T22:10:44Z", "Application", "MsiInstaller", 11707,
         "Information", "Product: Vendor Integration Suite -- Configuration completed successfully."),
        ("2026-03-21T07:31:12Z", "System", "Microsoft-Windows-WindowsUpdateClient", 26,
         "Information", "Installation ready: the following updates are downloaded and ready."),
        ("2026-03-22T15:55:31Z", "System", "Service Control Manager", 7040,
         "Information", "The start type of the Background Intelligent Transfer Service was changed."),
        ("2026-03-23T04:18:47Z", "Application", "Windows Error Reporting", 1001,
         "Information", "Fault bucket, type 0. Event Name: WindowsUpdateFailure3."),
    ):
        _add_noise_event(b, ts, channel, provider, event_id, message, level)

    # Current state: services (IIS configured but stopped = dormancy candidate).
    _add_service(b, state_ts, "W3SVC", "World Wide Web Publishing Service",
                 "stopped", "auto",
                 path="C:\\Windows\\System32\\svchost.exe",
                 raw_path="C:\\Windows\\system32\\svchost.exe -k iissvcs")
    _add_service(b, state_ts, "VendorAgent", "Vendor Integration Agent",
                 "running", "auto", principal="CORP\\svc_batch",
                 path="D:\\Vendor\\vendoragent.exe",
                 raw_path="\"D:\\Vendor\\vendoragent.exe\" -service")
    _add_service(b, state_ts, "WinDefend", "Microsoft Defender Antivirus Service",
                 "running", "auto",
                 path="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe")
    _add_service(b, state_ts, "Schedule", "Task Scheduler", "running", "auto",
                 path="C:\\Windows\\system32\\svchost.exe")
    _add_service(b, state_ts, "Dhcp", "DHCP Client", "running", "auto",
                 principal="NT AUTHORITY\\LocalService",
                 path="C:\\Windows\\system32\\svchost.exe")
    _add_service(b, state_ts, "TermService", "Remote Desktop Services",
                 "running", "manual",
                 principal="NT AUTHORITY\\NetworkService",
                 path="C:\\Windows\\System32\\svchost.exe")
    _add_service(b, state_ts, "W32Time", "Windows Time", "running", "manual",
                 principal="NT AUTHORITY\\LocalService",
                 path="C:\\Windows\\system32\\svchost.exe")
    _add_service(b, state_ts, "RemoteRegistry", "Remote Registry",
                 "stopped", "disabled",
                 principal="NT AUTHORITY\\LocalService",
                 path="C:\\Windows\\system32\\svchost.exe")

    # Scheduled task configuration (state matches observed history).
    _add_task_state(
        b, state_ts, VENDOR_TASK,
        principal="CORP\\svc_batch",
        execute=VENDOR_EXE, arguments="/profile nightly",
        trigger={"type": "daily", "start": "2026-03-02T01:00:00", "interval": None},
        last_run="2026-03-24T00:59:29Z", next_run="2026-03-25T01:00:00Z",
        last_result=0,
    )
    _add_task_state(
        b, state_ts, DEFENDER_TASK,
        principal="NT AUTHORITY\\SYSTEM",
        execute=DEFENDER_EXE, arguments="Scan -ScheduleJob",
        trigger={"type": "daily", "start": "2020-01-01T02:30:00", "interval": None},
        last_run="2026-03-24T02:30:00Z", next_run="2026-03-25T02:30:00Z",
        last_result=0,
    )
    _add_task_state(
        b, state_ts, DEFRAG_TASK,
        principal="NT AUTHORITY\\SYSTEM",
        execute="C:\\Windows\\system32\\defrag.exe", arguments="-c -h -o",
        trigger={"type": "other", "start": "2020-01-01T01:00:00", "interval": "P1W"},
        last_run="2026-03-18T01:00:00Z", next_run="2026-03-25T01:00:00Z",
        last_result=0,
    )

    # Running processes.
    _add_process(b, state_ts, "D:\\Vendor\\vendoragent.exe", 3488,
                 principal="CORP\\svc_batch", parent_pid=624,
                 command_line="\"D:\\Vendor\\vendoragent.exe\" -service",
                 start_time="2026-02-25T04:13:11Z")
    _add_process(b, state_ts, "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
                 2144, principal="NT AUTHORITY\\SYSTEM", parent_pid=624,
                 start_time="2026-02-25T04:12:40Z")
    _add_process(b, state_ts, "C:\\Windows\\system32\\svchost.exe", 912,
                 principal="NT AUTHORITY\\SYSTEM", parent_pid=624,
                 command_line="C:\\Windows\\system32\\svchost.exe -k netsvcs",
                 start_time="2026-02-25T04:12:15Z")
    _add_process(b, state_ts, "C:\\Windows\\system32\\lsass.exe", 668,
                 principal="NT AUTHORITY\\SYSTEM", parent_pid=540,
                 start_time="2026-02-25T04:12:10Z")

    # Network state: the vendor agent still holds one DB connection.
    _add_established(b, state_ts, BATCH01_DB_IP, 1433, "vendoragent.exe", 3488,
                     "10.20.7.15", 49321)
    _add_listen(b, state_ts, 3389, "svchost.exe", 1104)
    _add_listen(b, state_ts, 445, "System", 4)
    _add_listen(b, state_ts, 135, "svchost.exe", 908)

    _add_identity(b, state_ts, "BATCH01", "batch01.corp.example",
                  "Windows Server 2019 Standard", "10.0.17763",
                  ["10.20.7.15"], "2026-02-25T04:12:09Z")

    _add_role(b, state_ts, "Web-Server", "Web Server (IIS)")
    _add_role(b, state_ts, "FileAndStorage-Services", "File and Storage Services")

    _add_software(b, state_ts, "Vendor Integration Suite", "9.4.1", "Vendor Corp",
                  "2026-03-01T00:00:00Z")
    _add_software(b, state_ts, "Microsoft ODBC Driver 17 for SQL Server",
                  "17.10.5.1", "Microsoft Corporation", "2026-03-01T00:00:00Z")
    _add_software(b, state_ts, "WinSCP 5.21.7", "5.21.7", "Martin Prikryl",
                  "2026-03-01T00:00:00Z")

    observations = b.observations()
    manifest = _manifest("BATCH01", collection_start, collection_end,
                         "30d", since, observations)
    return manifest, observations


# ---------------------------------------------------------------------------
# web01 — web/application server
# ---------------------------------------------------------------------------


def build_web01() -> tuple[dict[str, Any], list[Observation]]:
    """Web/application server.

    IIS (W3SVC + WAS) running, w3wp.exe worker processes, http.sys listening
    on 80/443, a current-only pool of 4 established sockets from w3wp.exe to
    db02 (10.20.30.41:1433) — enough for a MEDIUM db-client inference, never
    HIGH (simultaneity is not repetition). W3SVC/WAS service starts appear at
    three boots in history. The only recurring scheduled activity is the
    stock Microsoft Defender scan; it must not produce a batch role. A few
    admin RDP sessions stay below the interactive-classification threshold,
    and steady inbound network logons keep the host from looking quiet.
    """
    collection_start = datetime(2026, 4, 14, 7, 25, 0, tzinfo=_UTC)
    collection_end = datetime(2026, 4, 14, 7, 30, 0, tzinfo=_UTC)
    since = datetime(2026, 3, 31, 7, 25, 0, tzinfo=_UTC)
    inv_ts = to_iso(datetime(2026, 4, 14, 7, 26, 0, tzinfo=_UTC))
    state_ts = to_iso(datetime(2026, 4, 14, 7, 27, 0, tzinfo=_UTC))

    b = _Builder()

    _add_channel(b, inv_ts, _SEC_CHANNEL, True, 152344,
                 "2026-03-29T00:04:18Z", "2026-04-14T07:24:55Z", 4200)
    _add_channel(b, inv_ts, "System", True, 30122,
                 "2025-12-01T05:22:47Z", "2026-04-14T07:20:31Z", 900)
    _add_channel(b, inv_ts, "Application", True, 25011,
                 "2026-01-20T11:15:02Z", "2026-04-14T07:18:44Z", 700)
    _add_channel(b, inv_ts, _TS_CHANNEL, True, 10233,
                 "2026-03-28T02:59:41Z", "2026-04-14T03:19:03Z", 320)
    _add_channel(b, inv_ts, _LSM_CHANNEL, True, 210,
                 "2025-09-10T08:00:00Z", "2026-04-12T10:40:12Z", 9)
    _add_channel(b, inv_ts, "Microsoft-Windows-IIS-Configuration/Operational", True, 88,
                 "2025-11-02T16:20:33Z", "2026-04-09T04:16:40Z", 4)

    # Stock Microsoft maintenance: Defender scan daily 03:00 — the ONLY
    # recurring scheduled activity on this host.
    defender_base = datetime(2026, 4, 1, 3, 0, 0, tzinfo=_UTC)
    for i in range(14):
        _add_defender_scan_run(b, defender_base + timedelta(days=i))

    # Three boots, each followed by WAS/W3SVC service starts (as the Service
    # Control Manager reports them: display names) and the app-pool identity
    # logging on as a service when the first worker spins up.
    for boot_iso in (
        "2026-04-02T04:11:05Z",
        "2026-04-09T04:15:22Z",
        "2026-04-13T22:28:40Z",
    ):
        boot = datetime.strptime(boot_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_UTC)
        b.add(
            Category.SYSTEM_LIFECYCLE,
            "eventlog",
            timestamp=boot_iso,
            action="boot",
            message="The Event log service was started.",
            attributes=_event_attrs("System", "EventLog", 6005),
            raw_reference="raw/events_System.jsonl",
        )
        for offset, display in ((48, "Windows Process Activation Service"),
                                (50, "World Wide Web Publishing Service")):
            b.add(
                Category.SERVICE_ACTIVITY,
                "eventlog",
                timestamp=to_iso(boot + timedelta(seconds=offset)),
                action="start",
                service=display,
                message=f"The {display} service entered the running state.",
                attributes=_event_attrs(
                    "System", "Service Control Manager", 7036, state="running"
                ),
                raw_reference="raw/events_System.jsonl",
            )
        b.add(
            Category.LOGON,
            "eventlog",
            timestamp=to_iso(boot + timedelta(seconds=55)),
            action="logon",
            principal="IIS APPPOOL\\ContosoPortal",
            attributes=_event_attrs(
                _SEC_CHANNEL, _SEC_PROVIDER, 4624, logon_kind="service", logon_type=5
            ),
            raw_reference=_RAW_SEC,
        )

    # A few admin RDP sessions spread over weeks (below the interactive
    # classification threshold of 5).
    _add_rdp_session(b, datetime(2026, 4, 3, 10, 12, 44, tzinfo=_UTC),
                     "CORP\\ajones", "10.20.8.55",
                     datetime(2026, 4, 3, 10, 58, 2, tzinfo=_UTC))
    _add_rdp_session(b, datetime(2026, 4, 8, 16, 3, 10, tzinfo=_UTC),
                     "CORP\\rpatel", "10.20.8.60",
                     datetime(2026, 4, 8, 16, 40, 55, tzinfo=_UTC))
    _add_rdp_session(b, datetime(2026, 4, 12, 9, 55, 31, tzinfo=_UTC),
                     "CORP\\ajones", "10.20.8.55",
                     datetime(2026, 4, 12, 10, 40, 12, tzinfo=_UTC))

    # Steady inbound network logons (monitoring, service-to-service auth).
    net_base = datetime(2026, 3, 31, 8, 7, 13, tzinfo=_UTC)
    net_principals = ("CORP\\svc_scanner", "CORP\\APP03$", "CORP\\jenkins")
    for i in range(30):
        b.add(
            Category.LOGON,
            "eventlog",
            timestamp=to_iso(net_base + timedelta(hours=8 * i, minutes=i % 3)),
            action="logon",
            principal=net_principals[i % 3],
            remote_host=f"10.20.9.{20 + i % 4}",
            attributes=_event_attrs(
                _SEC_CHANNEL, _SEC_PROVIDER, 4624, logon_kind="network", logon_type=3
            ),
            raw_reference=_RAW_SEC,
        )
    for ts, principal in (
        ("2026-04-05T03:14:29Z", "CORP\\svc_scanner"),
        ("2026-04-11T19:44:01Z", "CORP\\jjenkins"),
    ):
        b.add(
            Category.LOGON,
            "eventlog",
            timestamp=ts,
            action="logon_failed",
            principal=principal,
            remote_host="10.20.9.23",
            attributes=_event_attrs(
                _SEC_CHANNEL, _SEC_PROVIDER, 4625,
                logon_kind="network", logon_type=3, level="Warning",
            ),
            raw_reference=_RAW_SEC,
        )

    # Generic clutter.
    for ts, channel, provider, event_id, level, message in (
        ("2026-04-01T09:00:11Z", "System", "Microsoft-Windows-GroupPolicy", 1502,
         "Information", "The Group Policy settings for the computer were processed successfully."),
        ("2026-04-02T04:16:39Z", "Microsoft-Windows-IIS-Configuration/Operational",
         "Microsoft-Windows-IIS-Configuration", 29, "Information",
         "Configuration change: applicationHost.config committed."),
        ("2026-04-04T13:02:56Z", "Application", "ASP.NET 4.0.30319.0", 1309,
         "Warning", "Event code: 3005. An unhandled exception has occurred."),
        ("2026-04-06T00:00:04Z", "System", "Microsoft-Windows-Time-Service", 35,
         "Information", "The time service is now synchronizing the system time."),
        ("2026-04-07T22:15:18Z", "Application", "ASP.NET 4.0.30319.0", 1309,
         "Warning", "Event code: 3005. An unhandled exception has occurred."),
        ("2026-04-09T04:16:40Z", "Microsoft-Windows-IIS-Configuration/Operational",
         "Microsoft-Windows-IIS-Configuration", 29, "Information",
         "Configuration change: applicationHost.config committed."),
        ("2026-04-10T11:38:07Z", "Application", "ASP.NET 4.0.30319.0", 1309,
         "Warning", "Event code: 3005. An unhandled exception has occurred."),
        ("2026-04-13T22:29:55Z", "System", "Service Control Manager", 7040,
         "Information", "The start type of the Background Intelligent Transfer Service was changed."),
    ):
        _add_noise_event(b, ts, channel, provider, event_id, message, level)

    # Current state: IIS services running.
    _add_service(b, state_ts, "W3SVC", "World Wide Web Publishing Service",
                 "running", "auto",
                 path="C:\\Windows\\System32\\svchost.exe",
                 raw_path="C:\\Windows\\system32\\svchost.exe -k iissvcs")
    _add_service(b, state_ts, "WAS", "Windows Process Activation Service",
                 "running", "manual",
                 path="C:\\Windows\\System32\\svchost.exe",
                 raw_path="C:\\Windows\\system32\\svchost.exe -k iissvcs")
    _add_service(b, state_ts, "AppHostSvc", "Application Host Helper Service",
                 "running", "auto",
                 path="C:\\Windows\\System32\\svchost.exe")
    _add_service(b, state_ts, "WinDefend", "Microsoft Defender Antivirus Service",
                 "running", "auto",
                 path="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe")
    _add_service(b, state_ts, "Schedule", "Task Scheduler", "running", "auto",
                 path="C:\\Windows\\system32\\svchost.exe")
    _add_service(b, state_ts, "TermService", "Remote Desktop Services",
                 "running", "manual", principal="NT AUTHORITY\\NetworkService",
                 path="C:\\Windows\\System32\\svchost.exe")
    _add_service(b, state_ts, "CryptSvc", "Cryptographic Services",
                 "running", "auto", principal="NT AUTHORITY\\NetworkService",
                 path="C:\\Windows\\system32\\svchost.exe")
    _add_service(b, state_ts, "wuauserv", "Windows Update", "stopped", "manual",
                 path="C:\\Windows\\system32\\svchost.exe")

    _add_task_state(
        b, state_ts, DEFENDER_TASK,
        principal="NT AUTHORITY\\SYSTEM",
        execute=DEFENDER_EXE, arguments="Scan -ScheduleJob",
        trigger={"type": "daily", "start": "2020-01-01T03:00:00", "interval": None},
        last_run="2026-04-14T03:00:02Z", next_run="2026-04-15T03:00:00Z",
        last_result=0,
    )
    _add_task_state(
        b, state_ts, DEFRAG_TASK,
        principal="NT AUTHORITY\\SYSTEM",
        execute="C:\\Windows\\system32\\defrag.exe", arguments="-c -h -o",
        trigger={"type": "other", "start": "2020-01-01T01:00:00", "interval": "P1W"},
        last_run="2026-04-08T01:12:00Z", next_run="2026-04-15T01:00:00Z",
        last_result=0,
    )

    _add_process(b, state_ts, "C:\\Windows\\System32\\inetsrv\\w3wp.exe", 4812,
                 principal="IIS APPPOOL\\ContosoPortal", parent_pid=1520,
                 command_line="c:\\windows\\system32\\inetsrv\\w3wp.exe -ap \"ContosoPortal\"",
                 start_time="2026-04-13T22:30:12Z")
    _add_process(b, state_ts, "C:\\Windows\\System32\\inetsrv\\w3wp.exe", 5120,
                 principal="IIS APPPOOL\\ContosoApi", parent_pid=1520,
                 command_line="c:\\windows\\system32\\inetsrv\\w3wp.exe -ap \"ContosoApi\"",
                 start_time="2026-04-13T22:31:44Z")
    _add_process(b, state_ts, "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
                 2208, principal="NT AUTHORITY\\SYSTEM", parent_pid=624,
                 start_time="2026-04-13T22:29:10Z")
    _add_process(b, state_ts, "C:\\Windows\\system32\\lsass.exe", 672,
                 principal="NT AUTHORITY\\SYSTEM", parent_pid=544,
                 start_time="2026-04-13T22:28:44Z")

    # http.sys owns 80/443 (shows as System, pid 4).
    _add_listen(b, state_ts, 80, "System", 4)
    _add_listen(b, state_ts, 443, "System", 4)
    _add_listen(b, state_ts, 3389, "svchost.exe", 1188)
    _add_listen(b, state_ts, 445, "System", 4)
    _add_listen(b, state_ts, 135, "svchost.exe", 916)

    # Current-only connection pool to db02 (4 sockets at one instant), plus
    # ordinary domain-infrastructure connections.
    for local_port, pid in ((51244, 4812), (51245, 4812), (51246, 5120), (51247, 5120)):
        _add_established(b, state_ts, WEB01_DB_IP, 1433, "w3wp.exe", pid,
                         "10.20.7.20", local_port)
    _add_established(b, state_ts, "10.20.30.10", 445, "System", 4,
                     "10.20.7.20", 50101)
    _add_established(b, state_ts, "10.20.30.10", 389, "lsass.exe", 672,
                     "10.20.7.20", 50102)

    _add_identity(b, state_ts, "WEB01", "web01.corp.example",
                  "Windows Server 2022 Standard", "10.0.20348",
                  ["10.20.7.20"], "2026-04-13T22:28:40Z")

    _add_role(b, state_ts, "Web-Server", "Web Server (IIS)")
    _add_role(b, state_ts, "NET-Framework-45-Features", ".NET Framework 4.7 Features")

    _add_software(b, state_ts, "Contoso Customer Portal", "4.2.1", "Contoso IT",
                  "2025-06-12T00:00:00Z")
    _add_software(b, state_ts, "Microsoft ODBC Driver 17 for SQL Server",
                  "17.10.5.1", "Microsoft Corporation", "2025-06-12T00:00:00Z")
    _add_software(b, state_ts, "IIS URL Rewrite Module 2", "7.2.1993",
                  "Microsoft Corporation", "2025-06-12T00:00:00Z")

    observations = b.observations()
    manifest = _manifest("WEB01", collection_start, collection_end,
                         "14d", since, observations)
    return manifest, observations


# ---------------------------------------------------------------------------
# idle01 — mostly-idle administration box
# ---------------------------------------------------------------------------


def build_idle01() -> tuple[dict[str, Any], list[Observation]]:
    """Mostly-idle administration box.

    Four admin RDP sessions from two admins over 30 days (each recorded by
    both the audit log and the session manager — dedupe must count 4).
    The Microsoft maintenance tasks are configured with daily triggers, but
    the TaskScheduler/Operational channel retains far less history than
    Security (2.3 days vs 30+), so only TWO Defender scan starts survive in
    evidence — below the recurrence analyzer's 3-start threshold. That is
    exactly what keeps role.quiet.v1 eligible (it requires no recurring
    findings) and is the honest reading of the evidence: the short retention
    is itself reported as a limitation. Several auto/manual services are
    stopped with no observed activity, a legacy backup app is installed, and
    the only listener is RDP on 3389.
    """
    collection_start = datetime(2026, 5, 5, 15, 55, 0, tzinfo=_UTC)
    collection_end = datetime(2026, 5, 5, 16, 0, 0, tzinfo=_UTC)
    since = datetime(2026, 4, 5, 15, 55, 0, tzinfo=_UTC)
    inv_ts = to_iso(datetime(2026, 5, 5, 15, 56, 0, tzinfo=_UTC))
    state_ts = to_iso(datetime(2026, 5, 5, 15, 57, 0, tzinfo=_UTC))

    b = _Builder()

    # Security retains the full window; TaskScheduler/Operational retains
    # only ~2.3 days (a small log on a box nobody resized it on).
    _add_channel(b, inv_ts, _SEC_CHANNEL, True, 9866,
                 "2026-04-02T11:20:05Z", "2026-05-05T15:52:10Z", 210)
    _add_channel(b, inv_ts, "System", True, 15221,
                 "2025-08-19T02:33:20Z", "2026-05-05T15:40:08Z", 300)
    _add_channel(b, inv_ts, "Application", True, 8455,
                 "2025-09-01T10:12:00Z", "2026-05-05T12:02:51Z", 150)
    _add_channel(b, inv_ts, _TS_CHANNEL, True, 1023,
                 "2026-05-03T09:12:44Z", "2026-05-05T04:29:07Z", 40,
                 max_size=1052672)
    _add_channel(b, inv_ts, _LSM_CHANNEL, True, 84,
                 "2025-06-30T07:45:00Z", "2026-05-01T09:20:41Z", 8)

    # Only two Defender scan runs fall inside TaskScheduler retention —
    # deliberately below the >=3-start recurrence threshold (see docstring).
    _add_defender_scan_run(b, datetime(2026, 5, 4, 4, 10, 3, tzinfo=_UTC))
    _add_defender_scan_run(b, datetime(2026, 5, 5, 4, 10, 7, tzinfo=_UTC))

    # Four RDP sessions from two admins across the month (audit + session
    # manager pairs; dedupe must yield exactly 4 remote-interactive logons).
    _add_rdp_session(b, datetime(2026, 4, 8, 9, 15, 2, tzinfo=_UTC),
                     "CORP\\ajones", "10.20.8.55",
                     datetime(2026, 4, 8, 9, 58, 40, tzinfo=_UTC))
    _add_rdp_session(b, datetime(2026, 4, 15, 14, 22, 41, tzinfo=_UTC),
                     "CORP\\rpatel", "10.20.8.60",
                     datetime(2026, 4, 15, 15, 3, 12, tzinfo=_UTC))
    _add_rdp_session(b, datetime(2026, 4, 24, 11, 5, 33, tzinfo=_UTC),
                     "CORP\\ajones", "10.20.8.55",
                     datetime(2026, 4, 24, 11, 47, 21, tzinfo=_UTC))
    _add_rdp_session(b, datetime(2026, 5, 1, 8, 44, 19, tzinfo=_UTC),
                     "CORP\\rpatel", "10.20.8.60",
                     datetime(2026, 5, 1, 9, 20, 41, tzinfo=_UTC))

    # Light clutter: a couple of machine-account network logons, one typo'd
    # failed logon, and generic events. Everything stays below the analyzer's
    # activity thresholds — that is the archetype.
    for ts, principal, source in (
        ("2026-04-11T02:00:15Z", "CORP\\DC01$", "10.20.30.10"),
        ("2026-04-25T02:00:22Z", "CORP\\DC01$", "10.20.30.10"),
        ("2026-04-29T16:12:44Z", "CORP\\svc_monitor", "10.20.30.14"),
    ):
        b.add(
            Category.LOGON,
            "eventlog",
            timestamp=ts,
            action="logon",
            principal=principal,
            remote_host=source,
            attributes=_event_attrs(
                _SEC_CHANNEL, _SEC_PROVIDER, 4624, logon_kind="network", logon_type=3
            ),
            raw_reference=_RAW_SEC,
        )
    b.add(
        Category.LOGON,
        "eventlog",
        timestamp="2026-04-24T11:05:12Z",
        action="logon_failed",
        principal="CORP\\ajones",
        remote_host="10.20.8.55",
        attributes=_event_attrs(
            _SEC_CHANNEL, _SEC_PROVIDER, 4625,
            logon_kind="remote_interactive", logon_type=10, level="Warning",
        ),
        raw_reference=_RAW_SEC,
    )

    for ts, channel, provider, event_id, level, message in (
        ("2026-04-06T00:00:09Z", "System", "Microsoft-Windows-Time-Service", 35,
         "Information", "The time service is now synchronizing the system time."),
        ("2026-04-07T09:00:31Z", "System", "Microsoft-Windows-GroupPolicy", 1502,
         "Information", "The Group Policy settings for the computer were processed successfully."),
        ("2026-04-10T00:00:12Z", "System", "Microsoft-Windows-Time-Service", 35,
         "Information", "The time service is now synchronizing the system time."),
        ("2026-04-13T03:22:40Z", "System", "Microsoft-Windows-Kernel-General", 16,
         "Information", "The access history in hive was cleared updating 214 keys."),
        ("2026-04-17T09:00:27Z", "System", "Microsoft-Windows-GroupPolicy", 1502,
         "Information", "The Group Policy settings for the computer were processed successfully."),
        ("2026-04-20T00:00:10Z", "System", "Microsoft-Windows-Time-Service", 35,
         "Information", "The time service is now synchronizing the system time."),
        ("2026-04-22T06:00:00Z", "System", "EventLog", 6013,
         "Information", "The system uptime is 1985460 seconds."),
        ("2026-04-27T09:00:29Z", "System", "Microsoft-Windows-GroupPolicy", 1502,
         "Information", "The Group Policy settings for the computer were processed successfully."),
        ("2026-04-30T00:00:14Z", "System", "Microsoft-Windows-Time-Service", 35,
         "Information", "The time service is now synchronizing the system time."),
        ("2026-05-02T13:41:52Z", "Application", "SceCli", 1704,
         "Information", "Security policy in the Group policy objects has been applied successfully."),
        ("2026-05-04T00:00:08Z", "System", "Microsoft-Windows-Time-Service", 35,
         "Information", "The time service is now synchronizing the system time."),
        ("2026-05-05T06:00:00Z", "System", "EventLog", 6013,
         "Information", "The system uptime is 3108660 seconds."),
    ):
        _add_noise_event(b, ts, channel, provider, event_id, message, level)

    # Current state: several dormancy candidates (auto/manual, stopped, no
    # observed activity) among ordinary running plumbing.
    _add_service(b, state_ts, "CobianBackup11", "Cobian Backup 11 Gravity",
                 "stopped", "auto",
                 path="C:\\Program Files (x86)\\Cobian Backup 11\\cbService.exe",
                 raw_path="\"C:\\Program Files (x86)\\Cobian Backup 11\\cbService.exe\"")
    _add_service(b, state_ts, "Spooler", "Print Spooler", "stopped", "auto",
                 path="C:\\Windows\\System32\\spoolsv.exe")
    _add_service(b, state_ts, "RemoteRegistry", "Remote Registry",
                 "stopped", "manual", principal="NT AUTHORITY\\LocalService",
                 path="C:\\Windows\\system32\\svchost.exe")
    _add_service(b, state_ts, "SNMPTRAP", "SNMP Trap", "stopped", "manual",
                 principal="NT AUTHORITY\\LocalService",
                 path="C:\\Windows\\System32\\snmptrap.exe")
    _add_service(b, state_ts, "WinDefend", "Microsoft Defender Antivirus Service",
                 "running", "auto",
                 path="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe")
    _add_service(b, state_ts, "Schedule", "Task Scheduler", "running", "auto",
                 path="C:\\Windows\\system32\\svchost.exe")
    _add_service(b, state_ts, "TermService", "Remote Desktop Services",
                 "running", "manual", principal="NT AUTHORITY\\NetworkService",
                 path="C:\\Windows\\System32\\svchost.exe")
    _add_service(b, state_ts, "Dhcp", "DHCP Client", "running", "auto",
                 principal="NT AUTHORITY\\LocalService",
                 path="C:\\Windows\\system32\\svchost.exe")
    _add_service(b, state_ts, "W32Time", "Windows Time", "running", "manual",
                 principal="NT AUTHORITY\\LocalService",
                 path="C:\\Windows\\system32\\svchost.exe")

    # Microsoft maintenance tasks are configured (their triggers fire daily);
    # only the short TaskScheduler retention hides most of their history.
    _add_task_state(
        b, state_ts, DEFENDER_TASK,
        principal="NT AUTHORITY\\SYSTEM",
        execute=DEFENDER_EXE, arguments="Scan -ScheduleJob",
        trigger={"type": "daily", "start": "2020-01-01T04:10:00", "interval": None},
        last_run="2026-05-05T04:10:07Z", next_run="2026-05-06T04:10:00Z",
        last_result=0,
    )
    _add_task_state(
        b, state_ts, DEFRAG_TASK,
        principal="NT AUTHORITY\\SYSTEM",
        execute="C:\\Windows\\system32\\defrag.exe", arguments="-c -h -o",
        trigger={"type": "other", "start": "2020-01-01T01:00:00", "interval": "P1W"},
        last_run="2026-04-29T01:00:00Z", next_run="2026-05-06T01:00:00Z",
        last_result=0,
    )
    _add_task_state(
        b, state_ts,
        "\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
        principal="NT AUTHORITY\\SYSTEM",
        execute="C:\\Windows\\system32\\rundll32.exe",
        arguments="invagent.dll,RunUpdate",
        trigger={"type": "time", "start": "2020-01-01T02:30:00", "interval": None},
        last_run="2026-01-14T02:30:00Z", next_run=None,
        last_result=0,
    )

    _add_process(b, state_ts, "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
                 1988, principal="NT AUTHORITY\\SYSTEM", parent_pid=612,
                 start_time="2026-03-30T07:03:01Z")
    _add_process(b, state_ts, "C:\\Windows\\system32\\svchost.exe", 1032,
                 principal="NT AUTHORITY\\NetworkService", parent_pid=612,
                 command_line="C:\\Windows\\System32\\svchost.exe -k NetworkService",
                 start_time="2026-03-30T07:02:44Z")
    _add_process(b, state_ts, "C:\\Windows\\system32\\lsass.exe", 660,
                 principal="NT AUTHORITY\\SYSTEM", parent_pid=532,
                 start_time="2026-03-30T07:02:20Z")

    # The only listener is RDP.
    _add_listen(b, state_ts, 3389, "svchost.exe", 1032)

    _add_identity(b, state_ts, "IDLE01", "idle01.corp.example",
                  "Windows Server 2016 Standard", "10.0.14393",
                  ["10.20.7.31"], "2026-03-30T07:02:11Z")

    _add_software(b, state_ts, "Cobian Backup 11", "11.2.0.582", "CobianSoft",
                  "2019-04-11T00:00:00Z")
    _add_software(b, state_ts, "PuTTY release 0.76", "0.76.0.0", "Simon Tatham",
                  "2021-08-02T00:00:00Z")
    _add_software(b, state_ts, "Microsoft Visual C++ 2015 Redistributable (x64)",
                  "14.0.24215.1", "Microsoft Corporation", "2019-04-11T00:00:00Z")

    observations = b.observations()
    manifest = _manifest("IDLE01", collection_start, collection_end,
                         "30d", since, observations)
    return manifest, observations


BUILDERS = {
    "batch01": build_batch01,
    "web01": build_web01,
    "idle01": build_idle01,
}


def write_directory_bundle(
    path: str | Path, manifest: dict[str, Any], observations: list[Observation]
) -> Path:
    """Write a bundle as a directory (manifest.json + observations.jsonl)."""
    bundle_dir = Path(path)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    with open(bundle_dir / "observations.jsonl", "w", encoding="utf-8") as fh:
        for obs in observations:
            fh.write(json.dumps(obs.to_json_dict(), ensure_ascii=False) + "\n")
    return bundle_dir


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("usage: python tests/synth.py <output-dir>")
    root = Path(sys.argv[1])
    for name, builder in BUILDERS.items():
        manifest, observations = builder()
        out = write_directory_bundle(root / name, manifest, observations)
        print(f"wrote {out} ({len(observations)} observations)")
