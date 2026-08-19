"""Tests for the configured-but-unobserved analyzer (CONTRACTS.md §4)."""

from __future__ import annotations

import json

from wtfserver.analyzers.configured_unobserved import (
    ANALYZER,
    ConfiguredUnobservedAnalyzer,
)
from wtfserver.model import (
    EVIDENCE_CONFIGURED,
    EVIDENCE_UNKNOWN,
    Category,
    FindingType,
)

from helpers import build_ctx, make_manifest, make_obs


def _svc_state(name, start_mode="auto", state="stopped", display_name=None):
    return make_obs(
        Category.SERVICE_STATE,
        source="services",
        action="configured",
        service=name,
        attributes={
            "display_name": display_name if display_name is not None else name,
            "state": state,
            "start_mode": start_mode,
            "raw_path": None,
        },
    )


def _task_state(path, enabled=True, last_run=None):
    return make_obs(
        Category.SCHEDULED_TASK_STATE,
        source="scheduled_tasks",
        action="configured",
        scheduled_action=path,
        attributes={
            "enabled": enabled,
            "state": "Ready",
            "actions": [],
            "triggers": [],
            "last_run": last_run,
            "next_run": None,
            "last_result": None,
            "missed_runs": None,
            "hidden": False,
        },
    )


def _role(name):
    return make_obs(
        Category.INSTALLED_ROLE,
        source="software",
        action="installed",
        message=name,
        attributes={"name": name, "display_name": name},
    )


def _hist_event():
    return make_obs(
        Category.EVENT,
        source="eventlog",
        timestamp="2026-08-17T01:00:00Z",
        attributes={"channel": "System", "provider": "p", "event_id": 1, "level": None},
    )


def _channel(oldest="2026-08-10T00:00:00Z"):
    # Evidence-channel retention record; oldest before the default window
    # start means the full requested window is actually available.
    return make_obs(
        Category.EVIDENCE_CHANNEL,
        source="eventlog",
        action="inventoried",
        timestamp="2026-08-19T12:01:00Z",
        attributes={
            "channel": "System",
            "enabled": True,
            "record_count": 100,
            "oldest_record": oldest,
            "newest_record": "2026-08-19T12:00:00Z",
            "max_size_bytes": None,
            "collected_events": 100,
            "truncated": False,
        },
    )


def _svc_activity(name, action="start", source="eventlog", message=None):
    return make_obs(
        Category.SERVICE_ACTIVITY,
        source=source,
        action=action,
        service=name,
        message=message,
        timestamp="2026-08-17T02:00:00Z",
        attributes={"channel": "System", "provider": "SCM", "event_id": 7036, "level": None},
    )


def _sched_activity(path):
    return make_obs(
        Category.SCHEDULED_ACTIVITY,
        source="eventlog",
        action="start",
        scheduled_action=path,
        timestamp="2026-08-17T03:00:00Z",
        attributes={"channel": "TS", "provider": "TS", "event_id": 100, "level": None},
    )


def _listening(port):
    return make_obs(
        Category.SOCKET_STATE,
        source="network",
        action="listening",
        attributes={
            "protocol": "tcp",
            "local_address": "0.0.0.0",
            "local_port": port,
            "pid": 4,
            "state": "LISTEN",
        },
    )


def _run(observations, manifest=None):
    ctx = build_ctx(observations, manifest=manifest)
    return ANALYZER.analyze(ctx)


def _configured(findings):
    return [f for f in findings if f.finding_type == FindingType.CONFIGURED_BUT_UNOBSERVED]


def test_module_exports_analyzer_instance():
    assert isinstance(ANALYZER, ConfiguredUnobservedAnalyzer)
    assert ANALYZER.name == "configured_unobserved"


def test_no_history_emits_single_limitation_and_no_items():
    obs = [
        _svc_state("AcmeSync"),
        _task_state("\\Vendor\\NightlyExport"),
        _role("Web-Server"),
    ]
    findings = _run(obs)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == FindingType.LIMITATION
    assert finding.evidence_class == EVIDENCE_UNKNOWN
    assert finding.details == {"kind": "no_history", "subject": "configured_unobserved"}
    assert _configured(findings) == []


def test_history_from_any_source_counts():
    # History is defined by category, not collector: an observation in a
    # historical category from any source enables dormancy analysis.
    journald_event = make_obs(
        Category.EVENT,
        source="journald",
        timestamp="2026-08-17T01:00:00Z",
        attributes={},
    )
    findings = _run([_svc_state("AcmeSync"), journald_event])
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.CONFIGURED_BUT_UNOBSERVED
    assert findings[0].details["name"] == "AcmeSync"
    # ...and matching activity from a non-eventlog source suppresses the item.
    suppressed = _run(
        [_svc_state("AcmeSync"), _svc_activity("AcmeSync", source="journald")]
    )
    assert suppressed == []


def test_stopped_auto_service_flagged():
    svc = _svc_state("AcmeSync")
    # Full-retention channel: the whole requested 3-day window is available.
    findings = _run([svc, _hist_event(), _channel()])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == FindingType.CONFIGURED_BUT_UNOBSERVED
    assert finding.evidence_class == EVIDENCE_CONFIGURED
    assert finding.details["kind"] == "service"
    assert finding.details["name"] == "AcmeSync"
    assert finding.details["configured_state"] == "auto-start, stopped"
    assert finding.details["window_days"] == 3.0
    assert "3.0-day available history" in finding.conclusion
    assert finding.supporting_observations == [svc.id]


def test_window_days_capped_by_evidence_retention():
    # Requested window is 3 days, but the only channel retains ~2 hours of
    # history: conclusions must quote ~0.1 days, never 3.0.
    recent_event = make_obs(
        Category.EVENT,
        source="eventlog",
        timestamp="2026-08-19T11:00:00Z",
        attributes={"channel": "System", "provider": "p", "event_id": 1, "level": None},
    )
    findings = _run(
        [_svc_state("AcmeSync"), recent_event, _channel(oldest="2026-08-19T10:05:00Z")]
    )
    assert len(findings) == 1
    assert findings[0].details["window_days"] == 0.1
    assert "0.1-day available history" in findings[0].conclusion
    assert "3.0-day" not in findings[0].conclusion


def test_stopped_manual_service_with_observed_start_not_flagged():
    # Counterexample: case-insensitive match against service field.
    obs = [
        _svc_state("MyBatchSvc", start_mode="manual"),
        _svc_activity("mybatchsvc"),
    ]
    assert _run(obs) == []


def test_service_matched_via_message_field_not_flagged():
    activity = make_obs(
        Category.PROCESS_ACTIVITY,
        source="eventlog",
        action="start",
        process="C:\\Windows\\System32\\svchost.exe",
        message="Started AcmeSync worker process",
        timestamp="2026-08-17T02:00:00Z",
        attributes={"channel": "Security", "provider": "s", "event_id": 4688, "level": None},
    )
    assert _run([_svc_state("AcmeSync"), activity]) == []


def test_service_activity_under_display_name_not_flagged():
    # Short-name state + display-name activity (wuauserv vs 'Windows Update')
    # must NOT produce a false "no related activity" claim.
    obs = [
        _svc_state("wuauserv", start_mode="manual", display_name="Windows Update"),
        _svc_activity("Windows Update"),
    ]
    assert _run(obs) == []


def test_display_name_matched_in_message_field_not_flagged():
    obs = [
        _svc_state("wuauserv", start_mode="manual", display_name="Windows Update"),
        _svc_activity(
            "some-other-svc",
            message="The WINDOWS UPDATE service entered the running state.",
        ),
    ]
    assert _run(obs) == []


def test_unrelated_activity_still_flags_service_with_display_name():
    # Counterexample: neither the short name nor the display name appears in
    # any activity — the service must still be flagged.
    obs = [
        _svc_state("wuauserv", display_name="Windows Update"),
        _svc_activity("CompletelyDifferentService"),
    ]
    findings = _run(obs)
    assert len(findings) == 1
    assert findings[0].details["name"] == "wuauserv"


def test_running_service_never_flagged():
    assert _run([_svc_state("AcmeSync", state="running"), _hist_event()]) == []


def test_disabled_service_not_flagged():
    assert _run([_svc_state("AcmeSync", start_mode="disabled"), _hist_event()]) == []


def test_enabled_task_never_run_flagged():
    task = _task_state("\\Vendor\\NightlyExport", last_run=None)
    findings = _run([task, _hist_event()])
    assert len(findings) == 1
    details = findings[0].details
    assert details["kind"] == "scheduled_action"
    assert details["name"] == "\\Vendor\\NightlyExport"
    assert details["configured_state"] == "enabled"
    assert details["note"] is not None


def test_enabled_task_recent_last_run_not_flagged():
    # Counterexample: last_run inside the window (since 2026-08-16T12:00Z).
    task = _task_state("\\Vendor\\NightlyExport", last_run="2026-08-18T00:00:00Z")
    assert _run([task, _hist_event()]) == []


def test_enabled_task_stale_last_run_flagged():
    task = _task_state("\\Vendor\\NightlyExport", last_run="2026-08-01T00:00:00Z")
    findings = _run([task, _hist_event()])
    assert len(findings) == 1
    assert findings[0].details["kind"] == "scheduled_action"


def test_task_with_observed_activity_not_flagged_exact_path():
    stale = "2026-08-01T00:00:00Z"
    # activity for the exact path suppresses the finding...
    obs = [
        _task_state("\\Vendor\\NightlyExport", last_run=stale),
        _sched_activity("\\Vendor\\NightlyExport"),
    ]
    assert _run(obs) == []
    # ...activity for a different path does not
    obs = [
        _task_state("\\Vendor\\NightlyExport", last_run=stale),
        _sched_activity("\\Vendor\\OtherTask"),
    ]
    findings = _run(obs)
    assert len(findings) == 1
    assert findings[0].details["name"] == "\\Vendor\\NightlyExport"


def test_disabled_task_not_flagged():
    obs = [_task_state("\\Vendor\\NightlyExport", enabled=False), _hist_event()]
    assert _run(obs) == []


def test_max_window_task_with_any_last_run_not_flagged():
    # --since max: a non-null last_run means "ran at some point" -> do not flag.
    manifest = make_manifest(requested_since="max", since_resolved=None)
    ran_once = _task_state("\\Vendor\\RanOnce", last_run="2020-01-01T00:00:00Z")
    never_ran = _task_state("\\Vendor\\NeverRan", last_run=None)
    findings = _run([ran_once, never_ran, _hist_event()], manifest=manifest)
    assert len(findings) == 1
    assert findings[0].details["name"] == "\\Vendor\\NeverRan"


def test_task_unparseable_last_run_not_flagged():
    # Malformed data: cannot compare against the window -> conservative skip.
    task = _task_state("\\Vendor\\NightlyExport", last_run="not-a-timestamp")
    assert _run([task, _hist_event()]) == []


def test_web_server_role_active_not_flagged():
    # Counterexample: Web-Server with w3svc running and :443 listening.
    obs = [
        _role("Web-Server"),
        _svc_state("W3SVC", state="running"),
        _listening(443),
        _hist_event(),
    ]
    assert _run(obs) == []


def test_web_server_role_with_only_port_or_only_activity_not_flagged():
    assert _run([_role("Web-Server"), _listening(8080), _hist_event()]) == []
    assert _run([_role("Web-Server"), _svc_activity("W3SVC")]) == []


def test_web_server_role_inactive_flagged():
    findings = _run([_role("Web-Server"), _hist_event()])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.details["kind"] == "role"
    assert finding.details["name"] == "Web-Server"
    assert finding.details["configured_state"] == "installed"
    assert finding.evidence_class == EVIDENCE_CONFIGURED


def test_print_server_not_flagged_when_spooler_runs():
    # spooler runs everywhere; it alone must suppress the Print-Server flag
    obs = [_role("Print-Server"), _svc_state("Spooler", state="running"), _hist_event()]
    assert _run(obs) == []


def test_print_server_flagged_without_spooler_or_print_ports():
    findings = _run([_role("Print-Server"), _hist_event()])
    assert len(findings) == 1
    assert findings[0].details["name"] == "Print-Server"


def test_unmapped_role_never_flagged():
    assert _run([_role("FileAndStorage-Services"), _hist_event()]) == []


def test_fs_dfs_prefix_role():
    active = [_role("FS-DFS-Namespace"), _svc_state("Dfs", state="running"), _hist_event()]
    assert _run(active) == []
    dormant = _run([_role("FS-DFS-Namespace"), _hist_event()])
    assert len(dormant) == 1
    assert dormant[0].details["name"] == "FS-DFS-Namespace"


def test_malformed_state_observations_skipped():
    obs = [
        make_obs(Category.SERVICE_STATE, source="services", action="configured"),  # no name
        make_obs(Category.SCHEDULED_TASK_STATE, source="scheduled_tasks"),  # no path/attrs
        make_obs(Category.INSTALLED_ROLE, source="software"),  # no attributes
        _hist_event(),
    ]
    assert _run(obs) == []


def test_cap_15_auto_first_then_name_with_omission_note():
    obs = [_hist_event()]
    for i in range(10):
        obs.append(_svc_state(f"auto-{i:02d}", start_mode="auto"))
    for i in range(10):
        obs.append(_svc_state(f"manual-{i:02d}", start_mode="manual"))
    findings = _run(obs)
    assert len(findings) == 15
    names = [f.details["name"] for f in findings]
    assert names[:10] == [f"auto-{i:02d}" for i in range(10)]
    assert names[10:] == [f"manual-{i:02d}" for i in range(5)]
    last = findings[-1]
    assert last.details["omitted"] == 5
    assert "omitted" in last.conclusion
    for finding in findings[:-1]:
        assert "omitted" not in finding.details


def test_deterministic_output():
    obs = [
        _hist_event(),
        _svc_state("ZetaSvc", start_mode="manual"),
        _svc_state("AlphaSvc", start_mode="auto"),
        _task_state("\\Vendor\\NightlyExport", last_run=None),
        _role("Web-Server"),
    ]
    first = [f.to_json_dict() for f in _run(obs)]
    second = [f.to_json_dict() for f in _run(obs)]
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    # ordering: auto service, then manual/task/role by name
    kinds = [(f["details"]["kind"], f["details"]["name"]) for f in first]
    assert kinds[0] == ("service", "AlphaSvc")
