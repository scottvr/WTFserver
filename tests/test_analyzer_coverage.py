"""Tests for the coverage analyzer (evidence_coverage + limitation findings)."""

from __future__ import annotations

import json
from typing import Any

from wtfserver.analyzers.coverage import ANALYZER, CoverageAnalyzer
from wtfserver.model import (
    EVIDENCE_OBSERVED,
    EVIDENCE_UNKNOWN,
    Category,
    FindingType,
)

from helpers import build_ctx, make_manifest, make_obs

# Manifest defaults (helpers.make_manifest): window 72h resolved to
# 2026-08-16T12:00:00Z, collection_end 2026-08-19T12:05:00Z.
WINDOW_START = "2026-08-16T12:00:00Z"


def chan(
    channel: str,
    enabled: bool = True,
    record_count: int = 100,
    oldest: str | None = "2026-08-10T00:00:00Z",
    newest: str | None = "2026-08-19T00:00:00Z",
    collected_events: int = 100,
    truncated: bool = False,
    error: str | None = None,
    **attr_overrides: Any,
):
    attrs: dict[str, Any] = {
        "channel": channel,
        "enabled": enabled,
        "record_count": record_count,
        "oldest_record": oldest,
        "newest_record": newest,
        "max_size_bytes": 20971520,
        "collected_events": collected_events,
        "truncated": truncated,
    }
    if error is not None:
        attrs["error"] = error
    attrs.update(attr_overrides)
    return make_obs(
        Category.EVIDENCE_CHANNEL,
        source="eventlog",
        action="inventoried",
        timestamp="2026-08-19T12:01:00Z",
        attributes=attrs,
    )


def hist_event(**kwargs: Any):
    defaults: dict[str, Any] = {
        "source": "eventlog",
        "timestamp": "2026-08-18T03:00:00Z",
        "attributes": {
            "channel": "System",
            "provider": "Service Control Manager",
            "event_id": 7036,
            "level": "Information",
        },
    }
    defaults.update(kwargs)
    return make_obs(Category.EVENT, **defaults)


def run(observations, manifest=None):
    ctx = build_ctx(observations, manifest=manifest)
    return ANALYZER.analyze(ctx)


def coverage_of(findings):
    matches = [f for f in findings if f.finding_type == FindingType.EVIDENCE_COVERAGE]
    assert len(matches) == 1
    return matches[0]


def limitations_of(findings, kind=None):
    out = [f for f in findings if f.finding_type == FindingType.LIMITATION]
    if kind is not None:
        out = [f for f in out if f.details.get("kind") == kind]
    return out


def test_analyzer_identity():
    assert isinstance(ANALYZER, CoverageAnalyzer)
    assert ANALYZER.name == "coverage"
    assert ANALYZER.required_categories == ()


def test_coverage_finding_shape():
    obs = [
        chan("Security", record_count=5000, collected_events=4000),
        chan(
            "Application",
            record_count=200,
            oldest="2026-08-17T00:00:00Z",
            newest="2026-08-19T00:00:00Z",
            collected_events=200,
        ),
        hist_event(),
    ]
    findings = run(obs)
    finding = coverage_of(findings)

    assert finding.evidence_class == EVIDENCE_OBSERVED
    details = finding.details
    assert details["window"] == {
        "requested": "72h",
        "resolved": WINDOW_START,
        "collection_end": "2026-08-19T12:05:00Z",
    }
    rows = details["channels"]
    # Sorted record_count desc.
    assert [r["channel"] for r in rows] == ["Security", "Application"]
    security = rows[0]
    assert security["enabled"] is True
    assert security["record_count"] == 5000
    assert security["oldest"] == "2026-08-10T00:00:00Z"
    assert security["newest"] == "2026-08-19T00:00:00Z"
    assert security["span_days"] == 9.0
    assert security["covers_window"] is True  # oldest precedes window start
    assert security["collected_events"] == 4000
    assert security["truncated"] is False
    assert security["error"] is None
    app = rows[1]
    assert app["span_days"] == 2.0
    assert app["covers_window"] is False  # oldest after window start
    assert details["total_span_days"] == 9.0
    assert details["channels_omitted"] == 0
    assert finding.supporting_observations  # channel obs ids


def test_channel_row_tie_break_name_asc():
    obs = [
        chan("Zeta", record_count=10),
        chan("Alpha", record_count=10),
    ]
    rows = coverage_of(run(obs)).details["channels"]
    assert [r["channel"] for r in rows] == ["Alpha", "Zeta"]


def test_uninteresting_empty_channel_excluded():
    obs = [
        chan("Security", record_count=500),
        # Enabled, zero records, no error: not worth a row.
        chan("Microsoft-Windows-Empty/Operational", record_count=0, oldest=None, newest=None),
        # Disabled empty channel IS worth a row.
        chan("Setup", enabled=False, record_count=0, oldest=None, newest=None),
    ]
    rows = coverage_of(run(obs)).details["channels"]
    names = [r["channel"] for r in rows]
    assert "Microsoft-Windows-Empty/Operational" not in names
    assert "Setup" in names
    assert "Security" in names


def test_covers_window_null_when_window_is_max():
    manifest = make_manifest(requested_since="max", since_resolved=None)
    obs = [chan("Security", record_count=100)]
    finding = coverage_of(run(obs, manifest=manifest))
    assert finding.details["window"]["resolved"] is None
    assert finding.details["channels"][0]["covers_window"] is None


def test_covers_window_null_when_oldest_unknown():
    obs = [chan("Security", record_count=100, oldest=None)]
    row = coverage_of(run(obs)).details["channels"][0]
    assert row["covers_window"] is None
    assert row["span_days"] is None


def test_channel_row_cap_and_supporting_cap():
    obs = [chan(f"Chan{i:03d}", record_count=100 + i) for i in range(55)]
    finding = coverage_of(run(obs))
    details = finding.details
    assert len(details["channels"]) == 40
    assert details["channels_omitted"] == 15
    assert len(finding.supporting_observations) == 50
    assert details["supporting_capped"] is True
    assert details["supporting_total"] == 55


def test_channel_disabled_limitation_for_interesting_channels_only():
    obs = [
        chan("Security", enabled=False, record_count=0, oldest=None, newest=None),
        chan(
            "Microsoft-Windows-TaskScheduler/Operational",
            enabled=False,
            record_count=0,
            oldest=None,
            newest=None,
        ),
        # Disabled but not in the interesting set: must NOT fire.
        chan(
            "Microsoft-Windows-Obscure/Operational",
            enabled=False,
            record_count=0,
            oldest=None,
            newest=None,
        ),
    ]
    lims = limitations_of(run(obs), kind="channel_disabled")
    subjects = [f.details["subject"] for f in lims]
    assert subjects == ["Microsoft-Windows-TaskScheduler/Operational", "Security"]
    for f in lims:
        assert f.evidence_class == EVIDENCE_UNKNOWN


def test_channel_disabled_not_fired_when_enabled():
    obs = [chan("Security", enabled=True, record_count=100)]
    assert limitations_of(run(obs), kind="channel_disabled") == []


def test_retention_short_fired_and_counterexample():
    obs = [
        # Oldest record after window start: retention shortfall.
        chan("Application", record_count=50, oldest="2026-08-18T00:00:00Z"),
        # Oldest before window start: fine.
        chan("Security", record_count=50, oldest="2026-08-01T00:00:00Z"),
    ]
    lims = limitations_of(run(obs), kind="retention_short")
    assert [f.details["subject"] for f in lims] == ["Application"]
    # Negative phrasing must stay scoped to the window.
    assert "72h" in lims[0].conclusion


def test_retention_short_not_fired_for_max_window():
    manifest = make_manifest(requested_since="max", since_resolved=None)
    obs = [chan("Application", record_count=50, oldest="2026-08-18T00:00:00Z")]
    assert limitations_of(run(obs, manifest=manifest), kind="retention_short") == []


def test_truncated_limitation_and_counterexample():
    obs = [
        chan("Security", record_count=90000, truncated=True),
        chan("System", record_count=100, truncated=False),
    ]
    lims = limitations_of(run(obs), kind="truncated")
    assert [f.details["subject"] for f in lims] == ["Security"]


def test_collector_error_limitations_from_manifest():
    manifest = make_manifest(
        collectors=[
            {"name": "eventlog", "status": "ok", "observation_count": 10},
            {
                "name": "services",
                "status": "partial",
                "observation_count": 5,
                "errors": ["access denied on one service"],
            },
            {
                "name": "network",
                "status": "failed",
                "observation_count": 0,
                "errors": ["PowerShellError: boom"],
            },
        ]
    )
    lims = limitations_of(run([chan("Security")], manifest=manifest), kind="collector_error")
    subjects = [f.details["subject"] for f in lims]
    assert subjects == ["services", "network"]  # manifest order, ok skipped
    assert "boom" in lims[1].conclusion


def test_no_process_auditing_fired_when_history_lacks_security_starts():
    obs = [
        chan("Security", record_count=100),
        hist_event(),  # history exists but no process_activity from Security
        # A process start from another channel does not count as auditing.
        make_obs(
            Category.PROCESS_ACTIVITY,
            source="eventlog",
            action="start",
            timestamp="2026-08-18T04:00:00Z",
            process="C:\\Tools\\thing.exe",
            attributes={
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "provider": "Sysmon",
                "event_id": 1,
                "level": None,
            },
        ),
    ]
    lims = limitations_of(run(obs), kind="no_process_auditing")
    assert len(lims) == 1


def test_no_process_auditing_not_fired_with_security_starts():
    obs = [
        chan("Security", record_count=100),
        make_obs(
            Category.PROCESS_ACTIVITY,
            source="eventlog",
            action="start",
            timestamp="2026-08-18T04:00:00Z",
            process="C:\\Windows\\System32\\cmd.exe",
            attributes={
                "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "event_id": 4688,
                "level": None,
            },
        ),
    ]
    assert limitations_of(run(obs), kind="no_process_auditing") == []


def test_no_process_auditing_not_fired_without_any_history():
    # No historical observations at all -> no_history instead.
    obs = [chan("Security", record_count=100)]
    findings = run(obs)
    assert limitations_of(findings, kind="no_process_auditing") == []
    assert len(limitations_of(findings, kind="no_history")) == 1


def test_no_security_log_absent_error_and_empty():
    # Absent from inventory.
    findings = run([chan("System", record_count=10), hist_event()])
    lims = limitations_of(findings, kind="no_security_log")
    assert len(lims) == 1
    assert lims[0].details["subject"] == "Security"

    # Present but unreadable.
    findings = run(
        [chan("Security", record_count=100, error="access denied"), hist_event()]
    )
    lims = limitations_of(findings, kind="no_security_log")
    assert len(lims) == 1
    assert "access denied" in lims[0].conclusion

    # Present but zero records.
    findings = run(
        [chan("Security", record_count=0, oldest=None, newest=None), hist_event()]
    )
    assert len(limitations_of(findings, kind="no_security_log")) == 1


def test_no_security_log_not_fired_when_healthy():
    findings = run([chan("Security", record_count=100), hist_event()])
    assert limitations_of(findings, kind="no_security_log") == []


def test_no_history_counterexample():
    findings = run([chan("Security", record_count=100), hist_event()])
    assert limitations_of(findings, kind="no_history") == []


def test_empty_bundle_still_reports_coverage():
    findings = run([])
    finding = coverage_of(findings)
    assert finding.details["channels"] == []
    assert finding.details["total_span_days"] is None
    assert finding.details["channels_omitted"] == 0
    kinds = {f.details["kind"] for f in limitations_of(findings)}
    assert "no_history" in kinds
    assert "no_security_log" in kinds


def test_malformed_channel_attributes_do_not_crash():
    weird = make_obs(
        Category.EVIDENCE_CHANNEL,
        source="eventlog",
        action="inventoried",
        timestamp="2026-08-19T12:01:00Z",
        attributes={
            "channel": "Weird",
            "enabled": False,
            "record_count": "not-an-int",
            "oldest_record": "garbage-timestamp",
            "newest_record": 12345,
            "collected_events": None,
            "truncated": "yes-ish",
        },
    )
    missing_attrs = make_obs(
        Category.EVIDENCE_CHANNEL,
        source="eventlog",
        action="inventoried",
        timestamp="2026-08-19T12:01:00Z",
        attributes={},
    )
    findings = run([weird, missing_attrs, chan("Security", record_count=10)])
    rows = coverage_of(findings).details["channels"]
    weird_row = next(r for r in rows if r["channel"] == "Weird")
    assert weird_row["record_count"] == 0
    assert weird_row["span_days"] is None
    assert weird_row["covers_window"] is None
    # Everything must survive json serialization.
    json.dumps([f.to_json_dict() for f in findings])


def test_determinism_identical_output():
    obs = [
        chan("Security", record_count=5000, truncated=True),
        chan("Application", record_count=200, oldest="2026-08-18T00:00:00Z"),
        chan(
            "Microsoft-Windows-PowerShell/Operational",
            enabled=False,
            record_count=0,
            oldest=None,
            newest=None,
        ),
        hist_event(),
    ]
    manifest = make_manifest(
        collectors=[{"name": "software", "status": "failed", "errors": ["nope"]}]
    )
    first = [f.to_json_dict() for f in run(list(obs), manifest=dict(manifest))]
    second = [f.to_json_dict() for f in run(list(obs), manifest=dict(manifest))]
    assert json.dumps(first) == json.dumps(second)
