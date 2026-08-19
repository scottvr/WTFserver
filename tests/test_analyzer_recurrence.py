"""Tests for the recurrence analyzer (recurring_scheduled_activity)."""

from datetime import datetime, timedelta, timezone

from helpers import build_ctx, make_obs

from wtfserver.analyzers.recurrence import ANALYZER, RecurrenceAnalyzer
from wtfserver.model import EVIDENCE_OBSERVED, Category, FindingType

TASK = "\\Vendor\\NightlyExport"
BASE = datetime(2026, 7, 20, 1, 0, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def nightly_observations(days: int = 21):
    """days nightly runs at 01:00 UTC +/- <=2 min jitter (median jitter 0)."""
    jitter = [0, 90, -90]  # seconds; cycles to a median of 0
    obs = []
    for i in range(days):
        start_at = BASE + timedelta(days=i, seconds=jitter[i % 3])
        obs.append(
            make_obs(
                Category.SCHEDULED_ACTIVITY,
                timestamp=iso(start_at),
                action="start",
                scheduled_action=TASK,
            )
        )
        obs.append(
            make_obs(
                Category.SCHEDULED_ACTIVITY,
                timestamp=iso(start_at + timedelta(seconds=2)),
                action="action_start",
                scheduled_action=TASK,
                principal="SVC\\svc_export",
                process="C:\\Vendor\\export.exe",
            )
        )
    return obs


def run(observations):
    return ANALYZER.analyze(build_ctx(observations))


def test_analyzer_shape():
    assert ANALYZER.name == "recurrence"
    assert isinstance(ANALYZER, RecurrenceAnalyzer)
    assert Category.SCHEDULED_ACTIVITY in ANALYZER.required_categories


def test_canonical_nightly_task():
    findings = run(nightly_observations())
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == FindingType.RECURRING_SCHEDULED_ACTIVITY
    assert f.analyzer == "recurrence"
    assert f.evidence_class == EVIDENCE_OBSERVED
    d = f.details
    assert d["scheduled_action"] == TASK
    assert d["count"] == 21
    assert d["cadence"] == "daily"
    assert d["typical_time"] == "01:00"
    assert 82800 <= d["interval_seconds"] <= 90000
    assert d["jitter_seconds"] <= 240
    assert d["principal"] == "SVC\\svc_export"
    assert d["process"] == "C:\\Vendor\\export.exe"
    assert d["failure_count"] == 0
    assert d["first"] == iso(BASE)
    # day 20 falls on the -90 s jitter step
    assert d["last"] == iso(BASE + timedelta(days=20, seconds=-90))
    # supporting observations are the start observation IDs
    assert len(f.supporting_observations) == 21
    assert "supporting_capped" not in d
    assert TASK in f.conclusion
    assert "21" in f.conclusion


def test_two_starts_do_not_fire():
    obs = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp=iso(BASE + timedelta(days=i)),
            action="start",
            scheduled_action=TASK,
        )
        for i in range(2)
    ]
    assert run(obs) == []


def test_non_start_actions_do_not_count_toward_threshold():
    obs = []
    for i in range(5):
        obs.append(
            make_obs(
                Category.SCHEDULED_ACTIVITY,
                timestamp=iso(BASE + timedelta(days=i)),
                action="complete",
                scheduled_action=TASK,
            )
        )
    assert run(obs) == []


def test_irregular_gaps():
    offsets = [0, 1000, 51000, 54000, 174000]  # gaps 1000/50000/3000/120000 s
    obs = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp=iso(BASE + timedelta(seconds=s)),
            action="start",
            scheduled_action=TASK,
        )
        for s in offsets
    ]
    findings = run(obs)
    assert len(findings) == 1
    d = findings[0].details
    assert d["cadence"] == "irregular"
    assert d["typical_time"] is None


def test_hourly_cadence():
    obs = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp=iso(BASE + timedelta(hours=i)),
            action="start",
            scheduled_action=TASK,
        )
        for i in range(6)
    ]
    findings = run(obs)
    assert len(findings) == 1
    d = findings[0].details
    assert d["cadence"] == "hourly"
    assert d["typical_time"] is None
    assert d["interval_seconds"] == 3600.0


def test_stable_interval_cadence():
    obs = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp=iso(BASE + timedelta(seconds=300 * i)),
            action="start",
            scheduled_action=TASK,
        )
        for i in range(5)
    ]
    findings = run(obs)
    assert findings[0].details["cadence"] == "interval"
    assert findings[0].details["jitter_seconds"] == 0.0


def test_weekdays_cadence():
    obs = []
    day = BASE
    added = 0
    while added < 15:
        if day.weekday() < 5:  # Mon-Fri only
            obs.append(
                make_obs(
                    Category.SCHEDULED_ACTIVITY,
                    timestamp=iso(day),
                    action="start",
                    scheduled_action=TASK,
                )
            )
            added += 1
        day += timedelta(days=1)
    findings = run(obs)
    assert len(findings) == 1
    d = findings[0].details
    assert d["cadence"] == "weekdays"
    assert d["typical_time"] == "01:00"


def test_failure_count():
    obs = nightly_observations(days=5)
    obs.append(
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp=iso(BASE + timedelta(days=2, hours=1)),
            action="failed",
            scheduled_action=TASK,
        )
    )
    findings = run(obs)
    assert findings[0].details["failure_count"] == 1
    assert "1 failed run" in findings[0].conclusion


def test_missing_or_malformed_timestamps_are_skipped():
    obs = nightly_observations(days=3)
    obs.append(
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp=None,
            action="start",
            scheduled_action=TASK,
        )
    )
    obs.append(
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp="not-a-timestamp",
            action="start",
            scheduled_action=TASK,
        )
    )
    findings = run(obs)
    assert len(findings) == 1
    assert findings[0].details["count"] == 3

    # A task with only invalid timestamps never reaches the threshold.
    bad = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp="garbage",
            action="start",
            scheduled_action="\\Other\\Task",
        )
        for _ in range(4)
    ]
    assert run(bad) == []


def test_missing_scheduled_action_does_not_crash():
    obs = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp=iso(BASE + timedelta(days=i)),
            action="start",
            scheduled_action=None,
        )
        for i in range(4)
    ]
    assert run(obs) == []


def test_supporting_cap_at_50():
    obs = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp=iso(BASE + timedelta(hours=i)),
            action="start",
            scheduled_action=TASK,
        )
        for i in range(60)
    ]
    findings = run(obs)
    f = findings[0]
    assert len(f.supporting_observations) == 50
    assert f.details["supporting_capped"] is True
    assert f.details["supporting_total"] == 60


def test_process_fallback_from_task_state():
    obs = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp=iso(BASE + timedelta(days=i)),
            action="start",
            scheduled_action=TASK,
        )
        for i in range(3)
    ]
    obs.append(
        make_obs(
            Category.SCHEDULED_TASK_STATE,
            timestamp=iso(BASE + timedelta(days=3)),
            action="configured",
            scheduled_action=TASK,
            process="C:\\Vendor\\export.exe",
        )
    )
    findings = run(obs)
    assert findings[0].details["process"] == "C:\\Vendor\\export.exe"


def test_multiple_tasks_sorted_by_count_then_name():
    obs = nightly_observations(days=5)
    for i in range(5):
        obs.append(
            make_obs(
                Category.SCHEDULED_ACTIVITY,
                timestamp=iso(BASE + timedelta(days=i, hours=3)),
                action="start",
                scheduled_action="\\Aardvark\\Job",
            )
        )
    findings = run(obs)
    assert [f.details["scheduled_action"] for f in findings] == [
        "\\Aardvark\\Job",
        TASK,
    ]


def test_deterministic_output():
    obs = nightly_observations()
    first = [f.to_json_dict() for f in run(obs)]
    second = [f.to_json_dict() for f in run(obs)]
    assert first == second
