"""Tests for the correlation analyzer (activity_episode)."""

from datetime import datetime, timedelta, timezone

from helpers import build_ctx, make_obs

from wtfserver.analyzers.correlation import ANALYZER, CorrelationAnalyzer
from wtfserver.model import EVIDENCE_OBSERVED, Category, FindingType

TASK = "\\Vendor\\NightlyExport"
BASE = datetime(2026, 7, 20, 1, 0, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def nightly_episode_observations(days: int = 21, noise_days: tuple = ()):
    """Nightly task start with logon + action_start + db peer in its window."""
    obs = []
    for i in range(days):
        t0 = BASE + timedelta(days=i)
        obs.append(
            make_obs(
                Category.SCHEDULED_ACTIVITY,
                timestamp=iso(t0),
                action="start",
                scheduled_action=TASK,
            )
        )
        obs.append(
            make_obs(
                Category.LOGON,
                timestamp=iso(t0 + timedelta(seconds=1)),
                action="logon",
                principal="SVC\\svc_export",
                attributes={"logon_kind": "batch"},
            )
        )
        obs.append(
            make_obs(
                Category.SCHEDULED_ACTIVITY,
                timestamp=iso(t0 + timedelta(seconds=2)),
                action="action_start",
                scheduled_action=TASK,
                process="C:\\Vendor\\export.exe",
            )
        )
        obs.append(
            make_obs(
                Category.SOCKET_STATE,
                timestamp=iso(t0 + timedelta(seconds=4)),
                action="established",
                remote_host="db01",
                remote_port=1433,
                process="export.exe",
            )
        )
        if i in noise_days:
            obs.append(
                make_obs(
                    Category.PROCESS_ACTIVITY,
                    timestamp=iso(t0 + timedelta(seconds=10)),
                    action="start",
                    process=f"C:\\Windows\\noise{i}.exe",
                )
            )
    return obs


def run(observations, options=None):
    return ANALYZER.analyze(build_ctx(observations, options=options))


def task_episodes(findings):
    return [
        f
        for f in findings
        if f.details["anchor"]["category"] == Category.SCHEDULED_ACTIVITY
    ]


def test_analyzer_shape():
    assert ANALYZER.name == "correlation"
    assert isinstance(ANALYZER, CorrelationAnalyzer)


def test_canonical_nightly_episode():
    findings = run(nightly_episode_observations())
    episodes = task_episodes(findings)
    assert len(episodes) == 1
    f = episodes[0]
    assert f.finding_type == FindingType.ACTIVITY_EPISODE
    assert f.analyzer == "correlation"
    assert f.evidence_class == EVIDENCE_OBSERVED
    d = f.details
    assert d["anchor"] == {
        "category": Category.SCHEDULED_ACTIVITY,
        "action": "start",
        "name": TASK,
    }
    assert d["occurrences"] == 21
    assert d["first"] == iso(BASE)
    assert d["last"] == iso(BASE + timedelta(days=20))
    seq = d["typical_sequence"]
    assert [(s["category"], s["action"], s["name"]) for s in seq] == [
        (Category.LOGON, "logon", "SVC\\svc_export"),
        (Category.SCHEDULED_ACTIVITY, "action_start", "export.exe"),
        (Category.SOCKET_STATE, "established", "db01:1433"),
    ]
    assert [s["typical_offset_seconds"] for s in seq] == [1.0, 2.0, 4.0]
    assert all(s["seen_in"] == 21 for s in seq)
    # supporting: 21 anchors + 3 member examples, under the cap
    assert len(f.supporting_observations) == 24
    assert "supporting_capped" not in d

    # The batch logon is itself an anchor and yields its own episode; the
    # contract has no cross-anchor dedupe.
    logon_anchored = [
        f for f in findings if f.details["anchor"]["category"] == Category.LOGON
    ]
    assert len(logon_anchored) == 1
    assert logon_anchored[0].details["anchor"]["name"] == "SVC\\svc_export"


def test_two_occurrences_do_not_fire():
    findings = run(nightly_episode_observations(days=2))
    assert findings == []


def test_noise_below_half_presence_is_excluded():
    findings = run(nightly_episode_observations(days=21, noise_days=(0, 3, 7, 11, 15)))
    episodes = task_episodes(findings)
    assert len(episodes) == 1
    seq = episodes[0].details["typical_sequence"]
    assert episodes[0].details["occurrences"] == 21
    names = [s["name"] for s in seq]
    assert not any(n.startswith("noise") for n in names)
    assert names == ["SVC\\svc_export", "export.exe", "db01:1433"]


def test_different_anchors_do_not_merge():
    obs = []
    for i in range(3):
        t0 = BASE + timedelta(days=i)
        obs.append(
            make_obs(
                Category.SCHEDULED_ACTIVITY,
                timestamp=iso(t0),
                action="start",
                scheduled_action="\\A\\TaskA",
            )
        )
        obs.append(
            make_obs(
                Category.PROCESS_ACTIVITY,
                timestamp=iso(t0 + timedelta(seconds=3)),
                action="start",
                process="C:\\bin\\a.exe",
            )
        )
        # hours later: an unrelated service start with its own member
        t1 = t0 + timedelta(hours=6)
        obs.append(
            make_obs(
                Category.SERVICE_ACTIVITY,
                timestamp=iso(t1),
                action="start",
                service="SvcB",
            )
        )
        obs.append(
            make_obs(
                Category.PROCESS_ACTIVITY,
                timestamp=iso(t1 + timedelta(seconds=3)),
                action="start",
                process="C:\\bin\\b.exe",
            )
        )
    findings = run(obs)
    assert len(findings) == 2
    by_anchor = {f.details["anchor"]["name"]: f for f in findings}
    assert set(by_anchor) == {"\\A\\TaskA", "SvcB"}
    assert [s["name"] for s in by_anchor["\\A\\TaskA"].details["typical_sequence"]] == [
        "a.exe"
    ]
    assert [s["name"] for s in by_anchor["SvcB"].details["typical_sequence"]] == [
        "b.exe"
    ]


def test_dissimilar_member_sets_split_into_clusters():
    obs = []
    # 3 occurrences with member x.exe, then 2 with a disjoint member set
    for i in range(5):
        t0 = BASE + timedelta(days=i)
        member = "C:\\bin\\x.exe" if i < 3 else "C:\\bin\\y.exe"
        obs.append(
            make_obs(
                Category.SCHEDULED_ACTIVITY,
                timestamp=iso(t0),
                action="start",
                scheduled_action=TASK,
            )
        )
        obs.append(
            make_obs(
                Category.PROCESS_ACTIVITY,
                timestamp=iso(t0 + timedelta(seconds=3)),
                action="start",
                process=member,
            )
        )
    findings = run(obs)
    assert len(findings) == 1
    d = findings[0].details
    assert d["occurrences"] == 3
    assert [s["name"] for s in d["typical_sequence"]] == ["x.exe"]


def test_members_only_anchor_is_not_an_episode():
    obs = [
        make_obs(
            Category.SCHEDULED_ACTIVITY,
            timestamp=iso(BASE + timedelta(days=i)),
            action="start",
            scheduled_action=TASK,
        )
        for i in range(5)
    ]
    assert run(obs) == []


def test_anchor_identical_events_are_not_members():
    # Same task started twice 60 s apart, three days running. The second
    # start must not count as a member of the first (and vice versa), so the
    # member sets stay empty and nothing is emitted.
    obs = []
    for i in range(3):
        t0 = BASE + timedelta(days=i)
        for offset in (0, 60):
            obs.append(
                make_obs(
                    Category.SCHEDULED_ACTIVITY,
                    timestamp=iso(t0 + timedelta(seconds=offset)),
                    action="start",
                    scheduled_action=TASK,
                )
            )
    assert run(obs) == []


def test_network_logons_are_not_anchors():
    obs = []
    for i in range(5):
        t0 = BASE + timedelta(days=i)
        obs.append(
            make_obs(
                Category.LOGON,
                timestamp=iso(t0),
                action="logon",
                principal="SVC\\noise",
                attributes={"logon_kind": "network"},
            )
        )
        obs.append(
            make_obs(
                Category.PROCESS_ACTIVITY,
                timestamp=iso(t0 + timedelta(seconds=2)),
                action="start",
                process="C:\\bin\\x.exe",
            )
        )
    assert run(obs) == []


def test_missing_or_malformed_timestamps_are_skipped():
    obs = nightly_episode_observations(days=3)
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
    episodes = task_episodes(findings)
    assert len(episodes) == 1
    assert episodes[0].details["occurrences"] == 3


def test_window_options_are_respected():
    # With a 2-second window the peer at +4 s falls outside every occurrence.
    findings = run(
        nightly_episode_observations(days=5),
        options={"correlation_after": 2},
    )
    episodes = task_episodes(findings)
    assert len(episodes) == 1
    names = [s["name"] for s in episodes[0].details["typical_sequence"]]
    assert "db01:1433" not in names
    assert "export.exe" in names


def test_supporting_cap():
    findings = run(nightly_episode_observations(days=60))
    episodes = task_episodes(findings)
    f = episodes[0]
    assert len(f.supporting_observations) == 50
    assert f.details["supporting_capped"] is True
    assert f.details["supporting_total"] == 63  # 60 anchors + 3 member examples
    # member examples are preserved despite the cap
    member_ids = f.supporting_observations[-3:]
    assert len(set(member_ids)) == 3


def test_deterministic_output():
    obs = nightly_episode_observations(days=7, noise_days=(1, 4))
    first = [f.to_json_dict() for f in run(obs)]
    second = [f.to_json_dict() for f in run(obs)]
    assert first == second
