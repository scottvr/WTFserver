"""Regression tests over the three validation-experiment archetype bundles.

Each archetype from docs/WTFServer_First_Build.md section 17 (batch01 /
web01 / idle01, built deterministically in tests/synth.py) is written as a
DIRECTORY bundle, loaded through the real ``Bundle.load`` path, analyzed with
``run_analysis``, and checked against the operational portrait an engineer
should be able to reconstruct — plus over-inference guards (Microsoft
maintenance tasks must never produce a batch role, a current-only connection
pool must never be HIGH-confidence db-client evidence, and so on).
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from wtfserver.analysis import run_analysis
from wtfserver.bundle import Bundle
from wtfserver.model import Category, FindingType
from wtfserver.report.text import render_text

from synth import (
    BUILDERS,
    DEFENDER_TASK,
    VENDOR_TASK,
    write_directory_bundle,
)

ARCHETYPES = ("batch01", "web01", "idle01")


def _build_artifacts(tmp_path_factory, name: str) -> SimpleNamespace:
    root = tmp_path_factory.mktemp(f"synth_{name}")
    manifest, observations = BUILDERS[name]()
    bundle_dir = write_directory_bundle(root / name, manifest, observations)
    bundle = Bundle.load(bundle_dir)
    result = run_analysis(bundle)
    return SimpleNamespace(
        name=name,
        path=bundle_dir,
        bundle=bundle,
        result=result,
        text=render_text(result),
    )


@pytest.fixture(scope="module")
def batch01(tmp_path_factory):
    return _build_artifacts(tmp_path_factory, "batch01")


@pytest.fixture(scope="module")
def web01(tmp_path_factory):
    return _build_artifacts(tmp_path_factory, "web01")


@pytest.fixture(scope="module")
def idle01(tmp_path_factory):
    return _build_artifacts(tmp_path_factory, "idle01")


def _roles_by_rule(result) -> dict:
    roles: dict[str, list] = {}
    for finding in result.of_type(FindingType.ROLE_INFERENCE):
        roles.setdefault(finding.rule_id, []).append(finding)
    return roles


def _serialize(result) -> str:
    return json.dumps(
        [f.to_json_dict() for f in result.findings], sort_keys=True
    )


# --- shared expectations for all three archetypes -------------------------


@pytest.mark.parametrize("name", ARCHETYPES)
def test_bundle_round_trips_as_directory_bundle(name, request):
    art = request.getfixturevalue(name)
    assert art.bundle.manifest["schema_version"] == 1
    assert art.bundle.manifest["bundle_format"] == "wtf-bundle"
    ids = [obs.id for obs in art.bundle.observations]
    assert ids == [f"obs-{i:06d}" for i in range(1, len(ids) + 1)]
    assert art.bundle.manifest["observation_count"] == len(ids)


@pytest.mark.parametrize("name", ARCHETYPES)
def test_bundle_contains_required_evidence_shapes(name, request):
    # Every archetype must look like a real collection: channel inventory,
    # one host identity, configured services, generic event clutter, and the
    # stock Microsoft maintenance scheduled activity (Defender scan).
    art = request.getfixturevalue(name)
    by_cat: dict[str, int] = {}
    for obs in art.bundle.observations:
        by_cat[obs.category] = by_cat.get(obs.category, 0) + 1
    assert by_cat.get(Category.EVIDENCE_CHANNEL, 0) >= 4
    assert by_cat.get(Category.HOST_IDENTITY, 0) == 1
    assert by_cat.get(Category.SERVICE_STATE, 0) >= 5
    assert by_cat.get(Category.EVENT, 0) >= 5  # realistic noise
    maintenance = {
        obs.scheduled_action
        for obs in art.bundle.observations
        if obs.category == Category.SCHEDULED_ACTIVITY and obs.scheduled_action
    }
    assert DEFENDER_TASK in maintenance


@pytest.mark.parametrize("name", ARCHETYPES)
def test_analysis_is_deterministic(name, request):
    art = request.getfixturevalue(name)
    first = run_analysis(Bundle.load(art.path))
    second = run_analysis(Bundle.load(art.path))
    assert _serialize(first) == _serialize(second)
    assert _serialize(first) == _serialize(art.result)
    assert render_text(first) == art.text


@pytest.mark.parametrize("name", ARCHETYPES)
def test_no_analyzer_failed_limitations(name, request):
    art = request.getfixturevalue(name)
    failed = [
        f
        for f in art.result.of_type(FindingType.LIMITATION)
        if (f.details or {}).get("kind") == "analyzer_failed"
    ]
    assert failed == []
    assert re.search(r"Analyzer '[^']+' failed", art.text) is None


# --- batch01: nightly integration host ------------------------------------


def test_batch01_batch_role_high_naming_vendor_task(batch01):
    roles = _roles_by_rule(batch01.result)
    assert "role.batch.v1" in roles
    (finding,) = roles["role.batch.v1"]
    assert finding.confidence == "HIGH"
    assert finding.details["role"] == "batch/scheduled processing host"
    assert "NightlyExport" in finding.conclusion
    summary = finding.details["evidence_summary"]
    assert any(VENDOR_TASK in line for line in summary)
    # The stock Microsoft maintenance recurrence must not leak into the role.
    assert not any("Microsoft" in line for line in summary)
    assert "batch/scheduled processing host" in batch01.text
    assert "NightlyExport" in batch01.text


def test_batch01_db_client_and_transfer_client_roles(batch01):
    roles = _roles_by_rule(batch01.result)
    (db,) = roles["role.db_client.v1"]
    assert db.details["role"] == "database client (talks to 10.20.30.40:1433)"
    # Historical vendor events plus the live agent socket = evidence "both".
    assert db.confidence == "HIGH"
    (transfer,) = roles["role.transfer_client.v1"]
    assert (
        transfer.details["role"]
        == "outbound file-transfer/messaging client (ssh/sftp to sftp.vendor.example)"
    )


def test_batch01_vendor_recurrence_21_nightly_runs(batch01):
    recurrences = {
        f.details["scheduled_action"]: f
        for f in batch01.result.of_type(FindingType.RECURRING_SCHEDULED_ACTIVITY)
    }
    vendor = recurrences[VENDOR_TASK]
    assert vendor.details["count"] == 21
    assert vendor.details["cadence"] == "daily"
    assert vendor.details["principal"] == "CORP\\svc_batch"
    assert vendor.details["process"] == "D:\\Vendor\\export.exe"
    assert vendor.details["failure_count"] == 0
    # The stock maintenance task also recurs — that is the point of including
    # it — it just must not shape the role (asserted above).
    assert recurrences[DEFENDER_TASK].details["cadence"] == "daily"


def test_batch01_episode_logon_then_task_then_process(batch01):
    episodes = [
        f
        for f in batch01.result.of_type(FindingType.ACTIVITY_EPISODE)
        if f.details["anchor"]
        == {"category": "scheduled_activity", "action": "start", "name": VENDOR_TASK}
    ]
    assert len(episodes) == 1
    episode = episodes[0]
    assert episode.details["occurrences"] == 21
    sequence = episode.details["typical_sequence"]
    kinds = [(s["category"], s["action"], s["name"]) for s in sequence]
    logon_idx = kinds.index(("logon", "logon", "CORP\\svc_batch"))
    process_idx = kinds.index(("scheduled_activity", "action_start", "export.exe"))
    # Service-account logon precedes the task's process launch every night.
    assert logon_idx < process_idx
    assert sequence[logon_idx]["typical_offset_seconds"] < 0
    assert sequence[process_idx]["typical_offset_seconds"] > 0
    assert sequence[logon_idx]["seen_in"] == 21


def test_batch01_dormant_iis_configured_but_unobserved(batch01):
    names = {
        f.details["name"]
        for f in batch01.result.of_type(FindingType.CONFIGURED_BUT_UNOBSERVED)
    }
    assert "W3SVC" in names
    assert "Web-Server" in names
    assert "CONFIGURED BUT NOT OBSERVED" in batch01.text


def test_batch01_interactive_dedupe_counts_two_rdp_sessions(batch01):
    (interactive,) = batch01.result.of_type(FindingType.INTERACTIVE_USE)
    # Each RDP session is recorded by BOTH the audit log and the session
    # manager log (4 raw observations); the counting rule must yield 2.
    assert interactive.details["remote_interactive_logons"] == 2
    assert interactive.details["classification"] == "batch_scheduled"
    assert interactive.details["batch_logons"] == 21


def test_batch01_no_web_server_role(batch01):
    # IIS is installed but W3SVC is stopped and nothing listens on a web
    # port: a web-server inference here would be over-inference.
    assert "role.web_server.v1" not in _roles_by_rule(batch01.result)


# --- web01: web/application server ----------------------------------------


def test_web01_web_server_role(web01):
    roles = _roles_by_rule(web01.result)
    (web,) = roles["role.web_server.v1"]
    assert web.details["role"] == "web server"
    # Listener on 80/443 plus running W3SVC: the strongest form of the rule.
    assert web.confidence == "HIGH"
    assert "web server" in web01.text


def test_web01_db_client_at_most_medium_for_current_only_pool(web01):
    (db,) = _roles_by_rule(web01.result)["role.db_client.v1"]
    assert db.details["role"] == "database client (talks to 10.20.30.41:1433)"
    # 4 simultaneous sockets in one snapshot is a connection pool, not
    # repetition over time — must never reach HIGH.
    assert db.confidence in ("MEDIUM", "LOW")


def test_web01_no_batch_role_despite_microsoft_maintenance(web01):
    recurrences = [
        f.details["scheduled_action"]
        for f in web01.result.of_type(FindingType.RECURRING_SCHEDULED_ACTIVITY)
    ]
    # The stock Defender scan DOES recur daily on this host...
    assert recurrences == [DEFENDER_TASK]
    # ...but a built-in OS maintenance task is not a batch-processing purpose.
    assert "role.batch.v1" not in _roles_by_rule(web01.result)


def test_web01_not_quiet(web01):
    assert "role.quiet.v1" not in _roles_by_rule(web01.result)
    (interactive,) = web01.result.of_type(FindingType.INTERACTIVE_USE)
    assert interactive.details["classification"] != "apparently_quiet"
    # 3 RDP sessions (each double-recorded) stay below the interactive
    # classification threshold of 5.
    assert interactive.details["remote_interactive_logons"] == 3


# --- idle01: mostly-idle administration box --------------------------------


def test_idle01_no_business_roles(idle01):
    roles = _roles_by_rule(idle01.result)
    assert "role.batch.v1" not in roles
    assert "role.db_client.v1" not in roles
    assert "role.db_server.v1" not in roles
    assert "role.web_server.v1" not in roles
    assert "role.transfer_client.v1" not in roles


def test_idle01_remote_interactive_count_is_four(idle01):
    (interactive,) = idle01.result.of_type(FindingType.INTERACTIVE_USE)
    # 4 sessions x 2 evidence sources = 8 raw records; dedupe yields 4.
    assert interactive.details["remote_interactive_logons"] == 4
    principals = dict(
        (name, count) for name, count in interactive.details["interactive_principals"]
    )
    assert principals == {"CORP\\ajones": 2, "CORP\\rpatel": 2}


def test_idle01_configured_but_unobserved_nonempty(idle01):
    findings = idle01.result.of_type(FindingType.CONFIGURED_BUT_UNOBSERVED)
    assert findings
    names = {f.details["name"] for f in findings}
    assert {"CobianBackup11", "Spooler", "RemoteRegistry", "SNMPTRAP"} <= names


def test_idle01_negative_conclusions_name_the_window(idle01):
    # Negative-evidence discipline: every "nothing was observed" style
    # conclusion must be scoped to an N-day window, never absolute.
    window_re = re.compile(r"\d+(\.\d+)?-day")
    negatives = list(idle01.result.of_type(FindingType.CONFIGURED_BUT_UNOBSERVED))
    negatives += idle01.result.of_type(FindingType.INTERACTIVE_USE)
    negatives += [
        f
        for f in idle01.result.of_type(FindingType.ROLE_INFERENCE)
        if f.rule_id == "role.quiet.v1"
    ]
    assert negatives
    for finding in negatives:
        assert window_re.search(finding.conclusion), finding.conclusion


def test_idle01_quiet_role_fires_low(idle01):
    # Of the two candidate roles the rules produce role.quiet.v1 here, NOT
    # role.admin_host.v1: 4 deduped RDP logons stay below the "interactive"
    # classification threshold (>=5), so interactive_use classifies the host
    # as apparently_quiet, which is role.quiet's precondition and rules
    # admin_host out. role.quiet is only eligible because the TaskScheduler
    # channel's short retention leaves just 2 Defender scan starts in
    # evidence (below the >=3-start recurrence threshold) — the retention
    # shortfall itself is reported as a limitation.
    roles = _roles_by_rule(idle01.result)
    assert "role.admin_host.v1" not in roles
    (quiet,) = roles["role.quiet.v1"]
    assert quiet.confidence == "LOW"
    assert quiet.details["role"] == "apparently quiet during observed window"
    # The conclusion must disclaim "unused", not assert it.
    assert "not evidence" in quiet.conclusion
    # And the short TaskScheduler retention is visible as a limitation.
    retention = [
        f
        for f in idle01.result.of_type(FindingType.LIMITATION)
        if (f.details or {}).get("kind") == "retention_short"
    ]
    assert any(
        "TaskScheduler" in (f.details.get("subject") or "") for f in retention
    )
