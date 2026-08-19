"""Tests for the JSON report renderer (report/json_out.py)."""

from __future__ import annotations

import json

from wtfserver.analysis import AnalysisResult
from wtfserver.model import EVIDENCE_UNKNOWN, Finding, FindingType
from wtfserver.report.json_out import render_json

from helpers import make_manifest

from test_report_text import coverage_finding, full_result

TOP_LEVEL_KEYS = {
    "schema_version",
    "host",
    "manifest",
    "observations_summary",
    "evidence_coverage",
    "recurring_activity",
    "episodes",
    "associations",
    "dependencies",
    "interactive_use",
    "configured_but_unobserved",
    "role_inferences",
    "limitations",
    "findings",
}

MANIFEST_KEYS = {
    "tool_version",
    "collection_start",
    "collection_end",
    "requested_since",
    "since_resolved",
    "collectors",
}


def test_top_level_keys_exact():
    payload = render_json(full_result())
    assert set(payload.keys()) == TOP_LEVEL_KEYS
    assert payload["schema_version"] == 1


def test_round_trips_through_json_dumps():
    payload = render_json(full_result())
    assert json.loads(json.dumps(payload)) == payload


def test_host_and_manifest_subset():
    payload = render_json(full_result())
    assert payload["host"]["hostname"] == "testhost"
    assert payload["host"]["platform"] == "windows"
    assert set(payload["manifest"].keys()) == MANIFEST_KEYS
    assert payload["manifest"]["requested_since"] == "72h"
    assert payload["manifest"]["collectors"] == []


def test_observations_summary_passed_through():
    result = full_result()
    payload = render_json(result)
    assert payload["observations_summary"] == result.observations_summary


def test_evidence_coverage_merged_entry():
    payload = render_json(full_result())
    coverage = payload["evidence_coverage"]
    assert coverage["id"] == "f-0001"
    assert "conclusion" in coverage
    assert coverage["window"]["requested"] == "72h"
    assert len(coverage["channels"]) == 3
    assert coverage["total_span_days"] == 30.0


def test_list_entries_have_id_conclusion_confidence_and_details():
    payload = render_json(full_result())
    recurrence = payload["recurring_activity"][0]
    assert recurrence["id"] == "f-0004"
    assert recurrence["conclusion"].startswith("Task")
    assert recurrence["confidence"] is None  # descriptive finding
    assert recurrence["scheduled_action"] == "\\Vendor\\NightlyExport"
    assert recurrence["cadence"] == "daily"

    role = payload["role_inferences"][0]
    assert role["id"] == "f-0011"
    assert role["confidence"] == "HIGH"
    assert role["role"] == "batch/scheduled processing host"

    episode = payload["episodes"][0]
    assert episode["anchor"]["name"] == "\\Vendor\\NightlyExport"
    assert len(episode["typical_sequence"]) == 3

    association = payload["associations"][0]
    assert association["associated_with"]["kind"] == "scheduled_action"

    limitation = payload["limitations"][0]
    assert limitation["kind"] == "channel_disabled"


def test_lists_preserve_finding_order():
    payload = render_json(full_result())
    assert [d["id"] for d in payload["dependencies"]] == ["f-0007", "f-0008"]
    # Null port survives as null, not a string.
    assert payload["dependencies"][1]["remote_port"] is None


def test_interactive_use_single_object():
    payload = render_json(full_result())
    interactive = payload["interactive_use"]
    assert interactive["id"] == "f-0009"
    assert interactive["classification"] == "batch_scheduled"


def test_findings_serialized_completely_in_order():
    result = full_result()
    payload = render_json(result)
    assert len(payload["findings"]) == len(result.findings)
    assert [f["id"] for f in payload["findings"]] == [f.id for f in result.findings]
    for entry in payload["findings"]:
        assert "finding_type" in entry
        assert "evidence_class" in entry


def test_empty_result_shape():
    payload = render_json(AnalysisResult(manifest=make_manifest(), findings=[]))
    assert set(payload.keys()) == TOP_LEVEL_KEYS
    assert payload["evidence_coverage"] is None
    assert payload["interactive_use"] is None
    for key in (
        "recurring_activity",
        "episodes",
        "associations",
        "dependencies",
        "configured_but_unobserved",
        "role_inferences",
        "limitations",
        "findings",
    ):
        assert payload[key] == []
    assert json.loads(json.dumps(payload)) == payload


def test_malformed_details_key_cannot_clobber_provenance():
    # A contract-violating details dict with an "id" key must not overwrite
    # the finding's own id in the merged entry.
    finding = Finding(
        id="f-0001",
        finding_type=FindingType.PEER_DEPENDENCY,
        analyzer="peers",
        conclusion="Peer with hostile details.",
        evidence_class=EVIDENCE_UNKNOWN,
        details={"id": "bogus", "conclusion": "bogus", "remote_host": "10.0.0.1"},
    )
    payload = render_json(AnalysisResult(manifest={}, findings=[finding]))
    entry = payload["dependencies"][0]
    assert entry["id"] == "f-0001"
    assert entry["conclusion"] == "Peer with hostile details."
    assert entry["remote_host"] == "10.0.0.1"
    # Missing manifest keys render as nulls, not crashes.
    assert payload["host"]["hostname"] is None
    assert json.loads(json.dumps(payload)) == payload


def test_render_json_is_deterministic():
    first = json.dumps(render_json(full_result()), sort_keys=True)
    second = json.dumps(render_json(full_result()), sort_keys=True)
    assert first == second


def test_coverage_only_result():
    result = AnalysisResult(manifest=make_manifest(), findings=[coverage_finding(1)])
    payload = render_json(result)
    assert payload["evidence_coverage"]["id"] == "f-0001"
    assert payload["limitations"] == []
