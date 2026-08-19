"""Tests for the text report renderer (report/text.py)."""

from __future__ import annotations

from wtfserver.analysis import AnalysisResult
from wtfserver.model import (
    CONFIDENCE_HIGH,
    EVIDENCE_CONFIGURED,
    EVIDENCE_INFERRED,
    EVIDENCE_OBSERVED,
    EVIDENCE_UNKNOWN,
    Finding,
    FindingType,
)
from wtfserver.report.text import render_text

from helpers import make_manifest

ALL_HEADERS = [
    "HOST",
    "EVIDENCE",
    "LIKELY ROLES",
    "PRIMARY RECURRING ACTIVITY",
    "ASSOCIATED EXECUTION",
    "OBSERVED PEERS",
    "CONFIGURED BUT NOT OBSERVED",
    "INTERACTIVE USE",
    "ACTIVITY SUMMARY",
    "LIMITATIONS",
]

OPTIONAL_HEADERS = [
    "PRIMARY RECURRING ACTIVITY",
    "ASSOCIATED EXECUTION",
    "OBSERVED PEERS",
    "CONFIGURED BUT NOT OBSERVED",
    "INTERACTIVE USE",
    "ACTIVITY SUMMARY",
]


def _finding(seq, ftype, analyzer, conclusion, evidence_class, **kwargs):
    return Finding(
        id=f"f-{seq:04d}",
        finding_type=ftype,
        analyzer=analyzer,
        conclusion=conclusion,
        evidence_class=evidence_class,
        **kwargs,
    )


def coverage_finding(seq=1):
    return _finding(
        seq,
        FindingType.EVIDENCE_COVERAGE,
        "coverage",
        "Inventoried 3 event log channel(s); 2 contain records, "
        "with history spanning up to 30.0 days.",
        EVIDENCE_OBSERVED,
        details={
            "window": {
                "requested": "72h",
                "resolved": "2026-08-16T12:00:00Z",
                "collection_end": "2026-08-19T12:05:00Z",
            },
            "channels": [
                {
                    "channel": "Security",
                    "enabled": True,
                    "record_count": 52340,
                    "oldest": "2026-08-02T04:11:00Z",
                    "newest": "2026-08-19T11:59:00Z",
                    "span_days": 17.3,
                    "covers_window": True,
                    "collected_events": 25000,
                    "truncated": True,
                    "error": None,
                },
                {
                    "channel": "System",
                    "enabled": True,
                    "record_count": 8000,
                    "oldest": "2026-07-20T12:00:00Z",
                    "newest": "2026-08-19T11:59:00Z",
                    "span_days": 30.0,
                    "covers_window": True,
                    "collected_events": 8000,
                    "truncated": False,
                    "error": None,
                },
                {
                    "channel": "Microsoft-Windows-TaskScheduler/Operational",
                    "enabled": False,
                    "record_count": 0,
                    "oldest": None,
                    "newest": None,
                    "span_days": None,
                    "covers_window": None,
                    "collected_events": 0,
                    "truncated": False,
                    "error": None,
                },
            ],
            "channels_omitted": 0,
            "total_span_days": 30.0,
        },
        supporting_observations=["obs-000001", "obs-000002", "obs-000003"],
    )


def limitation_finding(seq=2):
    return _finding(
        seq,
        FindingType.LIMITATION,
        "coverage",
        "Channel 'Microsoft-Windows-TaskScheduler/Operational' is disabled; "
        "its history is unavailable.",
        EVIDENCE_UNKNOWN,
        details={
            "kind": "channel_disabled",
            "subject": "Microsoft-Windows-TaskScheduler/Operational",
        },
    )


def full_result():
    """One finding of every contracted type, in analyzer registry order."""
    findings = [
        coverage_finding(1),
        limitation_finding(2),
        _finding(
            3,
            FindingType.FREQUENCY_SUMMARY,
            "frequency",
            "Frequency summary over the available history.",
            EVIDENCE_OBSERVED,
            details={
                "top_providers": [
                    ["Microsoft-Windows-Security-Auditing", 41000],
                    ["Service Control Manager", 1200],
                ],
                "top_event_ids": [["Microsoft-Windows-Security-Auditing:4624", 20000]],
                "top_principals": [["CORP\\svc_batch", 300]],
                "top_services": [["VendorSvc", 40]],
                "top_scheduled_actions": [["\\Vendor\\NightlyExport", 21]],
                "top_processes": [["export.exe", 300]],
                "top_remote_hosts": [["10.0.0.5", 42]],
                "top_remote_ports": [["1433", 42]],
                "system_principals": [["SYSTEM", 9000]],
                "process_paths": {"export.exe": "C:\\Vendor\\export.exe"},
            },
        ),
        _finding(
            4,
            FindingType.RECURRING_SCHEDULED_ACTIVITY,
            "recurrence",
            "Task \\Vendor\\NightlyExport started 21 times, daily around 01:30 UTC.",
            EVIDENCE_OBSERVED,
            details={
                "scheduled_action": "\\Vendor\\NightlyExport",
                "count": 21,
                "first": "2026-07-29T01:30:02Z",
                "last": "2026-08-18T01:30:04Z",
                "cadence": "daily",
                "interval_seconds": 86400.0,
                "typical_time": "01:30",
                "jitter_seconds": 2.0,
                "principal": "CORP\\svc_batch",
                "process": "C:\\Vendor\\export.exe",
                "failure_count": 2,
            },
        ),
        _finding(
            5,
            FindingType.ACTIVITY_EPISODE,
            "correlation",
            "A repeated episode anchored on \\Vendor\\NightlyExport occurred 21 times.",
            EVIDENCE_OBSERVED,
            details={
                "anchor": {
                    "category": "scheduled_activity",
                    "action": "start",
                    "name": "\\Vendor\\NightlyExport",
                },
                "occurrences": 21,
                "first": "2026-07-29T01:30:02Z",
                "last": "2026-08-18T01:30:04Z",
                "typical_sequence": [
                    {
                        "category": "scheduled_activity",
                        "action": "start",
                        "name": "\\Vendor\\NightlyExport",
                        "typical_offset_seconds": 0.0,
                        "seen_in": 21,
                    },
                    {
                        "category": "logon",
                        "action": "logon",
                        "name": "CORP\\svc_batch",
                        "typical_offset_seconds": 1.0,
                        "seen_in": 21,
                    },
                    {
                        "category": "process_activity",
                        "action": "start",
                        "name": "export.exe",
                        "typical_offset_seconds": 3.0,
                        "seen_in": 20,
                    },
                ],
            },
        ),
        _finding(
            6,
            FindingType.PROCESS_ASSOCIATION,
            "associations",
            "export.exe is associated with \\Vendor\\NightlyExport (21 co-occurrences).",
            EVIDENCE_OBSERVED,
            details={
                "process": "export.exe",
                "process_path": "C:\\Vendor\\export.exe",
                "associated_with": {
                    "kind": "scheduled_action",
                    "name": "\\Vendor\\NightlyExport",
                    "count": 21,
                },
                "total_process_observations": 25,
            },
        ),
        _finding(
            7,
            FindingType.PEER_DEPENDENCY,
            "peers",
            "Outbound connections to 10.0.0.5:1433 (mssql) observed 42 times.",
            EVIDENCE_OBSERVED,
            details={
                "remote_host": "10.0.0.5",
                "remote_port": 1433,
                "count": 42,
                "evidence": "both",
                "processes": ["export.exe"],
                "service_hint": "mssql",
            },
        ),
        _finding(
            8,
            FindingType.PEER_DEPENDENCY,
            "peers",
            "Historical activity referenced remote host 10.0.0.9 3 times.",
            EVIDENCE_OBSERVED,
            details={
                "remote_host": "10.0.0.9",
                "remote_port": None,
                "count": 3,
                "evidence": "historical",
                "processes": [],
                "service_hint": None,
            },
        ),
        _finding(
            9,
            FindingType.INTERACTIVE_USE,
            "interactive",
            "2 administrator RDP sessions over 17 days; batch activity dominates.",
            EVIDENCE_OBSERVED,
            details={
                "classification": "batch_scheduled",
                "interactive_logons": 0,
                "remote_interactive_logons": 2,
                "batch_logons": 21,
                "service_logons": 4,
                "network_logons": 100,
                "failed_logons": 1,
                "interactive_principals": [["CORP\\alice", 2]],
                "first_interactive": "2026-08-04T09:12:00Z",
                "last_interactive": "2026-08-15T16:40:00Z",
                "window_days": 17.3,
            },
        ),
        _finding(
            10,
            FindingType.CONFIGURED_BUT_UNOBSERVED,
            "configured_unobserved",
            "Service 'SomeVendorSvc' is configured (auto-start, stopped) but no "
            "execution was observed during the 17-day available history.",
            EVIDENCE_CONFIGURED,
            details={
                "kind": "service",
                "name": "SomeVendorSvc",
                "configured_state": "auto-start, stopped",
                "window_days": 17.3,
                "note": None,
            },
        ),
        _finding(
            11,
            FindingType.ROLE_INFERENCE,
            "roles",
            "This host appears to be a batch/scheduled processing host.",
            EVIDENCE_INFERRED,
            rule_id="role.batch.v1",
            confidence=CONFIDENCE_HIGH,
            details={
                "role": "batch/scheduled processing host",
                "evidence_summary": [
                    "\\Vendor\\NightlyExport ran 21 times daily as CORP\\svc_batch"
                ],
            },
        ),
    ]
    return AnalysisResult(
        manifest=make_manifest(),
        findings=findings,
        observations_summary={
            "total": 1234,
            "by_category": {"logon": 100, "scheduled_activity": 42},
            "by_source": {"eventlog": 1200, "services": 34},
        },
    )


def test_all_sections_present_in_order():
    text = render_text(full_result())
    positions = []
    for header in ALL_HEADERS:
        index = text.find(header + "\n")
        assert index != -1, f"missing section header: {header}"
        positions.append(index)
    assert positions == sorted(positions), "sections out of order"


def test_every_finding_id_appears_in_brackets():
    result = full_result()
    text = render_text(result)
    for finding in result.findings:
        assert f"[{finding.id}]" in text, f"missing bracketed id for {finding.id}"


def test_host_section_from_manifest():
    text = render_text(full_result())
    assert "testhost  (windows)" in text
    assert "requested window: 72h" in text
    assert "2026-08-16T12:00:00Z" in text


def test_evidence_section_channels_and_span():
    text = render_text(full_result())
    assert "Security: 17.3 days (52340 records)" in text
    assert "truncated" in text
    assert "Microsoft-Windows-TaskScheduler/Operational: disabled" in text
    assert "total observed span: up to 30.0 days" in text


def test_roles_section_line_format():
    text = render_text(full_result())
    assert "batch/scheduled processing host  HIGH  [f-0011]" in text


def test_recurrence_block():
    text = render_text(full_result())
    assert "\\Vendor\\NightlyExport  [f-0004]" in text
    assert "21 starts, daily around 01:30 UTC" in text
    assert "CORP\\svc_batch -> C:\\Vendor\\export.exe" in text
    assert "2 failed run(s) in window" in text


def test_episode_sequence_offsets():
    text = render_text(full_result())
    assert "x21  [f-0005]" in text
    assert "+0s  scheduled_activity start \\Vendor\\NightlyExport" in text
    assert "+1s  logon logon CORP\\svc_batch" in text
    assert "+3s  process_activity start export.exe" in text


def test_peer_lines_including_null_port():
    text = render_text(full_result())
    assert "10.0.0.5:1433  (mssql)  x42  both  [f-0007]" in text
    # Null port: bare host, no ":None", no hint parens.
    assert "10.0.0.9  x3  historical  [f-0008]" in text
    assert "10.0.0.9:" not in text
    # Finding order preserved within the section.
    assert text.index("[f-0007]") < text.index("[f-0008]")


def test_interactive_section_principals():
    text = render_text(full_result())
    assert "batch activity dominates.  [f-0009]" in text
    assert "CORP\\alice  x2" in text


def test_no_roles_exact_line_and_optional_sections_omitted():
    result = AnalysisResult(
        manifest=make_manifest(),
        findings=[coverage_finding(1), limitation_finding(2)],
    )
    text = render_text(result)
    assert "\n  No role inference met evidence thresholds.\n" in text
    for header in OPTIONAL_HEADERS:
        assert header + "\n" not in text, f"empty section not omitted: {header}"
    for header in ("HOST", "EVIDENCE", "LIKELY ROLES", "LIMITATIONS"):
        assert header + "\n" in text


def test_empty_findings_result_renders():
    result = AnalysisResult(manifest=make_manifest(), findings=[])
    text = render_text(result)
    assert "HOST" in text
    assert "No evidence coverage finding is available." in text
    assert "No role inference met evidence thresholds." in text
    assert "\n  None recorded.\n" in text


def test_malformed_findings_with_empty_details_do_not_crash():
    types = [
        FindingType.EVIDENCE_COVERAGE,
        FindingType.FREQUENCY_SUMMARY,
        FindingType.RECURRING_SCHEDULED_ACTIVITY,
        FindingType.ACTIVITY_EPISODE,
        FindingType.PROCESS_ASSOCIATION,
        FindingType.PEER_DEPENDENCY,
        FindingType.INTERACTIVE_USE,
        FindingType.CONFIGURED_BUT_UNOBSERVED,
        FindingType.ROLE_INFERENCE,
        FindingType.LIMITATION,
    ]
    findings = [
        _finding(i + 1, ftype, "test", f"Bare conclusion for {ftype}.", EVIDENCE_UNKNOWN)
        for i, ftype in enumerate(types)
    ]
    text = render_text(AnalysisResult(manifest={}, findings=findings))
    for finding in findings:
        assert f"[{finding.id}]" in text


def test_output_is_ascii_and_within_width():
    text = render_text(full_result())
    assert text.isascii()
    for line in text.splitlines():
        assert len(line) <= 100, f"line exceeds 100 cols: {line!r}"
        assert "\x1b" not in line  # no ANSI


def test_render_is_deterministic():
    assert render_text(full_result()) == render_text(full_result())
