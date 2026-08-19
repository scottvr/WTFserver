"""Machine-readable JSON report.

The dict returned by render_json must round-trip through json.dumps: only
strings, numbers, bools, None, lists, and dicts — never datetime objects.
Shape is fixed by docs/dev/CONTRACTS.md section 6; all lists preserve
finding order.
"""

from __future__ import annotations

from typing import Any

from ..model import SCHEMA_VERSION, Finding, FindingType

_MANIFEST_KEYS = (
    "tool_version",
    "collection_start",
    "collection_end",
    "requested_since",
    "since_resolved",
    "collectors",
)


def render_json(result) -> dict[str, Any]:
    manifest = result.manifest or {}

    host: dict[str, Any] = {
        "hostname": manifest.get("hostname"),
        "platform": manifest.get("platform"),
    }
    # AnalysisResult.host carries the host_identity observation's attributes.
    for key, value in (getattr(result, "host", None) or {}).items():
        host.setdefault(key, value)

    coverage = result.of_type(FindingType.EVIDENCE_COVERAGE)
    interactive = result.of_type(FindingType.INTERACTIVE_USE)

    return {
        "schema_version": SCHEMA_VERSION,
        "host": host,
        "manifest": {key: manifest.get(key) for key in _MANIFEST_KEYS},
        "observations_summary": result.observations_summary,
        "evidence_coverage": _entry(coverage[0]) if coverage else None,
        "recurring_activity": [
            _entry(f) for f in result.of_type(FindingType.RECURRING_SCHEDULED_ACTIVITY)
        ],
        "episodes": [_entry(f) for f in result.of_type(FindingType.ACTIVITY_EPISODE)],
        "associations": [
            _entry(f) for f in result.of_type(FindingType.PROCESS_ASSOCIATION)
        ],
        "dependencies": [_entry(f) for f in result.of_type(FindingType.PEER_DEPENDENCY)],
        "interactive_use": _entry(interactive[0]) if interactive else None,
        "configured_but_unobserved": [
            _entry(f) for f in result.of_type(FindingType.CONFIGURED_BUT_UNOBSERVED)
        ],
        "role_inferences": [_entry(f) for f in result.of_type(FindingType.ROLE_INFERENCE)],
        "limitations": [_entry(f) for f in result.of_type(FindingType.LIMITATION)],
        "findings": [f.to_json_dict() for f in result.findings],
    }


def _entry(finding: Finding) -> dict[str, Any]:
    """Finding details with id/conclusion/confidence merged in.

    Provenance keys win over any (contract-violating) same-named detail key.
    """
    out: dict[str, Any] = {
        "id": finding.id,
        "conclusion": finding.conclusion,
        "confidence": finding.confidence,
    }
    for key, value in (finding.details or {}).items():
        if key not in out:
            out[key] = value
    return out
