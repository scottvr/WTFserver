"""Terminal-friendly text report.

Renders an AnalysisResult into plain ASCII-safe text: UPPERCASE section
headers, two-space indents, every conclusion tagged with its finding ID in
brackets so provenance is reachable from the text. Sections with nothing to
say are omitted, except HOST, EVIDENCE, LIKELY ROLES, and LIMITATIONS, which
always render (see docs/dev/CONTRACTS.md section 6).
"""

from __future__ import annotations

import textwrap
from typing import Any

from ..model import Finding, FindingType

WIDTH = 100
_INDENT = "  "
_SUBINDENT = "    "

NO_ROLES_LINE = "No role inference met evidence thresholds."


def render_text(result) -> str:
    sections: list[list[str]] = [
        _host_section(result),
        _evidence_section(result),
        _roles_section(result),
    ]
    for section in (
        _recurring_section(result),
        _associations_section(result),
        _peers_section(result),
        _configured_section(result),
        _interactive_section(result),
        _activity_section(result),
    ):
        if section is not None:
            sections.append(section)
    sections.append(_limitations_section(result))
    return "\n\n".join("\n".join(lines) for lines in sections) + "\n"


# --- helpers ---


def _fid(finding: Finding) -> str:
    return f"[{finding.id}]"


def _wrap(text: str, indent: str = _INDENT) -> list[str]:
    """Wrap one logical line to WIDTH; continuations get two extra spaces."""
    if not text or not text.strip():
        return []
    return textwrap.wrap(
        text,
        width=WIDTH,
        initial_indent=indent,
        subsequent_indent=indent + "  ",
    )


def _as_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _fmt_days(value: Any) -> str:
    try:
        return f"{float(value):.1f}"
    except (TypeError, ValueError):
        return str(value)


def _fmt_offset(value: Any) -> str:
    """Signed offset like '+4' / '-1'; the caller appends the unit."""
    try:
        return f"{int(round(float(value))):+d}"
    except (TypeError, ValueError):
        return "+?"


def _fmt_interval(seconds: Any) -> str:
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    if s >= 86400:
        return f"{s / 86400:.1f}d"
    if s >= 3600:
        return f"{s / 3600:.1f}h"
    if s >= 60:
        return f"{s / 60:.0f}m"
    return f"{s:.0f}s"


# --- sections ---


def _host_section(result) -> list[str]:
    manifest = result.manifest or {}
    lines = ["HOST"]
    hostname = manifest.get("hostname") or "(unknown host)"
    platform = manifest.get("platform") or "unknown platform"
    lines += _wrap(f"{hostname}  ({platform})")

    start = manifest.get("collection_start")
    end = manifest.get("collection_end")
    if start or end:
        collected = f"collected {start or '?'} .. {end or '?'}"
        tool_version = manifest.get("tool_version")
        if tool_version:
            collected += f"  (whatami {tool_version})"
        lines += _wrap(collected)

    requested = manifest.get("requested_since")
    if requested:
        window = f"requested window: {requested}"
        resolved = manifest.get("since_resolved")
        if resolved:
            window += f"  (resolved to {resolved})"
        lines += _wrap(window)

    host = getattr(result, "host", None) or {}
    os_name = host.get("os_name")
    if os_name:
        os_line = f"os: {os_name}"
        if host.get("os_version"):
            os_line += f" {host['os_version']}"
        lines += _wrap(os_line)
    if host.get("domain"):
        domain_line = f"domain: {host['domain']}"
        if host.get("domain_role"):
            domain_line += f" ({host['domain_role']})"
        lines += _wrap(domain_line)
    return lines


def _channel_line(row: dict[str, Any]) -> str:
    name = row.get("channel") or "(unknown channel)"
    error = row.get("error")
    record_count = _as_int(row.get("record_count"))
    if error:
        body = f"error: {str(error)[:60]}"
    elif row.get("enabled") is False and record_count == 0:
        body = "disabled"
    else:
        span = row.get("span_days")
        if isinstance(span, (int, float)) and not isinstance(span, bool):
            body = f"{_fmt_days(span)} days ({record_count} records)"
        else:
            body = f"span unknown ({record_count} records)"
    markers = []
    if row.get("enabled") is False and record_count > 0:
        markers.append("disabled")
    if row.get("truncated"):
        markers.append("truncated")
    if row.get("covers_window") is False:
        markers.append("history shorter than window")
    line = f"{name}: {body}"
    if markers:
        line += "  (" + ", ".join(markers) + ")"
    return line


def _evidence_section(result) -> list[str]:
    lines = ["EVIDENCE"]
    coverage = result.of_type(FindingType.EVIDENCE_COVERAGE)
    if not coverage:
        lines += _wrap("No evidence coverage finding is available.")
        return lines
    finding = coverage[0]
    details = finding.details or {}
    lines += _wrap(f"{finding.conclusion}  {_fid(finding)}")

    window = details.get("window") or {}
    parts = []
    if window.get("requested"):
        parts.append(f"requested {window['requested']}")
    parts.append(f"resolved {window.get('resolved') or 'max history'}")
    if window.get("collection_end"):
        parts.append(f"collection end {window['collection_end']}")
    lines += _wrap("window: " + ", ".join(parts))

    channels = details.get("channels") or []
    shown = channels[:12]  # keep the section compact; order is as the analyzer sorted it
    for row in shown:
        if isinstance(row, dict):
            lines += _wrap(_channel_line(row), indent=_SUBINDENT)
    omitted = max(len(channels) - len(shown), 0) + _as_int(details.get("channels_omitted"))
    if omitted:
        lines += _wrap(f"... {omitted} more channel(s) not shown", indent=_SUBINDENT)

    span = details.get("total_span_days")
    if span is not None:
        lines += _wrap(f"total observed span: up to {_fmt_days(span)} days")
    else:
        lines += _wrap("total observed span: unknown")
    return lines


def _roles_section(result) -> list[str]:
    lines = ["LIKELY ROLES"]
    roles = result.of_type(FindingType.ROLE_INFERENCE)
    if not roles:
        lines.append(f"{_INDENT}{NO_ROLES_LINE}")
        return lines
    for finding in roles:
        details = finding.details or {}
        role = details.get("role") or finding.conclusion
        confidence = finding.confidence or "UNSPECIFIED"
        lines += _wrap(f"{role}  {confidence}  {_fid(finding)}")
        for bullet in details.get("evidence_summary") or []:
            lines += _wrap(f"- {bullet}", indent=_SUBINDENT)
    return lines


def _recurring_section(result) -> list[str] | None:
    recurrences = result.of_type(FindingType.RECURRING_SCHEDULED_ACTIVITY)
    episodes = result.of_type(FindingType.ACTIVITY_EPISODE)
    if not recurrences and not episodes:
        return None
    lines = ["PRIMARY RECURRING ACTIVITY"]

    # Present workload tasks before built-in OS maintenance so routine hygiene
    # (Defender scans etc.) never headlines the section; mirrors the
    # role.batch.v1 rule-data prefix in analyzers/roles.py.
    def _maintenance_last(finding) -> tuple:
        name = (finding.details or {}).get("scheduled_action") or ""
        return (name.lower().startswith("\\microsoft\\"), )

    for finding in sorted(recurrences, key=_maintenance_last):
        details = finding.details or {}
        name = details.get("scheduled_action") or "(unknown task)"
        lines += _wrap(f"{name}  {_fid(finding)}")

        count = details.get("count")
        cadence = details.get("cadence") or "unknown cadence"
        desc = f"{count if count is not None else '?'} starts, {cadence}"
        if details.get("typical_time"):
            desc += f" around {details['typical_time']} UTC"
        elif cadence == "interval" and details.get("interval_seconds") is not None:
            desc += f", every {_fmt_interval(details['interval_seconds'])}"
        if details.get("first") and details.get("last"):
            desc += f" (first {details['first']}, last {details['last']})"
        lines += _wrap(desc, indent=_SUBINDENT)

        principal = details.get("principal")
        process = details.get("process")
        if principal or process:
            lines += _wrap(
                f"{principal or '(unknown principal)'} -> {process or '(unknown process)'}",
                indent=_SUBINDENT,
            )
        failures = _as_int(details.get("failure_count"))
        if failures:
            lines += _wrap(f"{failures} failed run(s) in window", indent=_SUBINDENT)

    for finding in episodes:
        details = finding.details or {}
        anchor = details.get("anchor") or {}
        anchor_name = " ".join(
            str(part)
            for part in (anchor.get("category"), anchor.get("action"), anchor.get("name"))
            if part
        ) or "(unknown anchor)"
        occurrences = details.get("occurrences")
        lines += _wrap(
            f"episode: {anchor_name}  "
            f"x{occurrences if occurrences is not None else '?'}  {_fid(finding)}"
        )
        if details.get("first") and details.get("last"):
            lines += _wrap(
                f"first {details['first']}, last {details['last']}", indent=_SUBINDENT
            )
        for step in details.get("typical_sequence") or []:
            if not isinstance(step, dict):
                continue
            offset = step.get("typical_offset_seconds")
            step_name = " ".join(
                str(part)
                for part in (step.get("category"), step.get("action"), step.get("name"))
                if part
            )
            lines += _wrap(f"{_fmt_offset(offset)}s  {step_name}", indent=_SUBINDENT)
    return lines


def _associations_section(result) -> list[str] | None:
    findings = result.of_type(FindingType.PROCESS_ASSOCIATION)
    if not findings:
        return None
    lines = ["ASSOCIATED EXECUTION"]
    # Group by process, preserving first-appearance order.
    order: list[str] = []
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        process = (finding.details or {}).get("process") or "(unknown process)"
        if process not in groups:
            groups[process] = []
            order.append(process)
        groups[process].append(finding)
    for process in order:
        group = groups[process]
        path = next(
            (p for p in ((f.details or {}).get("process_path") for f in group) if p), None
        )
        header = process
        if path and path != process:
            header += f"  ({path})"
        lines += _wrap(header)
        for finding in group:
            assoc = (finding.details or {}).get("associated_with") or {}
            kind = assoc.get("kind") or "association"
            name = assoc.get("name") or "(unknown)"
            count = assoc.get("count")
            lines += _wrap(
                f"{kind} {name}  x{count if count is not None else '?'}  {_fid(finding)}",
                indent=_SUBINDENT,
            )
    return lines


def _peers_section(result) -> list[str] | None:
    findings = result.of_type(FindingType.PEER_DEPENDENCY)
    if not findings:
        return None
    lines = ["OBSERVED PEERS"]
    omitted = 0
    for finding in findings:
        details = finding.details or {}
        host = details.get("remote_host") or "(unknown host)"
        port = details.get("remote_port")
        endpoint = f"{host}:{port}" if port is not None else host
        parts = [endpoint]
        if details.get("service_hint"):
            parts.append(f"({details['service_hint']})")
        count = details.get("count")
        parts.append(f"x{count if count is not None else '?'}")
        if details.get("evidence"):
            parts.append(str(details["evidence"]))
        parts.append(_fid(finding))
        lines += _wrap("  ".join(parts))
        omitted += _as_int(details.get("peers_omitted"))
    if omitted:
        lines += _wrap(f"... {omitted} more peer(s) not shown")
    return lines


def _configured_section(result) -> list[str] | None:
    findings = result.of_type(FindingType.CONFIGURED_BUT_UNOBSERVED)
    if not findings:
        return None
    lines = ["CONFIGURED BUT NOT OBSERVED"]
    for finding in findings:
        # The conclusion carries the window-scoped negative-evidence phrasing.
        lines += _wrap(f"{finding.conclusion}  {_fid(finding)}")
    return lines


def _interactive_section(result) -> list[str] | None:
    findings = result.of_type(FindingType.INTERACTIVE_USE)
    if not findings:
        return None
    finding = findings[0]
    lines = ["INTERACTIVE USE"]
    lines += _wrap(f"{finding.conclusion}  {_fid(finding)}")
    for entry in (finding.details or {}).get("interactive_principals") or []:
        try:
            name, count = entry[0], entry[1]
        except (TypeError, IndexError, KeyError):
            continue
        lines += _wrap(f"{name}  x{count}", indent=_SUBINDENT)
    return lines


def _activity_section(result) -> list[str] | None:
    findings = result.of_type(FindingType.FREQUENCY_SUMMARY)
    if not findings:
        return None
    finding = findings[0]
    details = finding.details or {}
    lines = ["ACTIVITY SUMMARY"]
    lines += _wrap(f"{finding.conclusion}  {_fid(finding)}")
    for label, key in (
        ("top providers", "top_providers"),
        ("top processes", "top_processes"),
        ("top principals", "top_principals"),
    ):
        rendered = []
        for entry in (details.get(key) or [])[:5]:  # compact: a few entries, not a dump
            try:
                rendered.append(f"{entry[0]} ({entry[1]})")
            except (TypeError, IndexError, KeyError):
                continue
        if rendered:
            lines += _wrap(f"{label}: " + ", ".join(rendered))
    return lines


def _limitations_section(result) -> list[str]:
    lines = ["LIMITATIONS"]
    findings = result.of_type(FindingType.LIMITATION)
    if not findings:
        lines.append(f"{_INDENT}None recorded.")
        return lines
    for finding in findings:
        lines += _wrap(f"{finding.conclusion}  {_fid(finding)}")
    return lines
