"""Core data model for WTFServer / whatami.

This module defines the platform-neutral vocabulary shared by collectors,
analyzers, and reports. Windows-specific detail belongs in collector code and
in per-observation ``attributes`` — never in these types.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = 1


# --- Confidence levels (no numeric pseudo-precision) ---

CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"

CONFIDENCE_LEVELS = (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW)


# --- Evidence classes (Configured / Observed / Inferred / Unknown) ---

EVIDENCE_CONFIGURED = "configured"
EVIDENCE_OBSERVED = "observed"
EVIDENCE_INFERRED = "inferred"
EVIDENCE_UNKNOWN = "unknown"

EVIDENCE_CLASSES = (
    EVIDENCE_CONFIGURED,
    EVIDENCE_OBSERVED,
    EVIDENCE_INFERRED,
    EVIDENCE_UNKNOWN,
)


class Category:
    """Normalized observation categories.

    Historical activity categories describe things that happened during the
    evidence window. State categories describe configuration or runtime state
    at collection time.
    """

    # Evidence-source metadata
    EVIDENCE_CHANNEL = "evidence_channel"

    # Historical activity
    EVENT = "event"  # unrecognized historical event, kept for frequency analysis
    LOGON = "logon"
    PROCESS_ACTIVITY = "process_activity"
    SERVICE_ACTIVITY = "service_activity"
    SCHEDULED_ACTIVITY = "scheduled_activity"
    SYSTEM_LIFECYCLE = "system_lifecycle"

    # Current state at collection time
    SERVICE_STATE = "service_state"
    SCHEDULED_TASK_STATE = "scheduled_task_state"
    PROCESS_STATE = "process_state"
    SOCKET_STATE = "socket_state"
    HOST_IDENTITY = "host_identity"
    INSTALLED_ROLE = "installed_role"
    INSTALLED_SOFTWARE = "installed_software"

    ALL = (
        EVIDENCE_CHANNEL,
        EVENT,
        LOGON,
        PROCESS_ACTIVITY,
        SERVICE_ACTIVITY,
        SCHEDULED_ACTIVITY,
        SYSTEM_LIFECYCLE,
        SERVICE_STATE,
        SCHEDULED_TASK_STATE,
        PROCESS_STATE,
        SOCKET_STATE,
        HOST_IDENTITY,
        INSTALLED_ROLE,
        INSTALLED_SOFTWARE,
    )


class FindingType:
    """Types of findings produced by analyzers."""

    EVIDENCE_COVERAGE = "evidence_coverage"
    FREQUENCY_SUMMARY = "frequency_summary"
    RECURRING_SCHEDULED_ACTIVITY = "recurring_scheduled_activity"
    ACTIVITY_EPISODE = "activity_episode"
    PROCESS_ASSOCIATION = "process_association"
    PEER_DEPENDENCY = "peer_dependency"
    INTERACTIVE_USE = "interactive_use"
    CONFIGURED_BUT_UNOBSERVED = "configured_but_unobserved"
    ROLE_INFERENCE = "role_inference"
    LIMITATION = "limitation"


@dataclass
class Observation:
    """One normalized observation.

    Most fields are None for most observations; that is by design. Source-
    specific detail goes in ``attributes``. ``raw_reference`` points into the
    bundle's raw/ directory (e.g. ``raw/services.json#3``).
    """

    id: str
    source: str
    category: str
    timestamp: str | None = None  # ISO 8601 UTC, e.g. "2026-08-19T01:00:02Z"
    host: str | None = None
    action: str | None = None
    principal: str | None = None
    process: str | None = None
    service: str | None = None
    scheduled_action: str | None = None
    remote_host: str | None = None
    remote_port: int | None = None
    local_path: str | None = None
    message: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    raw_reference: str | None = None

    def __post_init__(self) -> None:
        # Foreign/hand-edited bundles may carry "attributes": null; analyzers
        # must be able to rely on attributes being a dict.
        if self.attributes is None:
            self.attributes = {}

    def to_json_dict(self) -> dict[str, Any]:
        """Serialize, omitting empty fields to keep JSONL compact."""
        out: dict[str, Any] = {"id": self.id, "source": self.source, "category": self.category}
        for key in (
            "timestamp",
            "host",
            "action",
            "principal",
            "process",
            "service",
            "scheduled_action",
            "remote_host",
            "remote_port",
            "local_path",
            "message",
            "raw_reference",
        ):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        if self.attributes:
            out["attributes"] = self.attributes
        return out

    @classmethod
    def from_json_dict(cls, data: dict[str, Any]) -> "Observation":
        known = {f for f in cls.__dataclass_fields__}
        kwargs = {k: v for k, v in data.items() if k in known}
        # Preserve unknown keys instead of dropping them (forward compatibility).
        extra = {k: v for k, v in data.items() if k not in known}
        obs = cls(**kwargs)
        if extra:
            obs.attributes = {**obs.attributes, "_unknown_fields": extra}
        return obs

    def when(self) -> datetime | None:
        return parse_iso(self.timestamp) if self.timestamp else None


@dataclass
class Finding:
    """One analyzer conclusion, traceable to supporting observations."""

    id: str
    finding_type: str
    analyzer: str
    conclusion: str
    evidence_class: str
    rule_id: str | None = None
    confidence: str | None = None  # HIGH / MEDIUM / LOW; None for descriptive findings
    supporting_observations: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_json_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "finding_type": self.finding_type,
            "analyzer": self.analyzer,
            "conclusion": self.conclusion,
            "evidence_class": self.evidence_class,
        }
        if self.rule_id is not None:
            out["rule_id"] = self.rule_id
        if self.confidence is not None:
            out["confidence"] = self.confidence
        out["supporting_observations"] = self.supporting_observations
        if self.details:
            out["details"] = self.details
        if self.limitations:
            out["limitations"] = self.limitations
        return out

    @classmethod
    def from_json_dict(cls, data: dict[str, Any]) -> "Finding":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


# --- Time helpers (all internal time handling is aware UTC) ---

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    """Render an aware datetime as ISO 8601 UTC with a Z suffix."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_FRACTION = re.compile(r"(\.\d+)")


def parse_iso(value: str) -> datetime | None:
    """Parse an ISO 8601 timestamp; returns aware UTC or None if unparseable.

    Handles the trailing-Z form on Python 3.10 (fromisoformat rejects it
    there), naive timestamps (assumed UTC), and over-long fractional seconds:
    PowerShell's round-trip 'o' format emits exactly 7 fractional digits,
    which fromisoformat rejects before Python 3.11.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    match = _FRACTION.search(text)
    if match and len(match.group(1)) - 1 > 6:
        frac = match.group(1)[1:7]
        text = text[: match.start(1)] + "." + frac + text[match.end(1) :]
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
