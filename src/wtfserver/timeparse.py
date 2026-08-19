"""Parsing for the --since time selector.

Accepted forms:
    30m       minutes
    72h       hours
    3d        days
    2w        weeks
    2026-08-01            absolute date (start of day, UTC)
    2026-08-01T06:00:00Z  absolute timestamp
    max       use all locally available history (returns None)
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .model import parse_iso

_RELATIVE = re.compile(r"^(\d+)\s*(m|min|h|hr|d|w)$", re.IGNORECASE)

_UNIT_SECONDS = {
    "m": 60,
    "min": 60,
    "h": 3600,
    "hr": 3600,
    "d": 86400,
    "w": 604800,
}


class SinceParseError(ValueError):
    pass


def parse_since(value: str, now: datetime) -> datetime | None:
    """Resolve a --since selector to an aware UTC datetime.

    Returns None for "max", meaning: use all available history.
    """
    text = value.strip()
    if not text:
        raise SinceParseError("empty --since value")
    if text.lower() == "max":
        return None

    match = _RELATIVE.match(text)
    if match:
        amount = int(match.group(1))
        unit = match.group(2).lower()
        if amount == 0:
            raise SinceParseError(f"--since {value!r}: duration must be positive")
        return now - timedelta(seconds=amount * _UNIT_SECONDS[unit])

    parsed = parse_iso(text)
    if parsed is not None:
        return parsed
    # Bare date (YYYY-MM-DD) is handled by parse_iso already; anything else is an error.
    raise SinceParseError(
        f"cannot parse --since {value!r}; expected forms like 72h, 3d, 2w, "
        f"2026-08-01, or max"
    )


def describe_since(since: datetime | None) -> str:
    if since is None:
        return "max"
    return since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
