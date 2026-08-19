from datetime import datetime, timedelta, timezone

import pytest

from wtfserver.timeparse import SinceParseError, describe_since, parse_since

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "value,delta",
    [
        ("30m", timedelta(minutes=30)),
        ("72h", timedelta(hours=72)),
        ("3d", timedelta(days=3)),
        ("2w", timedelta(weeks=2)),
        ("12 h", timedelta(hours=12)),
    ],
)
def test_relative(value, delta):
    assert parse_since(value, NOW) == NOW - delta


def test_max_returns_none():
    assert parse_since("max", NOW) is None
    assert parse_since("MAX", NOW) is None


def test_absolute_date():
    assert parse_since("2026-08-01", NOW) == datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert parse_since("2026-08-01T06:30:00Z", NOW) == datetime(
        2026, 8, 1, 6, 30, tzinfo=timezone.utc
    )


@pytest.mark.parametrize("bad", ["", "yesterday", "0h", "-3d", "3x"])
def test_rejects_garbage(bad):
    with pytest.raises(SinceParseError):
        parse_since(bad, NOW)


def test_describe():
    assert describe_since(None) == "max"
    assert describe_since(NOW) == "2026-08-19T12:00:00Z"
