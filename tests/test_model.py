from datetime import datetime, timezone

from wtfserver.model import Finding, Observation, parse_iso, to_iso


def test_observation_round_trip_omits_nulls():
    obs = Observation(
        id="obs-000001",
        source="services",
        category="service_state",
        timestamp="2026-08-19T01:00:00Z",
        service="Spooler",
        attributes={"state": "running"},
    )
    data = obs.to_json_dict()
    assert "remote_host" not in data
    assert "principal" not in data
    back = Observation.from_json_dict(data)
    assert back == obs


def test_observation_preserves_unknown_fields():
    data = {
        "id": "obs-000001",
        "source": "x",
        "category": "event",
        "future_field": {"a": 1},
    }
    obs = Observation.from_json_dict(data)
    assert obs.attributes["_unknown_fields"] == {"future_field": {"a": 1}}


def test_finding_round_trip():
    f = Finding(
        id="f-0001",
        finding_type="role_inference",
        analyzer="roles",
        rule_id="role.batch.v1",
        conclusion="batch host",
        evidence_class="inferred",
        confidence="HIGH",
        supporting_observations=["obs-000001"],
        details={"role": "batch"},
    )
    assert Finding.from_json_dict(f.to_json_dict()) == f


def test_observation_null_attributes_normalized():
    obs = Observation.from_json_dict(
        {"id": "obs-000001", "source": "x", "category": "event", "attributes": None}
    )
    assert obs.attributes == {}


def test_parse_iso_powershell_o_format():
    # PowerShell's round-trip 'o' format emits 7 fractional digits, which
    # fromisoformat rejects before Python 3.11 — parse_iso must handle it.
    dt = parse_iso("2026-08-18T09:00:00.1234567Z")
    assert dt == datetime(2026, 8, 18, 9, 0, 0, 123456, tzinfo=timezone.utc)
    assert parse_iso("2026-08-18T09:00:00.1234567+02:00") is not None
    assert parse_iso("2026-08-18T09:00:00.123Z") is not None


def test_parse_iso_variants():
    expected = datetime(2026, 8, 19, 1, 0, 2, tzinfo=timezone.utc)
    assert parse_iso("2026-08-19T01:00:02Z") == expected
    assert parse_iso("2026-08-19T01:00:02+00:00") == expected
    assert parse_iso("2026-08-19T03:00:02+02:00") == expected
    assert parse_iso("2026-08-19T01:00:02") == expected  # naive -> UTC
    assert parse_iso("garbage") is None
    assert parse_iso("") is None


def test_to_iso_is_utc_z():
    dt = datetime(2026, 8, 19, 1, 0, 2, tzinfo=timezone.utc)
    assert to_iso(dt) == "2026-08-19T01:00:02Z"
    assert parse_iso(to_iso(dt)) == dt
