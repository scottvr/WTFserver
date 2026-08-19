import json

import pytest

from wtfserver.bundle import Bundle, BundleError, BundleWriter
from wtfserver.model import Observation


def _obs(i: int) -> Observation:
    return Observation(
        id="", source="test", category="event", timestamp=f"2026-08-19T0{i}:00:00Z"
    )


def test_write_and_load_zip(tmp_path):
    writer = BundleWriter(tmp_path / "host.wtf")
    ids = [writer.add_observation(_obs(i)) for i in range(3)]
    assert ids == ["obs-000001", "obs-000002", "obs-000003"]
    ref = writer.add_raw("services.json", json.dumps([{"Name": "Spooler"}]))
    assert ref == "raw/services.json"
    path = writer.finalize({"hostname": "h1", "platform": "windows"})

    bundle = Bundle.load(path)
    assert bundle.manifest["hostname"] == "h1"
    assert bundle.manifest["schema_version"] == 1
    assert bundle.manifest["observation_count"] == 3
    assert [o.id for o in bundle.observations] == ids
    assert json.loads(bundle.open_raw("raw/services.json")) == [{"Name": "Spooler"}]
    assert bundle.raw_names() == ["raw/services.json"]


def test_load_directory_bundle(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"schema_version": 1}))
    (tmp_path / "observations.jsonl").write_text(
        '{"id": "obs-000001", "source": "s", "category": "event"}\n\n'
    )
    bundle = Bundle.load(tmp_path)
    assert len(bundle.observations) == 1
    assert bundle.observations[0].id == "obs-000001"


def test_raw_reference_fragment_is_stripped(tmp_path):
    writer = BundleWriter(tmp_path / "b.wtf")
    writer.add_raw("events_Security.jsonl", "{}\n")
    path = writer.finalize({})
    bundle = Bundle.load(path)
    assert bundle.open_raw("raw/events_Security.jsonl#42") == b"{}\n"


def test_rejects_future_schema_version(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"schema_version": 99}))
    with pytest.raises(BundleError, match="newer"):
        Bundle.load(tmp_path)


def test_rejects_missing_manifest(tmp_path):
    with pytest.raises(BundleError):
        Bundle.load(tmp_path)


def test_rejects_bad_zip(tmp_path):
    bad = tmp_path / "bad.wtf"
    bad.write_bytes(b"not a zip")
    with pytest.raises(BundleError, match="zip"):
        Bundle.load(bad)


def test_malformed_observation_line_raises(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"schema_version": 1}))
    (tmp_path / "observations.jsonl").write_text("{broken\n")
    with pytest.raises(BundleError, match="line 1"):
        Bundle.load(tmp_path)


def test_raw_name_sanitization(tmp_path):
    writer = BundleWriter(tmp_path / "b.wtf")
    ref = writer.add_raw("events_Microsoft-Windows-TaskScheduler/Operational.jsonl", "x")
    assert "/" not in ref.removeprefix("raw/")
    writer.finalize({})
