"""Tests for collection orchestration and CLI wiring (fixes from review)."""

import json

from wtfserver.bundle import Bundle
from wtfserver.cli import main
from wtfserver.collect import run_collection
from wtfserver.collectors.base import Collector, CollectorError, CollectorResult
from wtfserver.model import Observation


class _OkCollector(Collector):
    name = "ok"
    platforms = ("windows",)
    categories = ("event",)

    def collect(self, ctx):
        return CollectorResult(
            observations=[
                Observation(id="", source="ok", category="event", timestamp="2026-08-19T01:00:00Z")
            ]
        )


class _BoomCollector(Collector):
    name = "boom"
    platforms = ("windows",)
    categories = ("event",)

    def collect(self, ctx):
        raise RuntimeError("kaboom")


class _PartialCollector(Collector):
    name = "partial"
    platforms = ("windows",)
    categories = ("event",)

    def collect(self, ctx):
        return CollectorResult(errors=[CollectorError(collector="partial", message="denied")])


def test_run_collection_returns_written_manifest(tmp_path):
    path, manifest = run_collection(
        since=None,
        output_path=tmp_path / "out.wtf",
        requested_since="max",
        collectors=[_OkCollector(), _BoomCollector(), _PartialCollector()],
        runner=object(),
        host_platform="windows",
    )
    # The returned manifest must match what was written (collect CLI reads it).
    assert manifest["observation_count"] == 1
    on_disk = Bundle.load(path).manifest
    assert on_disk["observation_count"] == 1
    statuses = {r["name"]: r["status"] for r in manifest["collectors"]}
    assert statuses == {"ok": "ok", "boom": "failed", "partial": "partial"}
    # A crashed collector must not sink collection.
    assert Bundle.load(path).observations[0].source == "ok"


def test_analyze_json_unwritable_path_still_prints_report(tmp_path, capsys):
    (tmp_path / "manifest.json").write_text(json.dumps({"schema_version": 1}))
    (tmp_path / "observations.jsonl").write_text("")
    rc = main(["analyze", str(tmp_path), "--json", str(tmp_path / "no-such-dir" / "x.json")])
    out = capsys.readouterr()
    assert rc == 2
    assert "cannot write" in out.err
    assert "HOST" in out.out  # text report still delivered


def test_analyze_missing_bundle_is_clean_error(capsys):
    rc = main(["analyze", "/no/such/bundle.wtf"])
    assert rc == 2
    assert "error:" in capsys.readouterr().err
