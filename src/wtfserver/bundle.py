"""Versioned collection bundle: write and read .wtf files.

A bundle is a zip archive (or, for tests/fixtures, a plain directory) laid out as:

    manifest.json         provenance and collector results
    observations.jsonl    normalized observations, one JSON object per line
    raw/                  source-specific payloads for debugging / re-analysis

The writer stages files in a temporary directory and zips at finalize so a
crashed collection never leaves a half-written archive that parses.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .model import SCHEMA_VERSION, Observation

BUNDLE_FORMAT = "wtf-bundle"


class BundleError(Exception):
    pass


class BundleWriter:
    """Accumulates observations and raw files, then writes a .wtf zip.

    Observation IDs are assigned sequentially here so every observation in a
    bundle has a unique, stable ID that findings can reference.
    """

    def __init__(self, output_path: str | Path):
        self.output_path = Path(output_path)
        self._staging = Path(tempfile.mkdtemp(prefix="wtf-bundle-"))
        (self._staging / "raw").mkdir()
        self._obs_file = open(self._staging / "observations.jsonl", "w", encoding="utf-8")
        self._count = 0
        self._finalized = False
        #: The manifest as actually written to disk (set by finalize()).
        self.manifest: dict[str, Any] | None = None

    def next_observation_id(self) -> str:
        return f"obs-{self._count + 1:06d}"

    def add_observation(self, obs: Observation) -> str:
        """Write one observation. Assigns an ID if the collector left it empty."""
        if not obs.id:
            obs.id = self.next_observation_id()
        self._obs_file.write(json.dumps(obs.to_json_dict(), ensure_ascii=False) + "\n")
        self._count += 1
        return obs.id

    def add_raw(self, name: str, content: str | bytes) -> str:
        """Store a raw payload under raw/<name>; returns the raw reference."""
        safe = name.replace("\\", "_").replace("/", "_").replace(":", "_")
        path = self._staging / "raw" / safe
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return f"raw/{safe}"

    @property
    def observation_count(self) -> int:
        return self._count

    def finalize(self, manifest: dict[str, Any]) -> Path:
        if self._finalized:
            raise BundleError("bundle already finalized")
        self._obs_file.close()
        manifest = dict(manifest)
        manifest.setdefault("bundle_format", BUNDLE_FORMAT)
        manifest.setdefault("schema_version", SCHEMA_VERSION)
        manifest["observation_count"] = self._count
        self.manifest = manifest
        (self._staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(self.output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(self._staging.rglob("*")):
                if path.is_file():
                    zf.write(path, path.relative_to(self._staging).as_posix())
        shutil.rmtree(self._staging, ignore_errors=True)
        self._finalized = True
        return self.output_path

    def abort(self) -> None:
        try:
            self._obs_file.close()
        except Exception:
            pass
        shutil.rmtree(self._staging, ignore_errors=True)


@dataclass
class Bundle:
    """A loaded bundle: manifest plus normalized observations."""

    path: Path
    manifest: dict[str, Any]
    observations: list[Observation]
    _raw_reader: Any = field(default=None, repr=False)

    @classmethod
    def load(cls, path: str | Path) -> "Bundle":
        p = Path(path)
        if p.is_dir():
            return cls._load_dir(p)
        if p.is_file():
            return cls._load_zip(p)
        raise BundleError(f"bundle not found: {p}")

    @classmethod
    def _load_dir(cls, p: Path) -> "Bundle":
        manifest_path = p / "manifest.json"
        if not manifest_path.is_file():
            raise BundleError(f"not a bundle (missing manifest.json): {p}")
        manifest = _parse_manifest(manifest_path.read_text(encoding="utf-8"), p)
        _check_version(manifest, p)
        observations = []
        obs_path = p / "observations.jsonl"
        if obs_path.is_file():
            with open(obs_path, encoding="utf-8") as fh:
                observations = _parse_jsonl(fh)
        return cls(path=p, manifest=manifest, observations=observations)

    @classmethod
    def _load_zip(cls, p: Path) -> "Bundle":
        try:
            zf = zipfile.ZipFile(p)
        except zipfile.BadZipFile as exc:
            raise BundleError(f"not a bundle (bad zip): {p}") from exc
        names = set(zf.namelist())
        if "manifest.json" not in names:
            raise BundleError(f"not a bundle (missing manifest.json): {p}")
        manifest = _parse_manifest(zf.read("manifest.json").decode("utf-8"), p)
        _check_version(manifest, p)
        observations = []
        if "observations.jsonl" in names:
            text = zf.read("observations.jsonl").decode("utf-8")
            observations = _parse_jsonl(text.splitlines())
        return cls(path=p, manifest=manifest, observations=observations, _raw_reader=zf)

    def open_raw(self, raw_reference: str) -> bytes:
        """Read a raw payload by its raw/... reference."""
        name = raw_reference.split("#", 1)[0]
        if self._raw_reader is not None:
            return self._raw_reader.read(name)
        return (self.path / name).read_bytes()

    def raw_names(self) -> list[str]:
        if self._raw_reader is not None:
            return [n for n in self._raw_reader.namelist() if n.startswith("raw/")]
        raw_dir = self.path / "raw"
        if not raw_dir.is_dir():
            return []
        return sorted(f"raw/{f.name}" for f in raw_dir.iterdir() if f.is_file())


def _parse_manifest(text: str, path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BundleError(f"not a bundle (invalid manifest.json): {path}") from exc
    if not isinstance(manifest, dict):
        raise BundleError(f"not a bundle (manifest.json is not an object): {path}")
    return manifest


def _check_version(manifest: dict[str, Any], path: Path) -> None:
    version = manifest.get("schema_version")
    if version is None:
        raise BundleError(f"bundle has no schema_version: {path}")
    if not isinstance(version, int) or version > SCHEMA_VERSION:
        raise BundleError(
            f"bundle schema_version {version!r} is newer than this tool "
            f"supports ({SCHEMA_VERSION}); upgrade whatami"
        )


def _parse_jsonl(lines: Iterator[str] | list[str]) -> list[Observation]:
    observations = []
    for lineno, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BundleError(f"observations.jsonl line {lineno}: invalid JSON") from exc
        try:
            observations.append(Observation.from_json_dict(data))
        except TypeError as exc:
            raise BundleError(
                f"observations.jsonl line {lineno}: not a valid observation ({exc})"
            ) from exc
    return observations
