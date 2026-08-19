"""Shared test helpers, as specified in docs/dev/CONTRACTS.md §7."""

from __future__ import annotations

import itertools
from typing import Any

from wtfserver.analyzers.base import AnalysisContext, build_context
from wtfserver.model import Observation

_obs_counter = itertools.count(1)


def make_obs(category: str, **kwargs: Any) -> Observation:
    """Build an Observation with sensible test defaults."""
    defaults: dict[str, Any] = {
        "id": f"obs-{next(_obs_counter):06d}",
        "source": "test",
        "category": category,
    }
    defaults.update(kwargs)
    return Observation(**defaults)


def make_manifest(**overrides: Any) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "bundle_format": "wtf-bundle",
        "schema_version": 1,
        "tool": "wtfserver/whatami",
        "tool_version": "0.1.0-test",
        "hostname": "testhost",
        "platform": "windows",
        "collection_start": "2026-08-19T12:00:00Z",
        "collection_end": "2026-08-19T12:05:00Z",
        "requested_since": "72h",
        "since_resolved": "2026-08-16T12:00:00Z",
        "collectors": [],
    }
    manifest.update(overrides)
    return manifest


def build_ctx(
    observations: list[Observation],
    manifest: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
) -> AnalysisContext:
    return build_context(manifest or make_manifest(), observations, options)


class FakePowerShell:
    """Substring-matched canned PowerShell responses.

    responses: ordered list of (substring, payload) pairs. The first pair
    whose substring occurs in the submitted script supplies the payload.
    A payload that is an Exception instance is raised instead of returned.
    """

    def __init__(self, responses: list[tuple[str, Any]]):
        self.responses = list(responses)
        self.calls: list[str] = []

    def _match(self, script: str) -> Any:
        self.calls.append(script)
        for substring, payload in self.responses:
            if substring in script:
                if isinstance(payload, Exception):
                    raise payload
                return payload
        raise AssertionError(f"FakePowerShell: no canned response matches script:\n{script}")

    def run_json(self, script: str, timeout: float | None = None) -> Any:
        return self._match(script)

    def run_jsonl(self, script: str, timeout: float | None = None) -> list:
        payload = self._match(script)
        assert isinstance(payload, list), "run_jsonl payload must be a list"
        return payload

    def run_jsonl_partial(
        self, script: str, timeout: float | None = None
    ) -> tuple[list, Any]:
        """Payload may be a list -> (list, None), or an (items, error) tuple."""
        payload = self._match(script)
        if isinstance(payload, tuple):
            items, error = payload
            assert isinstance(items, list)
            return items, error
        assert isinstance(payload, list), "run_jsonl_partial payload must be list or tuple"
        return payload, None

    def run_raw(self, script: str, timeout: float | None = None) -> tuple[str, str, int]:
        """Payload may be a str -> (str, '', 0), or a (stdout, stderr, rc) tuple."""
        payload = self._match(script)
        if isinstance(payload, tuple):
            assert len(payload) == 3
            return payload
        assert isinstance(payload, str), "run_raw payload must be str or tuple"
        return payload, "", 0

    def run_text(self, script: str, timeout: float | None = None) -> str:
        payload = self._match(script)
        assert isinstance(payload, str), "run_text payload must be a str"
        return payload
