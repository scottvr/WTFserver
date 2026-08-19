"""Windows service configuration collector.

Queries Win32_Service via CIM and emits one ``service_state`` observation per
configured service. Windows-specific detail (PathName command-line parsing,
SCM start modes) stays here; observations expose the normalized vocabulary
plus the attribute keys defined in docs/dev/CONTRACTS.md.
"""

from __future__ import annotations

import json
from typing import Any

from ...model import Category, Observation, to_iso
from ..base import CollectionContext, Collector, CollectorError, CollectorResult

_SERVICES_SCRIPT = (
    "$svcs = @(Get-CimInstance Win32_Service -ErrorAction Stop | "
    "Select-Object Name, DisplayName, State, StartMode, StartName, PathName); "
    "ConvertTo-Json -InputObject $svcs -Compress -Depth 3"
)

# Extensions that mark the end of an unquoted executable path with arguments,
# e.g. "C:\Windows\system32\svchost.exe -k netsvcs".
_EXECUTABLE_EXTENSIONS = (".exe", ".bat", ".cmd", ".com")


def extract_executable(raw_path: Any) -> str | None:
    """Extract the bare executable path from a service command line.

    Handles quoted paths with arguments, unquoted paths with arguments, and
    null. Unquoted paths containing spaces are resolved by finding the first
    executable-extension boundary; if no boundary is found the first
    whitespace-delimited token is used.
    """
    if not isinstance(raw_path, str):
        return None
    text = raw_path.strip()
    if not text:
        return None
    if text.startswith('"'):
        end = text.find('"', 1)
        if end != -1:
            return text[1:end] or None
        return text[1:] or None  # unterminated quote: take the remainder
    lower = text.lower()
    for ext in _EXECUTABLE_EXTENSIONS:
        pos = 0
        while True:
            pos = lower.find(ext, pos)
            if pos == -1:
                break
            end = pos + len(ext)
            if end == len(text) or text[end] in (" ", "\t"):
                return text[:end]
            pos += 1
    return text.split()[0]


def _lowered(value: Any) -> str | None:
    if isinstance(value, str):
        return value.lower()
    return None


class ServicesCollector(Collector):
    name = "services"
    platforms = ("windows",)
    categories = (Category.SERVICE_STATE,)

    def collect(self, ctx: CollectionContext) -> CollectorResult:
        result = CollectorResult()
        try:
            payload = ctx.runner.run_json(_SERVICES_SCRIPT)
        except Exception as exc:
            result.errors.append(
                CollectorError(self.name, f"service query failed: {exc}", fatal=True)
            )
            return result

        if payload is None:
            entries: list[Any] = []
        elif isinstance(payload, dict):
            # ConvertTo-Json collapses a one-element array to a bare object.
            entries = [payload]
        elif isinstance(payload, list):
            entries = payload
        else:
            result.errors.append(
                CollectorError(
                    self.name,
                    f"unexpected service payload type: {type(payload).__name__}",
                    fatal=True,
                )
            )
            return result

        raw_ref = ctx.add_raw("services.json", json.dumps(entries, ensure_ascii=False))
        timestamp = to_iso(ctx.now)

        for index, entry in enumerate(entries):
            try:
                obs = self._normalize(entry, index, timestamp, raw_ref)
            except Exception as exc:
                result.errors.append(
                    CollectorError(self.name, f"service entry {index}: {exc}")
                )
                continue
            result.observations.append(obs)

        result.stats["services"] = len(result.observations)
        return result

    def _normalize(
        self, entry: Any, index: int, timestamp: str, raw_ref: str
    ) -> Observation:
        if not isinstance(entry, dict):
            raise ValueError(f"not an object: {type(entry).__name__}")
        service_name = entry.get("Name")
        if not isinstance(service_name, str) or not service_name.strip():
            raise ValueError("missing service Name")
        raw_path = entry.get("PathName")
        if not isinstance(raw_path, str):
            raw_path = None
        principal = entry.get("StartName")
        if not isinstance(principal, str):
            principal = None
        display_name = entry.get("DisplayName")
        if not isinstance(display_name, str):
            display_name = None
        return Observation(
            id="",
            source=self.name,
            category=Category.SERVICE_STATE,
            timestamp=timestamp,
            action="configured",
            principal=principal,
            process=extract_executable(raw_path),
            service=service_name,
            attributes={
                "display_name": display_name,
                "state": _lowered(entry.get("State")),
                "start_mode": _lowered(entry.get("StartMode")),
                "raw_path": raw_path,
            },
            raw_reference=f"{raw_ref}#{index}",
        )


COLLECTOR = ServicesCollector()
