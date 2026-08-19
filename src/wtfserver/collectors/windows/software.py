"""Windows installed roles/features and installed software collector.

Roles come from Get-WindowsFeature (server SKUs only; the cmdlet's absence on
client SKUs is a per-source error, not a collector failure). Installed
software comes from the registry uninstall keys, both the native and
WOW6432Node hives, through one PowerShell script.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ...model import Category, Observation, to_iso
from ..base import CollectionContext, Collector, CollectorError, CollectorResult

_ROLES_SCRIPT = (
    "if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { "
    "$roles = @(Get-WindowsFeature | Where-Object { $_.Installed } | "
    "Select-Object Name, DisplayName); "
    "ConvertTo-Json -InputObject $roles -Compress -Depth 2 "
    "} else { "
    "ConvertTo-Json -InputObject ([pscustomobject]@{ unavailable = $true }) -Compress "
    "}"
)

_SOFTWARE_SCRIPT = (
    "$keys = @("
    "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
    "); "
    "$items = @(foreach ($k in $keys) { "
    "Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | "
    "Select-Object DisplayName, DisplayVersion, Publisher, InstallDate }); "
    "ConvertTo-Json -InputObject $items -Compress -Depth 2"
)


def parse_install_date(value: Any) -> str | None:
    """Parse a registry InstallDate (yyyyMMdd) to ISO UTC; None if unparseable."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) != 8 or not text.isdigit():
        return None
    try:
        dt = datetime(
            int(text[0:4]), int(text[4:6]), int(text[6:8]), tzinfo=timezone.utc
        )
    except ValueError:
        return None
    return to_iso(dt)


def _optional_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


class SoftwareCollector(Collector):
    name = "software"
    platforms = ("windows",)
    categories = (Category.INSTALLED_ROLE, Category.INSTALLED_SOFTWARE)

    def collect(self, ctx: CollectionContext) -> CollectorResult:
        result = CollectorResult()
        timestamp = to_iso(ctx.now)
        roles_failed = self._collect_roles(ctx, result, timestamp)
        software_failed = self._collect_software(ctx, result, timestamp)
        if roles_failed and software_failed:
            result.errors.append(
                CollectorError(self.name, "all software evidence queries failed", fatal=True)
            )
        return result

    def _collect_roles(
        self, ctx: CollectionContext, result: CollectorResult, timestamp: str
    ) -> bool:
        """Collect installed roles/features. Returns True if the query failed."""
        try:
            payload = ctx.runner.run_json(_ROLES_SCRIPT)
        except Exception as exc:
            result.errors.append(CollectorError(self.name, f"role query failed: {exc}"))
            return True

        if isinstance(payload, dict) and payload.get("unavailable"):
            result.errors.append(
                CollectorError(
                    self.name,
                    "Get-WindowsFeature not available (client SKU?); "
                    "installed roles not collected",
                )
            )
            return True

        entries = self._as_list(payload)
        if entries is None:
            result.errors.append(
                CollectorError(
                    self.name,
                    f"unexpected role payload type: {type(payload).__name__}",
                )
            )
            return True

        raw_ref = ctx.add_raw("roles.json", json.dumps(entries, ensure_ascii=False))
        count = 0
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                result.errors.append(
                    CollectorError(self.name, f"role entry {index}: not an object")
                )
                continue
            name = _optional_str(entry.get("Name"))
            if name is None:
                result.errors.append(
                    CollectorError(self.name, f"role entry {index}: missing Name")
                )
                continue
            display_name = _optional_str(entry.get("DisplayName"))
            result.observations.append(
                Observation(
                    id="",
                    source=self.name,
                    category=Category.INSTALLED_ROLE,
                    timestamp=timestamp,
                    action="installed",
                    message=display_name or name,
                    attributes={"name": name, "display_name": display_name},
                    raw_reference=f"{raw_ref}#{index}",
                )
            )
            count += 1
        result.stats["installed_roles"] = count
        return False

    def _collect_software(
        self, ctx: CollectionContext, result: CollectorResult, timestamp: str
    ) -> bool:
        """Collect installed software. Returns True if the query failed."""
        try:
            payload = ctx.runner.run_json(_SOFTWARE_SCRIPT)
        except Exception as exc:
            result.errors.append(
                CollectorError(self.name, f"software query failed: {exc}")
            )
            return True

        entries = self._as_list(payload)
        if entries is None:
            result.errors.append(
                CollectorError(
                    self.name,
                    f"unexpected software payload type: {type(payload).__name__}",
                )
            )
            return True

        raw_ref = ctx.add_raw("software.json", json.dumps(entries, ensure_ascii=False))
        count = 0
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                result.errors.append(
                    CollectorError(self.name, f"software entry {index}: not an object")
                )
                continue
            name = _optional_str(entry.get("DisplayName"))
            if name is None:
                # Uninstall keys without DisplayName (patches, components) are
                # normal registry noise, not errors.
                continue
            result.observations.append(
                Observation(
                    id="",
                    source=self.name,
                    category=Category.INSTALLED_SOFTWARE,
                    timestamp=timestamp,
                    action="installed",
                    message=name,
                    attributes={
                        "name": name,
                        "version": _optional_str(entry.get("DisplayVersion")),
                        "vendor": _optional_str(entry.get("Publisher")),
                        "install_date": parse_install_date(entry.get("InstallDate")),
                    },
                    raw_reference=f"{raw_ref}#{index}",
                )
            )
            count += 1
        result.stats["installed_software"] = count
        return False

    @staticmethod
    def _as_list(payload: Any) -> list[Any] | None:
        """Normalize a ConvertTo-Json payload to a list; None if unusable."""
        if payload is None:
            return []
        if isinstance(payload, dict):
            # ConvertTo-Json collapses a one-element array to a bare object.
            return [payload]
        if isinstance(payload, list):
            return payload
        return None


COLLECTOR = SoftwareCollector()
