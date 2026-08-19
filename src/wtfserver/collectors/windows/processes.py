"""Running-process state collector (Windows).

Emits one ``process_state`` observation per running process, via
``Get-CimInstance Win32_Process``. Owner lookup happens per process inside
the PowerShell script (``Invoke-CimMethod GetOwner``) and tolerates
per-process failure — protected/system processes simply carry no principal.
"""

from __future__ import annotations

import json
from typing import Any

from ...model import Category, Observation, parse_iso, to_iso
from ..base import CollectionContext, Collector, CollectorError, CollectorResult
from .powershell import PowerShellError

# CreationDate is serialized to ISO inside PS; GetOwner failures leave owner
# null instead of aborting the whole enumeration.
_PS_PROCESSES = r"""
$procs = Get-CimInstance Win32_Process -ErrorAction Stop
$out = foreach ($p in $procs) {
    $owner = $null
    try {
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
        if ($o -and $o.ReturnValue -eq 0 -and $o.User) {
            $owner = @{ user = [string]$o.User; domain = [string]$o.Domain }
        }
    } catch { }
    [pscustomobject]@{
        pid          = $p.ProcessId
        parent_pid   = $p.ParentProcessId
        name         = $p.Name
        path         = $p.ExecutablePath
        command_line = $p.CommandLine
        start_time   = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') } else { $null }
        owner        = $owner
    }
}
ConvertTo-Json -Compress -Depth 4 -InputObject @($out)
"""


def _as_list(payload: Any) -> list:
    """ConvertTo-Json collapses a single element to a bare object."""
    if payload is None:
        return []
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return payload
    raise PowerShellError(f"unexpected process payload type: {type(payload).__name__}")


def _format_principal(owner: Any) -> str | None:
    """DOMAIN\\user when both parts are present, bare user otherwise."""
    if not isinstance(owner, dict):
        return None
    user = owner.get("user")
    if not isinstance(user, str) or not user:
        return None
    domain = owner.get("domain")
    if isinstance(domain, str) and domain:
        return f"{domain}\\{user}"
    return user


def _opt_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


class ProcessesCollector(Collector):
    name = "processes"
    platforms = ("windows",)
    categories = (Category.PROCESS_STATE,)

    def collect(self, ctx: CollectionContext) -> CollectorResult:
        result = CollectorResult()
        try:
            payload = ctx.runner.run_json(_PS_PROCESSES)
            entries = _as_list(payload)
        except PowerShellError as exc:
            result.errors.append(
                CollectorError(self.name, f"process query failed: {exc}", fatal=True)
            )
            return result

        raw_ref = ctx.add_raw(
            "processes.json", json.dumps(entries, ensure_ascii=False, indent=2)
        )
        timestamp = to_iso(ctx.now)
        skipped = 0
        for index, entry in enumerate(entries):
            try:
                result.observations.append(self._normalize(entry, timestamp, raw_ref))
            except (TypeError, ValueError, KeyError) as exc:
                skipped += 1
                result.errors.append(
                    CollectorError(
                        self.name, f"skipped malformed process entry {index}: {exc!r}"
                    )
                )
        result.stats["process_count"] = len(result.observations)
        if skipped:
            result.stats["skipped_entries"] = skipped
        return result

    def _normalize(self, entry: Any, timestamp: str, raw_ref: str) -> Observation:
        if not isinstance(entry, dict):
            raise TypeError(f"expected object, got {type(entry).__name__}")
        pid = entry.get("pid")
        if pid is None:
            raise KeyError("pid missing")
        pid = int(pid)

        path = entry.get("path")
        name = entry.get("name")
        process = path if isinstance(path, str) and path else None
        if process is None:
            process = name if isinstance(name, str) and name else None

        command_line = entry.get("command_line")
        if not isinstance(command_line, str):
            command_line = None

        start_raw = entry.get("start_time")
        started = parse_iso(start_raw) if isinstance(start_raw, str) else None

        return Observation(
            id="",  # assigned by the bundle writer
            source=self.name,
            category=Category.PROCESS_STATE,
            timestamp=timestamp,
            action="running",
            process=process,
            principal=_format_principal(entry.get("owner")),
            attributes={
                "pid": pid,
                "parent_pid": _opt_int(entry.get("parent_pid")),
                "command_line": command_line,
                "start_time": to_iso(started) if started else None,
            },
            raw_reference=raw_ref,
        )


COLLECTOR = ProcessesCollector()
