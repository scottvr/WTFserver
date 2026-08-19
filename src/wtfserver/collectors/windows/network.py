"""Current network socket state collector (Windows).

Emits ``socket_state`` observations: TCP connections via
``Get-NetTCPConnection`` (Listen -> ``listening``, Established ->
``established``; transient states like TimeWait/CloseWait are not emitted
but their counts land in stats) and UDP listeners via ``Get-NetUDPEndpoint``.
Owning process names are resolved inside PowerShell from a PID->name table
built with ``Get-Process``. Loopback endpoints are collected too; analyzers
decide what to filter.
"""

from __future__ import annotations

import json
from typing import Any

from ...model import Category, Observation, to_iso
from ..base import CollectionContext, Collector, CollectorError, CollectorResult
from .powershell import PowerShellError

_PS_TCP = r"""
$names = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
$conns = Get-NetTCPConnection -ErrorAction Stop
$out = foreach ($c in $conns) {
    $owningPid = if ($null -ne $c.OwningProcess) { [int]$c.OwningProcess } else { $null }
    [pscustomobject]@{
        local_address  = [string]$c.LocalAddress
        local_port     = [int]$c.LocalPort
        remote_address = [string]$c.RemoteAddress
        remote_port    = [int]$c.RemotePort
        state          = [string]$c.State
        pid            = $owningPid
        process_name   = if ($null -ne $owningPid -and $names.ContainsKey($owningPid)) { $names[$owningPid] } else { $null }
    }
}
ConvertTo-Json -Compress -Depth 3 -InputObject @($out)
"""

_PS_UDP = r"""
$names = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
$eps = Get-NetUDPEndpoint -ErrorAction Stop
$out = foreach ($e in $eps) {
    $owningPid = if ($null -ne $e.OwningProcess) { [int]$e.OwningProcess } else { $null }
    [pscustomobject]@{
        local_address = [string]$e.LocalAddress
        local_port    = [int]$e.LocalPort
        pid           = $owningPid
        process_name  = if ($null -ne $owningPid -and $names.ContainsKey($owningPid)) { $names[$owningPid] } else { $null }
    }
}
ConvertTo-Json -Compress -Depth 3 -InputObject @($out)
"""


def _as_list(payload: Any, what: str) -> list:
    """ConvertTo-Json collapses a single element to a bare object."""
    if payload is None:
        return []
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return payload
    raise PowerShellError(f"unexpected {what} payload type: {type(payload).__name__}")


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _opt_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class NetworkCollector(Collector):
    name = "network"
    platforms = ("windows",)
    categories = (Category.SOCKET_STATE,)

    def collect(self, ctx: CollectionContext) -> CollectorResult:
        result = CollectorResult()
        timestamp = to_iso(ctx.now)
        ignored_states: dict[str, int] = {}

        tcp_ok = self._collect_tcp(ctx, result, timestamp, ignored_states)
        udp_ok = self._collect_udp(ctx, result, timestamp)

        if not tcp_ok and not udp_ok:
            # Neither sub-query yielded anything: this collector produced
            # nothing usable.
            for err in result.errors:
                err.fatal = True
        if ignored_states:
            result.stats["tcp_ignored_states"] = {
                state: ignored_states[state] for state in sorted(ignored_states)
            }
        return result

    def _collect_tcp(
        self,
        ctx: CollectionContext,
        result: CollectorResult,
        timestamp: str,
        ignored_states: dict[str, int],
    ) -> bool:
        try:
            entries = _as_list(ctx.runner.run_json(_PS_TCP), "TCP")
        except PowerShellError as exc:
            result.errors.append(
                CollectorError(self.name, f"TCP connection query failed: {exc}")
            )
            return False
        raw_ref = ctx.add_raw(
            "network_tcp.json", json.dumps(entries, ensure_ascii=False, indent=2)
        )
        result.stats["tcp_total"] = len(entries)
        for index, entry in enumerate(entries):
            try:
                obs = self._normalize_tcp(entry, timestamp, raw_ref, ignored_states)
            except (TypeError, ValueError, KeyError) as exc:
                result.errors.append(
                    CollectorError(
                        self.name, f"skipped malformed TCP entry {index}: {exc!r}"
                    )
                )
                continue
            if obs is not None:
                result.observations.append(obs)
        return True

    def _normalize_tcp(
        self,
        entry: Any,
        timestamp: str,
        raw_ref: str,
        ignored_states: dict[str, int],
    ) -> Observation | None:
        if not isinstance(entry, dict):
            raise TypeError(f"expected object, got {type(entry).__name__}")
        state = _opt_str(entry.get("state")) or ""
        lowered = state.lower()
        if lowered == "listen":
            action = "listening"
        elif lowered == "established":
            action = "established"
        else:
            key = state or "unknown"
            ignored_states[key] = ignored_states.get(key, 0) + 1
            return None

        local_port = entry.get("local_port")
        if local_port is None:
            raise KeyError("local_port missing")
        local_port = int(local_port)

        remote_host = None
        remote_port = None
        if action == "established":
            remote_host = _opt_str(entry.get("remote_address"))
            remote_port = _opt_int(entry.get("remote_port"))

        return Observation(
            id="",  # assigned by the bundle writer
            source=self.name,
            category=Category.SOCKET_STATE,
            timestamp=timestamp,
            action=action,
            process=_opt_str(entry.get("process_name")),
            remote_host=remote_host,
            remote_port=remote_port,
            attributes={
                "protocol": "tcp",
                "local_address": _opt_str(entry.get("local_address")),
                "local_port": local_port,
                "pid": _opt_int(entry.get("pid")),
                "state": state or None,
            },
            raw_reference=raw_ref,
        )

    def _collect_udp(
        self, ctx: CollectionContext, result: CollectorResult, timestamp: str
    ) -> bool:
        try:
            entries = _as_list(ctx.runner.run_json(_PS_UDP), "UDP")
        except PowerShellError as exc:
            result.errors.append(
                CollectorError(self.name, f"UDP endpoint query failed: {exc}")
            )
            return False
        raw_ref = ctx.add_raw(
            "network_udp.json", json.dumps(entries, ensure_ascii=False, indent=2)
        )
        result.stats["udp_total"] = len(entries)
        for index, entry in enumerate(entries):
            try:
                obs = self._normalize_udp(entry, timestamp, raw_ref)
            except (TypeError, ValueError, KeyError) as exc:
                result.errors.append(
                    CollectorError(
                        self.name, f"skipped malformed UDP entry {index}: {exc!r}"
                    )
                )
                continue
            result.observations.append(obs)
        return True

    def _normalize_udp(self, entry: Any, timestamp: str, raw_ref: str) -> Observation:
        if not isinstance(entry, dict):
            raise TypeError(f"expected object, got {type(entry).__name__}")
        local_port = entry.get("local_port")
        if local_port is None:
            raise KeyError("local_port missing")
        local_port = int(local_port)
        return Observation(
            id="",  # assigned by the bundle writer
            source=self.name,
            category=Category.SOCKET_STATE,
            timestamp=timestamp,
            action="listening",
            process=_opt_str(entry.get("process_name")),
            attributes={
                "protocol": "udp",
                "local_address": _opt_str(entry.get("local_address")),
                "local_port": local_port,
                "pid": _opt_int(entry.get("pid")),
                # UDP endpoints have no connection state; recorded as null.
                "state": None,
            },
            raw_reference=raw_ref,
        )


COLLECTOR = NetworkCollector()
