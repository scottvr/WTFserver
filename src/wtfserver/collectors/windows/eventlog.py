"""Windows event log collector.

Enumerates every log channel for coverage, then reads history from enabled,
populated channels and normalizes well-known event IDs into platform-neutral
categories per docs/dev/CONTRACTS.md §2/§3. Everything else is kept as a
generic ``event`` observation so frequency analysis still sees it.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ...model import Category, Observation, parse_iso, to_iso
from ..base import CollectionContext, Collector, CollectorError, CollectorResult

_DEFAULT_MAX_EVENTS = 25000

_LOGON_TYPE_MAP = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    10: "remote_interactive",
}

_TASKSCHEDULER_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"
_TSLSM_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"

_LIST_CHANNELS_SCRIPT = (
    "Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object { "
    "[pscustomobject]@{ "
    "name = $_.LogName; "
    "enabled = [bool]$_.IsEnabled; "
    "record_count = [int64]$_.RecordCount; "
    "max_size_bytes = [int64]$_.MaximumSizeInBytes } "
    "| ConvertTo-Json -Compress -Depth 4 }"
)


def _ps_quote(value: str) -> str:
    return value.replace("'", "''")


def _edge_script(channel: str, oldest: bool) -> str:
    flag = " -Oldest" if oldest else ""
    return (
        f"$e = Get-WinEvent -LogName '{_ps_quote(channel)}' -MaxEvents 1{flag} "
        "-ErrorAction Stop; "
        "@{ t = $e.TimeCreated.ToUniversalTime().ToString('o') } "
        "| ConvertTo-Json -Compress"
    )


def _events_script(channel: str, since_iso: str | None, cap: int) -> str:
    start = ""
    if since_iso is not None:
        start = (
            f"; StartTime = [datetime]::Parse('{since_iso}', "
            "[System.Globalization.CultureInfo]::InvariantCulture, "
            "[System.Globalization.DateTimeStyles]::AdjustToUniversal)"
        )
    # Windows PowerShell 5.1 raises NoMatchingEventsFound when the filter
    # matches zero events, which is routine for a bounded --since window on a
    # healthy channel. The FullyQualifiedErrorId is culture-invariant, so it
    # is swallowed here (emit nothing, exit 0); every other failure is
    # rethrown so it surfaces as a real read error.
    return (
        "try { "
        f"Get-WinEvent -FilterHashtable @{{LogName='{_ps_quote(channel)}'{start}}} "
        f"-MaxEvents {cap} -ErrorAction Stop | ForEach-Object {{ "
        "$m = $_.Message; "
        "if ($m -ne $null -and $m.Length -gt 300) { $m = $m.Substring(0, 300) }; "
        "[pscustomobject]@{ "
        "t = $_.TimeCreated.ToUniversalTime().ToString('o'); "
        "id = $_.Id; "
        "provider = $_.ProviderName; "
        "channel = $_.LogName; "
        "level = $_.LevelDisplayName; "
        "record_id = $_.RecordId; "
        "props = @($_.Properties | Select-Object -First 20 "
        "| ForEach-Object { [string]$_.Value }); "
        "msg = $m } | ConvertTo-Json -Compress -Depth 4 } "
        "} catch { "
        "if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { } "
        "else { throw } }"
    )


def _sanitize_channel(channel: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", channel)


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        if text.lower().startswith("0x"):
            try:
                return int(text, 16)
            except ValueError:
                return None
        return None


def _prop(props: list[str], index: int) -> str | None:
    """Property value at index, or None if absent/empty/'-'."""
    if index < 0 or index >= len(props):
        return None
    value = props[index]
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    return text


def _principal(props: list[str], user_index: int, domain_index: int) -> str | None:
    user = _prop(props, user_index)
    if user is None:
        return None
    domain = _prop(props, domain_index)
    return f"{domain}\\{user}" if domain else user


def _clean_remote(value: str | None) -> str | None:
    """Drop absent/loopback/local pseudo-addresses; keep real source hosts."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    if text.upper() == "LOCAL":
        return None
    if text.startswith("127.") or text in ("::1", "0:0:0:0:0:0:0:1"):
        return None
    return text


def _truncate_message(msg: Any) -> str | None:
    if msg is None:
        return None
    text = str(msg)
    if not text:
        return None
    return text[:300]


class EventLogCollector(Collector):
    name = "eventlog"
    platforms = ("windows",)
    categories = (
        Category.EVIDENCE_CHANNEL,
        Category.EVENT,
        Category.LOGON,
        Category.PROCESS_ACTIVITY,
        Category.SERVICE_ACTIVITY,
        Category.SCHEDULED_ACTIVITY,
        Category.SYSTEM_LIFECYCLE,
    )

    def collect(self, ctx: CollectionContext) -> CollectorResult:
        result = CollectorResult()
        stats = {
            "channels": 0,
            "channels_read": 0,
            "events": 0,
            "malformed_rows": 0,
            "skipped_old": 0,
        }
        result.stats = stats

        try:
            listing = ctx.runner.run_jsonl(_LIST_CHANNELS_SCRIPT)
        except Exception as exc:
            result.errors.append(
                CollectorError(
                    collector=self.name,
                    message=f"channel enumeration failed: {exc}",
                    fatal=True,
                )
            )
            return result

        channels = []
        listing_lines = []
        for row in listing:
            if not isinstance(row, dict) or not row.get("name"):
                stats["malformed_rows"] += 1
                continue
            channels.append(row)
            listing_lines.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
        listing_raw_ref = ctx.add_raw(
            "eventlog_channels.jsonl", "\n".join(listing_lines) + ("\n" if listing_lines else "")
        )
        channels.sort(key=lambda row: str(row["name"]))
        stats["channels"] = len(channels)

        cap = int(ctx.options.get("max_events_per_channel", _DEFAULT_MAX_EVENTS))
        since_iso = to_iso(ctx.since) if ctx.since is not None else None
        collection_time = to_iso(ctx.now)

        for row in channels:
            channel = str(row["name"])
            enabled = bool(row.get("enabled"))
            record_count = _to_int(row.get("record_count")) or 0
            max_size = _to_int(row.get("max_size_bytes"))

            attrs: dict[str, Any] = {
                "channel": channel,
                "enabled": enabled,
                "record_count": record_count,
                "oldest_record": None,
                "newest_record": None,
                "max_size_bytes": max_size,
                "collected_events": 0,
                "truncated": False,
            }
            channel_obs = Observation(
                id="",
                source=self.name,
                category=Category.EVIDENCE_CHANNEL,
                timestamp=collection_time,
                action="inventoried",
                attributes=attrs,
                raw_reference=listing_raw_ref,
            )

            # Edges are queried for any populated channel (even disabled ones —
            # coverage wants the span); history only from enabled + populated.
            if record_count > 0:
                attrs["oldest_record"] = self._query_edge(ctx, channel, oldest=True)
                attrs["newest_record"] = self._query_edge(ctx, channel, oldest=False)

            if not enabled or record_count <= 0:
                result.observations.append(channel_obs)
                continue

            try:
                # Partial read: a corrupt record mid-channel must not throw
                # away the events already streamed before the failure.
                rows, read_error = ctx.runner.run_jsonl_partial(
                    _events_script(channel, since_iso, cap)
                )
            except Exception as exc:
                # Runner-level failure (timeout, PowerShell unavailable):
                # nothing was salvaged.
                attrs["error"] = str(exc)
                result.errors.append(
                    CollectorError(
                        collector=self.name,
                        message=f"failed to read channel {channel}: {exc}",
                    )
                )
                result.observations.append(channel_obs)
                continue

            stats["channels_read"] += 1
            # The PS query already filters on StartTime, so if the cap was hit
            # the truncated events were inside the requested window.
            attrs["truncated"] = len(rows) >= cap

            raw_lines = [
                json.dumps(r, ensure_ascii=False, sort_keys=True) for r in rows
            ]
            raw_ref = ctx.add_raw(
                f"events_{_sanitize_channel(channel)}.jsonl",
                "\n".join(raw_lines) + ("\n" if raw_lines else ""),
            )
            channel_obs.raw_reference = raw_ref

            events: list[Observation] = []
            for event_row in rows:
                obs, status = self._normalize_row(event_row, ctx, raw_ref)
                if status == "malformed":
                    stats["malformed_rows"] += 1
                    continue
                if status == "too_old":
                    stats["skipped_old"] += 1
                    continue
                events.append(obs)

            attrs["collected_events"] = len(events)
            if read_error is not None:
                partial_msg = (
                    f"read failed partway; {len(events)} events collected "
                    f"before the error: {read_error}"
                )
                attrs["error"] = partial_msg
                result.errors.append(
                    CollectorError(
                        collector=self.name,
                        message=f"channel {channel} {partial_msg}",
                    )
                )
            stats["events"] += len(events)
            result.observations.append(channel_obs)
            result.observations.extend(events)

        return result

    def _query_edge(self, ctx: CollectionContext, channel: str, oldest: bool) -> str | None:
        """Oldest/newest record time for a channel; failures tolerated as None."""
        try:
            payload = ctx.runner.run_json(_edge_script(channel, oldest=oldest))
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        when = parse_iso(str(payload.get("t") or ""))
        return to_iso(when) if when else None

    def _normalize_row(
        self, row: Any, ctx: CollectionContext, raw_ref: str
    ) -> tuple[Observation | None, str]:
        """Returns (observation, "ok") or (None, "malformed"|"too_old")."""
        if not isinstance(row, dict):
            return None, "malformed"
        when = parse_iso(str(row.get("t") or ""))
        event_id = _to_int(row.get("id"))
        if when is None or event_id is None:
            return None, "malformed"
        # Defense in depth: the PS query filters on StartTime already.
        if ctx.since is not None and when < ctx.since:
            return None, "too_old"

        channel = str(row.get("channel") or "")
        provider = str(row.get("provider") or "")
        level_raw = row.get("level")
        level = str(level_raw) if level_raw not in (None, "") else None
        props_raw = row.get("props")
        props = [str(p) if p is not None else "" for p in props_raw] if isinstance(props_raw, list) else []
        msg = _truncate_message(row.get("msg"))

        obs = Observation(
            id="",
            source=self.name,
            category=Category.EVENT,
            timestamp=to_iso(when),
            attributes={
                "channel": channel,
                "provider": provider,
                "event_id": event_id,
                "level": level,
            },
            raw_reference=raw_ref,
        )

        if channel == "Security":
            self._normalize_security(obs, event_id, props)
        elif channel == "System":
            self._normalize_system(obs, event_id, props)
        elif channel == _TASKSCHEDULER_CHANNEL:
            self._normalize_taskscheduler(obs, event_id, props)
        elif channel == _TSLSM_CHANNEL:
            self._normalize_tslsm(obs, event_id, props, msg)

        if obs.category == Category.EVENT:
            obs.message = msg if obs.message is None else obs.message
        return obs, "ok"

    # --- Security channel (Microsoft-Windows-Security-Auditing prop layouts) ---

    def _normalize_security(self, obs: Observation, event_id: int, props: list[str]) -> None:
        if event_id == 4624:
            self._logon(obs, "logon", props, user=5, domain=6, logon_type_idx=8,
                        ip_idx=18, process_idx=17)
        elif event_id == 4625:
            # 4625 layout differs from 4624: LogonType is prop 10, IpAddress 19.
            self._logon(obs, "logon_failed", props, user=5, domain=6,
                        logon_type_idx=10, ip_idx=19, process_idx=None)
        elif event_id == 4634:
            self._logon(obs, "logoff", props, user=1, domain=2, logon_type_idx=4,
                        ip_idx=None, process_idx=None)
        elif event_id == 4647:
            self._logon(obs, "logoff", props, user=1, domain=2, logon_type_idx=None,
                        ip_idx=None, process_idx=None)
        elif event_id == 4688:
            obs.category = Category.PROCESS_ACTIVITY
            obs.action = "start"
            obs.process = _prop(props, 5)
            obs.principal = _principal(props, user_index=1, domain_index=2)
            obs.attributes["command_line"] = _prop(props, 8)
            obs.attributes["parent_process"] = _prop(props, 13)
        elif event_id == 4689:
            obs.category = Category.PROCESS_ACTIVITY
            obs.action = "stop"
            obs.process = _prop(props, 6)
            obs.principal = _principal(props, user_index=1, domain_index=2)
            obs.attributes["command_line"] = None
            obs.attributes["parent_process"] = None

    def _logon(
        self,
        obs: Observation,
        action: str,
        props: list[str],
        user: int,
        domain: int,
        logon_type_idx: int | None,
        ip_idx: int | None,
        process_idx: int | None,
    ) -> None:
        obs.category = Category.LOGON
        obs.action = action
        obs.principal = _principal(props, user_index=user, domain_index=domain)
        logon_type = _to_int(_prop(props, logon_type_idx)) if logon_type_idx is not None else None
        obs.attributes["logon_type"] = logon_type
        obs.attributes["logon_kind"] = _LOGON_TYPE_MAP.get(logon_type, "other")
        if ip_idx is not None:
            obs.remote_host = _clean_remote(_prop(props, ip_idx))
        if process_idx is not None:
            obs.process = _prop(props, process_idx)

    # --- System channel ---

    def _normalize_system(self, obs: Observation, event_id: int, props: list[str]) -> None:
        if event_id == 7036:
            obs.category = Category.SERVICE_ACTIVITY
            obs.service = _prop(props, 0)
            state = _prop(props, 1)
            obs.attributes["state"] = state
            lowered = state.lower() if state else ""
            if lowered == "running":
                obs.action = "start"
            elif lowered == "stopped":
                obs.action = "stop"
            else:
                # Localized or unusual state text: keep it as a state change.
                obs.action = "state_change"
        elif event_id == 7045:
            obs.category = Category.SERVICE_ACTIVITY
            obs.action = "installed"
            obs.service = _prop(props, 0)
            obs.attributes["state"] = None
        elif event_id == 6005:
            obs.category = Category.SYSTEM_LIFECYCLE
            obs.action = "boot"
        elif event_id == 6006:
            obs.category = Category.SYSTEM_LIFECYCLE
            obs.action = "shutdown"
        elif event_id == 6008:
            obs.category = Category.SYSTEM_LIFECYCLE
            obs.action = "unexpected_shutdown"

    # --- Microsoft-Windows-TaskScheduler/Operational ---

    def _normalize_taskscheduler(self, obs: Observation, event_id: int, props: list[str]) -> None:
        actions = {
            100: "start",
            101: "failed",
            102: "complete",
            103: "failed",
            106: "registered",
            110: "start",
            111: "terminated",
            129: "action_start",
            200: "action_start",
            201: "action_complete",
        }
        action = actions.get(event_id)
        if action is None:
            return
        obs.category = Category.SCHEDULED_ACTIVITY
        obs.action = action
        obs.scheduled_action = _prop(props, 0)
        obs.attributes["result_code"] = None
        if event_id in (100, 101, 102, 106, 110):
            obs.principal = _prop(props, 1)
        if event_id == 101:
            obs.attributes["result_code"] = _to_int(_prop(props, 2))
        elif event_id == 129:
            obs.process = _prop(props, 1)  # Path
        elif event_id == 200:
            obs.process = _prop(props, 1)  # ActionName
        elif event_id == 201:
            obs.process = _prop(props, 2)  # ActionName
            obs.attributes["result_code"] = _to_int(_prop(props, 3))

    # --- Microsoft-Windows-TerminalServices-LocalSessionManager/Operational ---

    def _normalize_tslsm(
        self, obs: Observation, event_id: int, props: list[str], msg: str | None
    ) -> None:
        if event_id == 21:
            obs.category = Category.LOGON
            obs.action = "logon"
            obs.principal = _prop(props, 0)
            obs.remote_host = _clean_remote(_prop(props, 2))
            obs.attributes["logon_kind"] = "remote_interactive"
            obs.attributes["logon_type"] = None
        elif event_id == 23:
            obs.category = Category.LOGON
            obs.action = "logoff"
            obs.principal = _prop(props, 0)
            obs.attributes["logon_kind"] = "remote_interactive"
            obs.attributes["logon_type"] = None
        elif event_id == 24:
            obs.message = msg or "Remote session disconnected (TerminalServices-LocalSessionManager 24)"
        elif event_id == 25:
            obs.message = msg or "Remote session reconnected (TerminalServices-LocalSessionManager 25)"


COLLECTOR = EventLogCollector()
