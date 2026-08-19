"""Windows scheduled task configuration collector.

One PowerShell script joins Get-ScheduledTask with Get-ScheduledTaskInfo and
builds explicit objects, so serialization does not depend on CIM object
defaults. Emits one ``scheduled_task_state`` observation per task.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ...model import Category, Observation, parse_iso, to_iso
from ..base import CollectionContext, Collector, CollectorError, CollectorResult

_TASKS_SCRIPT = (
    "$tasks = @(Get-ScheduledTask -ErrorAction Stop); "
    "$out = foreach ($t in $tasks) { "
    "$info = $null; "
    "try { $info = Get-ScheduledTaskInfo -TaskPath $t.TaskPath -TaskName $t.TaskName "
    "-ErrorAction Stop } catch {}; "
    "[pscustomobject]@{ "
    "TaskPath = $t.TaskPath; "
    "TaskName = $t.TaskName; "
    "State = [string]$t.State; "
    "Principal = $t.Principal.UserId; "
    "Enabled = $t.Settings.Enabled; "
    "Hidden = $t.Settings.Hidden; "
    # Triggers/Actions are $null (not empty collections) for on-demand tasks,
    # and piping a real $null through ForEach-Object runs the block once,
    # producing a phantom all-null entry. Wrapping in @() does not help --
    # @($null) still enumerates one $null -- so filter nulls out first.
    "Actions = @($t.Actions | Where-Object { $null -ne $_ } | "
    "ForEach-Object { [pscustomobject]@{ "
    "Execute = $_.Execute; Arguments = $_.Arguments } }); "
    "Triggers = @($t.Triggers | Where-Object { $null -ne $_ } | "
    "ForEach-Object { [pscustomobject]@{ "
    "Class = $_.CimClass.CimClassName; StartBoundary = $_.StartBoundary; "
    "RepetitionInterval = $_.Repetition.Interval } }); "
    "LastRunTime = if ($info -and $info.LastRunTime) "
    "{ $info.LastRunTime.ToUniversalTime().ToString('o') } else { $null }; "
    "NextRunTime = if ($info -and $info.NextRunTime) "
    "{ $info.NextRunTime.ToUniversalTime().ToString('o') } else { $null }; "
    "LastTaskResult = if ($info) { $info.LastTaskResult } else { $null }; "
    "NumberOfMissedRuns = if ($info) { $info.NumberOfMissedRuns } else { $null } "
    "} }; "
    "ConvertTo-Json -InputObject @($out) -Compress -Depth 6"
)

# Trigger CIM class fragments -> short type strings. Checked before the
# repetition-interval fallback, per CONTRACTS.md ordering.
_TRIGGER_TYPES = (
    ("dailytrigger", "daily"),
    ("timetrigger", "time"),
    ("boottrigger", "boot"),
    ("logontrigger", "logon"),
)

# PowerShell ISO 8601 durations, e.g. PT15M, PT1H, P1DT2H30M.
_DURATION_RE = re.compile(
    r"^P(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$"
)

_FRACTION_RE = re.compile(r"\.\d+")


def parse_duration_seconds(value: Any) -> int | None:
    """Parse an ISO 8601 duration (as PS emits) to seconds; None if unparseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    match = _DURATION_RE.match(value.strip())
    if not match or not any(match.groupdict().values()):
        return None
    parts = {k: int(v) if v else 0 for k, v in match.groupdict().items()}
    return (
        parts["days"] * 86400
        + parts["hours"] * 3600
        + parts["minutes"] * 60
        + parts["seconds"]
    )


def _normalize_ps_datetime(value: Any) -> str | None:
    """Normalize a PS round-trip datetime string to ISO UTC with Z suffix.

    Task Scheduler reports never-ran as the COM epoch (year 1899); treat any
    pre-1900 timestamp as null.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = _FRACTION_RE.sub("", value.strip(), count=1)
    dt = parse_iso(text)
    if dt is None or dt.year < 1900:
        return None
    return to_iso(dt)


def _strip_quotes(value: str) -> str:
    return value.strip().strip('"')


class ScheduledTasksCollector(Collector):
    name = "scheduled_tasks"
    platforms = ("windows",)
    categories = (Category.SCHEDULED_TASK_STATE,)

    def collect(self, ctx: CollectionContext) -> CollectorResult:
        result = CollectorResult()
        try:
            payload = ctx.runner.run_json(_TASKS_SCRIPT)
        except Exception as exc:
            result.errors.append(
                CollectorError(self.name, f"scheduled task query failed: {exc}", fatal=True)
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
                    f"unexpected scheduled task payload type: {type(payload).__name__}",
                    fatal=True,
                )
            )
            return result

        raw_ref = ctx.add_raw(
            "scheduled_tasks.json", json.dumps(entries, ensure_ascii=False)
        )
        timestamp = to_iso(ctx.now)

        for index, entry in enumerate(entries):
            try:
                obs = self._normalize(entry, index, timestamp, raw_ref)
            except Exception as exc:
                result.errors.append(
                    CollectorError(self.name, f"scheduled task entry {index}: {exc}")
                )
                continue
            result.observations.append(obs)

        result.stats["scheduled_tasks"] = len(result.observations)
        return result

    def _normalize(
        self, entry: Any, index: int, timestamp: str, raw_ref: str
    ) -> Observation:
        if not isinstance(entry, dict):
            raise ValueError(f"not an object: {type(entry).__name__}")
        task_name = entry.get("TaskName")
        if not isinstance(task_name, str) or not task_name.strip():
            raise ValueError("missing TaskName")
        task_path = entry.get("TaskPath")
        base = task_path if isinstance(task_path, str) and task_path else "\\"
        if not base.endswith("\\"):
            base += "\\"
        full_path = base + task_name

        state = entry.get("State")
        if not isinstance(state, str):
            state = None
        enabled = entry.get("Enabled")
        if not isinstance(enabled, bool):
            # Fall back to task state; tasks default to enabled.
            enabled = not (isinstance(state, str) and state.lower() == "disabled")

        actions: list[dict[str, Any]] = []
        for act in self._as_list(entry.get("Actions")):
            if isinstance(act, dict) and not self._is_all_null(act):
                actions.append(
                    {"execute": act.get("Execute"), "arguments": act.get("Arguments")}
                )

        process = None
        for act in actions:
            execute = act["execute"]
            if isinstance(execute, str) and execute.strip():
                process = _strip_quotes(execute)
                break

        triggers = [
            self._normalize_trigger(trig)
            for trig in self._as_list(entry.get("Triggers"))
            if isinstance(trig, dict) and not self._is_all_null(trig)
        ]

        principal = entry.get("Principal")
        if not isinstance(principal, str):
            principal = None
        last_result = entry.get("LastTaskResult")
        if not isinstance(last_result, int) or isinstance(last_result, bool):
            last_result = None
        missed_runs = entry.get("NumberOfMissedRuns")
        if not isinstance(missed_runs, int) or isinstance(missed_runs, bool):
            missed_runs = None
        hidden = entry.get("Hidden")
        if not isinstance(hidden, bool):
            hidden = None

        return Observation(
            id="",
            source=self.name,
            category=Category.SCHEDULED_TASK_STATE,
            timestamp=timestamp,
            action="configured",
            principal=principal,
            process=process,
            scheduled_action=full_path,
            attributes={
                "enabled": enabled,
                "state": state,
                "actions": actions,
                "triggers": triggers,
                "last_run": _normalize_ps_datetime(entry.get("LastRunTime")),
                "next_run": _normalize_ps_datetime(entry.get("NextRunTime")),
                "last_result": last_result,
                "missed_runs": missed_runs,
                "hidden": hidden,
            },
            raw_reference=f"{raw_ref}#{index}",
        )

    @staticmethod
    def _is_all_null(item: dict[str, Any]) -> bool:
        """True for a dict carrying no information (every value null, or empty).

        The PS-side null filter should prevent phantom all-null trigger/action
        entries, but bundles produced by older collectors can still contain
        them; drop them defensively so they never reach analyzers.
        """
        return all(value is None for value in item.values())

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _normalize_trigger(trig: dict[str, Any]) -> dict[str, Any]:
        cim_class = trig.get("Class")
        class_lower = cim_class.lower() if isinstance(cim_class, str) else ""
        raw_interval = trig.get("RepetitionInterval")
        trigger_type = "other"
        for fragment, short in _TRIGGER_TYPES:
            if fragment in class_lower:
                trigger_type = short
                break
        else:
            if isinstance(raw_interval, str) and raw_interval.strip():
                trigger_type = "interval"
        interval: Any = parse_duration_seconds(raw_interval)
        if interval is None and isinstance(raw_interval, str) and raw_interval.strip():
            interval = raw_interval  # unparseable duration: keep the raw string
        start = trig.get("StartBoundary")
        if not isinstance(start, str) or not start.strip():
            start = None
        return {"type": trigger_type, "start": start, "interval": interval}


COLLECTOR = ScheduledTasksCollector()
