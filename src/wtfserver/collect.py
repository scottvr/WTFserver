"""Collection orchestration: run collectors, write a versioned bundle.

Partial failure is normal on neglected servers. A collector that raises is
recorded as failed in the manifest and collection continues.
"""

from __future__ import annotations

import platform as _platform
import socket
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .bundle import BundleWriter
from .collectors import COLLECTORS
from .collectors.base import CollectionContext, Collector
from .model import to_iso, utc_now
from .timeparse import describe_since


def current_platform() -> str:
    system = _platform.system().lower()
    return {"windows": "windows", "linux": "linux", "darwin": "darwin"}.get(system, system)


def default_output_path(now: datetime) -> Path:
    host = socket.gethostname().split(".")[0].lower() or "host"
    stamp = now.strftime("%Y%m%d-%H%M%S")
    return Path(f"{host}-{stamp}.wtf")


def run_collection(
    since: datetime | None,
    output_path: str | Path,
    requested_since: str,
    collectors: list[Collector] | None = None,
    runner: Any = None,
    options: dict[str, Any] | None = None,
    host_platform: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Run all platform-appropriate collectors and write the bundle.

    Returns (bundle_path, manifest). ``runner`` and ``collectors`` are
    injectable for tests; by default a real PowerShellRunner is built on
    Windows.
    """
    plat = host_platform or current_platform()
    now = utc_now()
    if collectors is None:
        collectors = [c for c in COLLECTORS if plat in c.platforms]
    if runner is None and plat == "windows":
        from .collectors.windows.powershell import PowerShellRunner

        runner = PowerShellRunner()

    writer = BundleWriter(output_path)
    collector_records: list[dict[str, Any]] = []
    try:
        ctx = CollectionContext(
            since=since,
            now=now,
            runner=runner,
            add_raw=writer.add_raw,
            options=options or {},
        )
        for collector in collectors:
            record: dict[str, Any] = {"name": collector.name}
            started = time.monotonic()
            try:
                result = collector.collect(ctx)
            except Exception as exc:
                record["status"] = "failed"
                record["observation_count"] = 0
                record["errors"] = [f"{type(exc).__name__}: {exc}"]
                record["traceback"] = traceback.format_exc(limit=5)
                collector_records.append(record)
                continue
            for obs in result.observations:
                writer.add_observation(obs)
            errors = [e.message for e in result.errors]
            record["status"] = (
                "failed"
                if any(e.fatal for e in result.errors)
                else ("partial" if errors else "ok")
            )
            record["observation_count"] = len(result.observations)
            if errors:
                record["errors"] = errors
            if result.stats:
                record["stats"] = result.stats
            record["duration_seconds"] = round(time.monotonic() - started, 2)
            collector_records.append(record)

        manifest = {
            "tool": "wtfserver/whatami",
            "tool_version": __version__,
            "hostname": socket.gethostname(),
            "platform": plat,
            "collection_start": to_iso(now),
            "collection_end": to_iso(utc_now()),
            "requested_since": requested_since,
            "since_resolved": describe_since(since) if since else None,
            "collectors": collector_records,
        }
        bundle_path = writer.finalize(manifest)
        # Return the manifest as written (finalize adds observation_count etc.).
        return bundle_path, writer.manifest or manifest
    except BaseException:
        writer.abort()
        raise
