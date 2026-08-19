"""PowerShell subprocess runner.

The only supported way for Windows collectors to reach the OS. Tests inject a
fake with the same interface, so collectors stay testable off-Windows.

Conventions for scripts passed to this runner:
  - Serialize datetimes explicitly to ISO 8601 UTC inside PowerShell
    (calculated properties with .ToUniversalTime().ToString('o')); never let
    ConvertTo-Json emit /Date(...)/ forms.
  - Emit compact JSON: ConvertTo-Json -Compress with an explicit -Depth.
  - Suppress progress/noise; script errors should be handled with
    -ErrorAction SilentlyContinue where per-item failure is tolerable.
"""

from __future__ import annotations

import json
import shutil
import subprocess

_PRELUDE = (
    "$ProgressPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
)


class PowerShellError(RuntimeError):
    def __init__(self, message: str, stderr: str = "", returncode: int | None = None):
        super().__init__(message)
        self.stderr = stderr
        self.returncode = returncode


class PowerShellUnavailableError(PowerShellError):
    pass


class PowerShellRunner:
    """Runs PowerShell snippets and parses their JSON output."""

    def __init__(self, executable: str | None = None, timeout: float = 600.0):
        self.executable = executable or self._find_executable()
        self.timeout = timeout

    @staticmethod
    def _find_executable() -> str:
        for candidate in ("powershell.exe", "powershell", "pwsh"):
            path = shutil.which(candidate)
            if path:
                return path
        raise PowerShellUnavailableError("no PowerShell executable found on PATH")

    def run_text(self, script: str, timeout: float | None = None) -> str:
        try:
            proc = subprocess.run(
                [
                    self.executable,
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    _PRELUDE + script,
                ],
                capture_output=True,
                timeout=timeout or self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise PowerShellError(f"PowerShell timed out after {exc.timeout}s") from exc
        except OSError as exc:
            raise PowerShellUnavailableError(f"cannot run {self.executable}: {exc}") from exc
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        if proc.returncode != 0:
            raise PowerShellError(
                f"PowerShell exited {proc.returncode}: {stderr[:500]}",
                stderr=stderr,
                returncode=proc.returncode,
            )
        return stdout

    def run_json(self, script: str, timeout: float | None = None):
        """Run a script whose stdout is one JSON document (or empty -> None)."""
        out = self.run_text(script, timeout=timeout).strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            raise PowerShellError(f"PowerShell output was not valid JSON: {out[:300]}") from exc

    def run_jsonl(self, script: str, timeout: float | None = None) -> list:
        """Run a script that emits one compact JSON document per line."""
        out = self.run_text(script, timeout=timeout)
        items = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                # One mangled line (e.g. truncated message) should not lose the rest.
                continue
        return items
