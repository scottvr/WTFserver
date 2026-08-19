"""Windows collectors.

WINDOWS_COLLECTORS is the platform registry consumed by
wtfserver.collectors.COLLECTORS. Populated during integration as collector
modules land.
"""

from __future__ import annotations

from ..base import Collector

WINDOWS_COLLECTORS: list[Collector] = []
