"""Collector registry.

COLLECTORS lists every available collector instance. The collection
orchestrator filters by platform tag; adding a platform or provider later
means adding entries here, not editing orchestration code.
"""

from __future__ import annotations

from .base import CollectionContext, Collector, CollectorError, CollectorResult

# Filled during integration; collector modules are imported lazily here so a
# broken import of one platform's collectors cannot break analysis-only use.
COLLECTORS: list[Collector] = []


def _register_windows() -> None:
    from .windows import WINDOWS_COLLECTORS

    COLLECTORS.extend(WINDOWS_COLLECTORS)


try:
    _register_windows()
except ImportError:
    pass

__all__ = [
    "COLLECTORS",
    "Collector",
    "CollectorError",
    "CollectorResult",
    "CollectionContext",
]
