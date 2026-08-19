"""Collector interface.

Collectors gather evidence and emit normalized observations. They do not
interpret what the host *is* — that belongs to analyzers. A collector that
fails partially should report errors and return what it got; one broken
source must not abort collection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from ..model import Observation


@dataclass
class CollectorError:
    collector: str
    message: str
    fatal: bool = False  # fatal = this collector produced nothing usable


@dataclass
class CollectorResult:
    observations: list[Observation] = field(default_factory=list)
    errors: list[CollectorError] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectionContext:
    """Everything a collector may depend on. Injectable for tests.

    ``since`` is None for --since max (use all available history).
    ``add_raw(name, content) -> raw_reference`` stores a raw payload in the
    bundle and returns the reference string to put on observations.
    ``runner`` is a PowerShell runner on Windows; collectors must not spawn
    processes any other way, so tests can substitute a fake.
    """

    since: datetime | None
    now: datetime
    runner: Any
    add_raw: Callable[[str, str | bytes], str]
    options: dict[str, Any] = field(default_factory=dict)


class Collector(ABC):
    """One evidence source.

    name: stable identifier, used as Observation.source.
    platforms: platform tags this collector supports, e.g. ("windows",).
    categories: observation categories this collector can produce.
    """

    name: str = ""
    platforms: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()

    @abstractmethod
    def collect(self, ctx: CollectionContext) -> CollectorResult:
        raise NotImplementedError
