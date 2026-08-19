"""Windows collectors.

WINDOWS_COLLECTORS is the platform registry consumed by
wtfserver.collectors.COLLECTORS. Order matches docs/dev/CONTRACTS.md §8.
"""

from __future__ import annotations

from ..base import Collector
from .eventlog import COLLECTOR as _eventlog
from .host_identity import COLLECTOR as _host_identity
from .network import COLLECTOR as _network
from .processes import COLLECTOR as _processes
from .scheduled_tasks import COLLECTOR as _scheduled_tasks
from .services import COLLECTOR as _services
from .software import COLLECTOR as _software

WINDOWS_COLLECTORS: list[Collector] = [
    _eventlog,
    _services,
    _scheduled_tasks,
    _processes,
    _network,
    _host_identity,
    _software,
]
