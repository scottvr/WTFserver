"""Analyzer registry.

ANALYZERS is the fixed, ordered list of analysis passes. Order is meaningful:
later analyzers may consume earlier findings via ctx.prior_findings (roles
must run last). Order matches docs/dev/CONTRACTS.md §8.
"""

from __future__ import annotations

from .associations import ANALYZER as _associations
from .base import AnalysisContext, Analyzer
from .configured_unobserved import ANALYZER as _configured_unobserved
from .correlation import ANALYZER as _correlation
from .coverage import ANALYZER as _coverage
from .frequency import ANALYZER as _frequency
from .interactive import ANALYZER as _interactive
from .peers import ANALYZER as _peers
from .recurrence import ANALYZER as _recurrence
from .roles import ANALYZER as _roles

ANALYZERS: list[Analyzer] = [
    _coverage,
    _frequency,
    _recurrence,
    _correlation,
    _associations,
    _peers,
    _interactive,
    _configured_unobserved,
    _roles,
]

__all__ = ["ANALYZERS", "Analyzer", "AnalysisContext"]
