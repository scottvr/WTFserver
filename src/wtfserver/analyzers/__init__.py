"""Analyzer registry.

ANALYZERS is the fixed, ordered list of analysis passes. Order is meaningful:
later analyzers may consume earlier findings via ctx.prior_findings.
Populated during integration as analyzer modules land. Intended order:

    coverage        -> evidence_coverage, limitation
    frequency       -> frequency_summary
    recurrence      -> recurring_scheduled_activity
    correlation     -> activity_episode
    associations    -> process_association
    peers           -> peer_dependency
    interactive     -> interactive_use
    configured_unobserved -> configured_but_unobserved
    roles           -> role_inference  (reads prior findings)
"""

from __future__ import annotations

from .base import AnalysisContext, Analyzer

ANALYZERS: list[Analyzer] = []

__all__ = ["ANALYZERS", "Analyzer", "AnalysisContext"]
