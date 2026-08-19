"""Analysis orchestration: run all analyzers over a bundle, in order.

Analyzer order matters only in one direction: later analyzers may consume
earlier analyzers' findings via ctx.prior_findings (role inference reads
recurrence/peer findings, for example). The order is fixed and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .analyzers import ANALYZERS
from .analyzers.base import AnalysisContext, build_context
from .bundle import Bundle
from .model import (
    EVIDENCE_UNKNOWN,
    Category,
    Finding,
    FindingType,
)


@dataclass
class AnalysisResult:
    manifest: dict[str, Any]
    findings: list[Finding]
    observations_summary: dict[str, Any] = field(default_factory=dict)
    # Host identity summary for reports: manifest hostname/platform merged with
    # the host_identity observation's attributes (os_name, domain, ...).
    host: dict[str, Any] = field(default_factory=dict)

    def of_type(self, finding_type: str) -> list[Finding]:
        return [f for f in self.findings if f.finding_type == finding_type]


def run_analysis(bundle: Bundle, options: dict[str, Any] | None = None) -> AnalysisResult:
    ctx = build_context(bundle.manifest, bundle.observations, options)
    all_findings: list[Finding] = []

    for analyzer in ANALYZERS:
        if analyzer.required_categories and not any(
            cat in ctx.by_category for cat in analyzer.required_categories
        ):
            continue
        try:
            findings = analyzer.analyze(ctx)
        except Exception as exc:  # one broken analyzer must not sink the report
            findings = [
                Finding(
                    id=ctx.next_finding_id(),
                    finding_type=FindingType.LIMITATION,
                    analyzer=analyzer.name,
                    conclusion=(
                        f"Analyzer '{analyzer.name}' failed and its findings are "
                        f"missing from this report: {type(exc).__name__}: {exc}"
                    ),
                    evidence_class=EVIDENCE_UNKNOWN,
                )
            ]
        all_findings.extend(findings)
        ctx.prior_findings = list(all_findings)

    return AnalysisResult(
        manifest=bundle.manifest,
        findings=all_findings,
        observations_summary=_summarize_observations(ctx),
        host=_host_summary(ctx),
    )


def _host_summary(ctx: AnalysisContext) -> dict[str, Any]:
    host: dict[str, Any] = {
        "hostname": ctx.manifest.get("hostname"),
        "platform": ctx.manifest.get("platform"),
    }
    identity = ctx.get(Category.HOST_IDENTITY)
    if identity:
        for key, value in identity[0].attributes.items():
            host.setdefault(key, value)
        host["host_identity_observation"] = identity[0].id
    return host


def _summarize_observations(ctx: AnalysisContext) -> dict[str, Any]:
    by_category = {cat: len(obs) for cat, obs in sorted(ctx.by_category.items())}
    by_source: dict[str, int] = {}
    for obs in ctx.observations:
        by_source[obs.source] = by_source.get(obs.source, 0) + 1
    return {
        "total": len(ctx.observations),
        "by_category": by_category,
        "by_source": dict(sorted(by_source.items())),
    }
