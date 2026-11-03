"""Shared model for endpoint and web-application surface checks.

A surface check produces zero or one finding. The check records whether it is a
``finding`` (risk present), ``pass`` (checked, no risk), ``info`` (configuration
detail an operator should know) or ``error`` (the probe could not decide).
Findings carry the evidence a reviewer needs to reproduce them without re-running
the whole scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..taxonomy import SEVERITY_RANK


@dataclass
class SurfaceFinding:
    check_id: str
    title: str
    framework: str
    category: str
    severity: str
    target: str
    evidence: str = ""
    remediation: str = ""
    reproduction: str = ""
    confidence: float = 0.8
    status: str = "finding"  # finding | pass | info | error
    manual_review: bool = False
    notes: str = ""
    indicators: list[str] = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    @property
    def is_finding(self) -> bool:
        return self.status == "finding"

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "framework": self.framework,
            "category": self.category,
            "severity": self.severity,
            "target": self.target,
            "status": self.status,
            "evidence": self.evidence,
            "indicators": list(self.indicators),
            "confidence": round(self.confidence, 2),
            "remediation": self.remediation,
            "reproduction": self.reproduction,
            "manual_review": self.manual_review,
            "notes": self.notes,
        }


def pass_result(check_id: str, title: str, framework: str, category: str, target: str, evidence: str = "") -> SurfaceFinding:
    return SurfaceFinding(
        check_id=check_id,
        title=title,
        framework=framework,
        category=category,
        severity="info",
        target=target,
        evidence=evidence,
        status="pass",
    )


def info_result(check_id: str, title: str, framework: str, category: str, target: str, evidence: str = "", notes: str = "") -> SurfaceFinding:
    return SurfaceFinding(
        check_id=check_id,
        title=title,
        framework=framework,
        category=category,
        severity="info",
        target=target,
        evidence=evidence,
        status="info",
        notes=notes,
    )


def error_result(check_id: str, title: str, framework: str, category: str, target: str, error: str) -> SurfaceFinding:
    return SurfaceFinding(
        check_id=check_id,
        title=title,
        framework=framework,
        category=category,
        severity="info",
        target=target,
        status="error",
        notes=error,
    )


@dataclass
class SurfaceScan:
    """The result of one endpoint or one web-target scan."""

    target: str
    kind: str                      # web | windows | macos
    authorized_by: str = ""
    authorization_ref: str = ""
    results: list[SurfaceFinding] = field(default_factory=list)
    started_at: str = ""
    ended_at: str = ""
    elapsed_s: float = 0.0
    command: str = ""

    @property
    def findings(self) -> list[SurfaceFinding]:
        return sorted(
            [r for r in self.results if r.is_finding],
            key=lambda r: r.severity_rank,
            reverse=True,
        )

    def severity_counts(self) -> dict[str, int]:
        counts = {k: 0 for k in SEVERITY_RANK}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts
