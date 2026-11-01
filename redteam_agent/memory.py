"""Engagement memory: findings, coverage, and what the planner should do next."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from .taxonomy import SEVERITY_RANK, escalate, label, suggests_agentic_effect_class


@dataclass
class Finding:
    id: str
    attack_id: str
    category: str
    framework: str
    title: str
    goal: str
    severity: str
    confidence: float
    reasoning: str
    indicators: list[str]
    payload: str
    mutation: str
    transcript: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0
    turn: int = 0
    needs_manual_review: bool = False
    # None = not attempted (budget, chains, or exploit_confirmation off),
    # True = the finding reproduced on a second probe, False = it did not.
    confirmed: bool | None = None
    confirm_with: str = ""
    agentic_class: str = "A0"

    @property
    def control_label(self) -> str:
        return label(self.framework, self.category)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["control_label"] = self.control_label
        return data


@dataclass
class CategoryState:
    probes: int = 0
    findings: int = 0
    best_severity: str = "info"
    working_mutations: list[str] = field(default_factory=list)
    exposed: bool = False


class Memory:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.coverage: dict[str, CategoryState] = {}
        self.attempts: dict[str, int] = {}
        self.tried_mutations: dict[str, set[str]] = {}
        self.probes: int = 0
        self.errors: int = 0
        self._next_id = 1

    # -- recording -------------------------------------------------------
    def record_probe(self, attack_id: str) -> None:
        self.probes += 1
        self.attempts[attack_id] = self.attempts.get(attack_id, 0) + 1

    def note_category(
        self,
        category: str,
        *,
        finding: bool = False,
        severity: str = "info",
        mutation: str = "",
    ) -> None:
        state = self.coverage.setdefault(category, CategoryState())
        state.probes += 1
        if finding:
            state.findings += 1
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(
                state.best_severity, 0
            ):
                state.best_severity = severity
            state.exposed = True
            if mutation and mutation not in state.working_mutations:
                state.working_mutations.append(mutation)

    def add_finding(
        self,
        *,
        attack: Any,
        verdict: Any,
        payload: str,
        mutation: str,
        transcript: str,
        tool_calls: list[dict[str, Any]],
        latency_ms: float,
        turn: int,
    ) -> Finding:
        tool_invoked = bool(tool_calls)
        agentic = suggests_agentic_effect_class(
            tool_invoked, text_reaches_sink=verdict.finding
        )
        severity = escalate(verdict.severity, 1) if tool_invoked else verdict.severity
        finding = Finding(
            id=f"RT-{self._next_id:03d}",
            attack_id=attack.id,
            category=attack.category,
            framework=attack.framework,
            title=attack.title,
            goal=attack.goal,
            severity=severity,
            confidence=verdict.confidence,
            reasoning=verdict.reasoning,
            indicators=verdict.indicators,
            payload=payload,
            mutation=mutation,
            transcript=transcript,
            tool_calls=tool_calls,
            latency_ms=round(latency_ms, 1),
            turn=turn,
            needs_manual_review=verdict.needs_manual_review,
            agentic_class=agentic,
        )
        self._next_id += 1
        self.findings.append(finding)
        return finding

    def note_error(self) -> None:
        self.errors += 1

    def note_mutation(self, category: str, mutation: str) -> None:
        self.tried_mutations.setdefault(category, set()).add(mutation)

    def mutation_tried(self, category: str, mutation: str) -> bool:
        return mutation in self.tried_mutations.get(category, set())

    def has_finding_for(self, attack_id: str) -> bool:
        """One confirmed finding per attack: later payloads only confirm it."""
        return any(f.attack_id == attack_id for f in self.findings)

    # -- planning --------------------------------------------------------
    def working_mutations(self, category: str) -> list[str]:
        return list(self.coverage.get(category, CategoryState()).working_mutations)

    def uncovered_categories(self, all_categories: tuple[str, ...]) -> list[str]:
        return [c for c in all_categories if self.coverage.get(c, CategoryState()).probes == 0]

    def attempts_for(self, attack_id: str) -> int:
        return self.attempts.get(attack_id, 0)

    def top_findings(self, limit: int = 10) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity_rank, reverse=True)[:limit]

    def severity_counts(self) -> dict[str, int]:
        counts = {k: 0 for k in SEVERITY_RANK}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def coverage_matrix(self, all_categories: tuple[str, ...]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for category in all_categories:
            state = self.coverage.get(category, CategoryState())
            rows.append(
                {
                    "category": category,
                    "label": label(
                        "OWASP-AGENTIC-2026" if category.startswith("ASI") else "OWASP-LLM-2025",
                        category,
                    ),
                    "probes": state.probes,
                    "findings": state.findings,
                    "best_severity": state.best_severity,
                    "exposed": state.exposed,
                    "working_mutations": state.working_mutations,
                }
            )
        return rows
