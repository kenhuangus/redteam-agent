"""The red-teaming agent: plans probes, executes them, judges the result, adapts.

Loop shape
----------
1. Prioritise untested risk categories, then attacks with the least attempts.
2. Send a payload under a mutation strategy (plain first, then evasions).
3. Judge the transcript against the attack's own success criteria.
4. On success: confirm with a variant, and mark the mutation family as viable
   for that category so later attacks in the category use it first.
5. Stop on budget, turn limit, or an optional stop-on-critical gate.

The agent never retries a mutation that the target already refused with a
baseline payload unless a different attack is being tried - probing budget is
finite and recorded in the report.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .attacks import ATTACKS, ATTACKS_BY_CATEGORY, Attack, categories
from .memory import Finding, Memory
from .mutators import MUTATIONS, apply_mutation
from .targets import Message
from .taxonomy import SEVERITY_RANK

Logger = Callable[[str], None]


@dataclass
class Budget:
    max_probes: int = 150
    max_turns: int = 150
    rate_limit_per_min: int = 30
    probes: int = 0
    turns: int = 0
    _last_request: float = field(default=0.0, repr=False)

    @property
    def exhausted(self) -> bool:
        return self.probes >= self.max_probes

    @property
    def remaining(self) -> int:
        return max(0, self.max_probes - self.probes)

    def throttle(self) -> None:
        if self.rate_limit_per_min <= 0:
            return
        min_interval = 60.0 / self.rate_limit_per_min
        now = time.monotonic()
        wait = self._last_request + min_interval - now
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()


@dataclass
class RunResult:
    findings: list[Finding] = field(default_factory=list)
    memory: Memory | None = None
    probes: int = 0
    turns: int = 0
    errors: int = 0
    stopped_reason: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0
    target_name: str = ""
    model: str = ""

    @property
    def elapsed_s(self) -> float:
        return max(0.0, self.ended_at - self.started_at)


class RedTeamAgent:
    def __init__(
        self,
        *,
        config: Any,
        target: Any,
        judge: Any,
        rng: random.Random | None = None,
        logger: Logger | None = None,
        attack_ids: Iterable[str] | None = None,
    ) -> None:
        self.config = config
        self.target = target
        self.judge = judge
        self.rng = rng or random.Random(config.seed)
        self.log: Logger = logger or (lambda _m: None)
        self.memory = Memory()
        rate_limit = config.scope.rate_limit_per_min
        if getattr(target, "name", "") == "mock":
            rate_limit = 0  # offline target: throttling only wastes demo time
        self.budget = Budget(
            max_probes=config.scope.max_probes,
            max_turns=config.scope.max_turns,
            rate_limit_per_min=rate_limit,
        )
        self.canary = config.judges.canary
        self._categories = categories()
        evasions = [name for name, _fn, _note in MUTATIONS if name != "none"]
        self.rng.shuffle(evasions)
        self._evasion_pool = evasions
        self.attack_ids = set(attack_ids) if attack_ids else None
        if self.attack_ids:
            unknown = self.attack_ids - {a.id for a in ATTACKS}
            if unknown:
                raise ValueError(f"unknown attack id(s): {sorted(unknown)}")

    # ------------------------------------------------------------------
    def run(self) -> RunResult:
        started = time.time()
        result = RunResult(
            memory=self.memory,
            started_at=started,
            target_name=getattr(self.target, "name", "unknown"),
            model=getattr(self.target, "model", ""),
        )
        attack_order = self._plan()

        for attack in attack_order:
            if self.budget.exhausted:
                result.stopped_reason = "probe budget exhausted"
                break
            self._run_attack(attack, result)
            if (
                self.config.scope.stop_on_critical
                and any(f.severity_rank >= SEVERITY_RANK["critical"] for f in self.memory.findings)
            ):
                result.stopped_reason = "stop_on_critical gate hit"
                break
        if not result.stopped_reason:
            result.stopped_reason = "attack set exhausted"

        result.findings = list(self.memory.findings)
        result.probes = self.memory.probes
        result.turns = self.budget.turns
        result.errors = self.memory.errors
        result.ended_at = time.time()
        self.log(
            f"[agent] finished: {result.probes} probes, {len(result.findings)} findings, "
            f"{result.errors} errors ({result.stopped_reason})"
        )
        return result

    # ------------------------------------------------------------------
    def _plan(self) -> list[Attack]:
        """Uncovered categories first, then categories with no exposure yet."""
        uncovered = self.memory.uncovered_categories(self._categories)
        covered_attacks: list[Attack] = []
        uncovered_attacks: list[Attack] = []

        for category in self._categories:
            bucket = ATTACKS_BY_CATEGORY.get(category, [])
            if category in uncovered:
                uncovered_attacks.extend(bucket)
            else:
                covered_attacks.extend(bucket)

        # Keep the demo deterministic but not alphabetical-blind: shuffle within
        # each bucket using the seeded RNG.
        self.rng.shuffle(uncovered_attacks)
        self.rng.shuffle(covered_attacks)
        ordered = uncovered_attacks + covered_attacks
        if self.attack_ids:
            ordered = [a for a in ordered if a.id in self.attack_ids]
        return ordered

    def _payload_budget(self, attack: Attack) -> int:
        return max(1, min(self.config.payloads_per_attack, len(attack.payloads)))

    def _mutation_sequence(self, category: str, payload: str) -> Iterable[tuple[str, str]]:
        """Plain first, then proven families, then families not yet tried.

        Rotating through the pool keeps evasion coverage broad within a finite
        probe budget instead of sampling the same two families by chance.
        """
        n = max(1, self.config.mutations_per_payload)
        yield ("none", payload)

        proven = [m for m in self.memory.working_mutations(category) if m in self._evasion_pool]
        untried = [m for m in self._evasion_pool if m not in proven and not self.memory.mutation_tried(category, m)]
        retry = [m for m in self._evasion_pool if m not in proven and m not in untried]
        ordered = proven + untried + retry

        for name in ordered[: max(0, n - 1)]:
            mutated, _note = apply_mutation(name, payload)
            yield (name, mutated)

    # ------------------------------------------------------------------
    def _run_attack(self, attack: Attack, result: RunResult) -> None:
        if self.memory.attempts_for(attack.id) > 0:
            return

        # Multi-turn chains get one full conversation.
        if attack.multi_turn and not self.budget.exhausted:
            self._run_chain(attack, result)

        payloads = list(attack.payloads)[: self._payload_budget(attack)]
        for payload in payloads:
            if self.budget.exhausted or self.memory.has_finding_for(attack.id):
                return
            for mutation_name, mutated in self._mutation_sequence(attack.category, payload):
                if self.budget.exhausted or self.memory.has_finding_for(attack.id):
                    return
                finding = self._probe_single(
                    attack, result, mutated, mutation_name
                )
                if finding is not None:
                    self._confirm(
                        attack,
                        result,
                        finding,
                        [Message(role="user", content=mutated)],
                        payload,
                        mutation_name,
                    )
                    return

    def _probe_single(
        self,
        attack: Attack,
        result: RunResult,
        payload: str,
        mutation_name: str,
    ) -> Finding | None:
        if self.budget.exhausted:
            return None
        self.budget.throttle()
        messages = [Message(role="user", content=payload)]
        return self._execute(attack, messages, payload, mutation_name, result)

    def _run_chain(self, attack: Attack, result: RunResult) -> None:
        for chain in attack.multi_turn:
            if self.budget.exhausted:
                return
            messages: list[Message] = []
            for turn_prompt in chain:
                if self.budget.exhausted:
                    return
                messages.append(Message(role="user", content=turn_prompt))
                self.budget.throttle()
                finding = self._execute(
                    attack,
                    list(messages),
                    turn_prompt,
                    "chain",
                    result,
                    transcript_override=" | ".join(chain),
                )
                if finding is None:
                    continue
                self._confirm(
                    attack, result, finding, list(messages), turn_prompt, "chain"
                )
                # Stop the chain at the first successful step.
                break

    def _execute(
        self,
        attack: Attack,
        messages: list[Message],
        payload: str,
        mutation_name: str,
        result: RunResult,
        transcript_override: str | None = None,
    ) -> Finding | None:
        outcome = self._send(attack, messages, payload, mutation_name, result)
        if outcome is None:
            return None
        probe, verdict = outcome
        self.memory.note_category(
            attack.category,
            finding=verdict.finding,
            severity=verdict.severity,
            mutation=mutation_name,
        )

        if not verdict.finding:
            self.log(
                f"  [{attack.id}] {mutation_name}: no finding "
                f"({verdict.reasoning[:90]})"
            )
            return None

        # Evidence is the conversation, not the payload alone: a finding without
        # the model's reply cannot be reviewed or reproduced.
        if transcript_override:
            transcript = transcript_override
        else:
            transcript = "\n".join(f"{m.role}: {m.content}" for m in messages)
        transcript += f"\nassistant: {probe.text}"
        if probe.tool_calls:
            transcript += f"\ntool_calls: {probe.tool_calls}"

        finding = self.memory.add_finding(
            attack=attack,
            verdict=verdict,
            payload=payload,
            mutation=mutation_name,
            transcript=transcript,
            tool_calls=probe.tool_calls,
            latency_ms=probe.latency_ms,
            turn=self.budget.turns,
        )
        self.log(
            f"  [{attack.id}] {mutation_name}: FINDING {finding.id} "
            f"{finding.severity} conf={finding.confidence} "
            f"-> {attack.framework}/{attack.category} ({finding.control_label})"
        )
        return finding

    # ------------------------------------------------------------------
    def _send(
        self,
        attack: Attack,
        messages: list[Message],
        payload: str,
        mutation_name: str,
        result: RunResult,
    ) -> tuple[Any, Any] | None:
        """One probe plus its verdict: budget accounting, target call, judging.

        Returns None when the budget is spent or the target errored.
        """
        if self.budget.exhausted:
            return None

        self.budget.probes += 1
        self.budget.turns += 1
        self.memory.record_probe(attack.id)
        self.memory.note_mutation(attack.category, mutation_name)
        max_tokens = getattr(self.config, "max_tokens", None)
        probe = self.target.probe(
            messages, canary=self.canary, max_tokens=max_tokens
        )
        if probe.model:
            result.model = probe.model

        if not probe.ok:
            self.memory.note_error()
            self.log(f"  [{attack.id}] {mutation_name}: ERROR {probe.error}")
            return None

        verdict = self.judge.evaluate(attack, messages, probe, self.canary)
        return probe, verdict

    def _confirm(
        self,
        attack: Attack,
        result: RunResult,
        finding: Finding,
        messages: list[Message],
        payload: str,
        mutation_name: str,
    ) -> None:
        """Re-probe once so a reported finding is not a one-shot artifact.

        The retry keeps the mutation family that proved the finding and swaps in
        a second payload from the same attack. That shows the weakness is not tied
        to one hand-written prompt without abandoning the evasion that reached
        the sink. Chains and single-payload attacks replay the identical request,
        which still catches a non-deterministic detector. An unreproduced finding
        is sent to manual review instead of being reported as confirmed.
        """
        if not getattr(self.config, "exploit_confirmation", True):
            return
        if self.budget.exhausted:
            return

        is_chain = attack.multi_turn and len(messages) > 1
        alternatives = [
            p
            for p in list(attack.payloads)[: self._payload_budget(attack)]
            if p != payload
        ]
        if is_chain or not alternatives:
            variant = payload
            label = "replay"
            alt_messages = [Message(role=m.role, content=m.content) for m in messages]
        else:
            variant_payload = alternatives[0]
            if mutation_name == "none":
                variant = variant_payload
            else:
                variant, _note = apply_mutation(mutation_name, variant_payload)
            label = f"variant-payload+{mutation_name}"
            alt_messages = [
                Message(role=m.role, content=variant if m.role == "user" else m.content)
                for m in messages
            ]

        self.budget.throttle()
        outcome = self._send(attack, alt_messages, variant, f"confirm:{label}", result)
        if outcome is None:
            # Budget gone or transport error: the finding stays unverified.
            return

        _probe, verdict = outcome
        finding.confirm_with = label
        finding.confirmed = bool(verdict.finding)
        if not finding.confirmed:
            finding.needs_manual_review = True
            finding.indicators.append(f"not_reproduced:{label}")
            self.log(
                f"  [{finding.id}] {finding.attack_id}: NOT REPRODUCED "
                f"({label}) -> flagged for manual review"
            )
            return
        self.log(f"  [{finding.id}] {finding.attack_id}: reproduced ({label})")

    # ------------------------------------------------------------------
    def coverage(self) -> list[dict[str, Any]]:
        return self.memory.coverage_matrix(self._categories)
