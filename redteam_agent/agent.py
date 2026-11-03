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

import hashlib
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .attacks import ATTACKS, ATTACKS_BY_CATEGORY, LIBRARY_VERSION, Attack, categories
from .evidence import EvidenceStore, sha256_hex
from .gates import FindingQualityGate
from .guard import Guard
from .memory import Finding, Memory
from .mutators import MUTATIONS, apply_mutation
from .payload_lab import PayloadLab
from .policy import PolicyEngine
from .retester import Retester, RetestVerdict
from .runstate import Frontier, IntentStatus, StopReason
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
        return self.probes >= self.max_probes or self.turns >= self.max_turns

    @property
    def exhausted_reason(self) -> str:
        if self.probes >= self.max_probes:
            return "probe budget exhausted"
        return "turn budget exhausted"

    @property
    def remaining(self) -> int:
        if self.exhausted:
            return 0
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
    stop_reason: StopReason | None = None
    frontier: dict[str, int] = field(default_factory=dict)
    audit: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    payload_lab: dict[str, Any] = field(default_factory=dict)
    planning_log: list[dict[str, Any]] = field(default_factory=list)
    read_only_policy: dict[str, Any] = field(default_factory=dict)

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

        # ARTEX-shaped roles: the loop schedules (frontier), a gate decides whether
        # a probe may leave, a dedicated retester judges reproduction, and an
        # evidence log proves which probe produced each finding.
        self.frontier = Frontier()
        self.guard = Guard()
        self.retester = Retester(logger=self.log)
        self.gate = (
            FindingQualityGate() if getattr(config, "quality_gate", True) else None
        )
        self.evidence = (
            EvidenceStore(
                config.evidence_dir,
                meta={
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "target": getattr(target, "name", "unknown"),
                    "model": getattr(target, "model", ""),
                    "canary": self.canary,
                    "seed": getattr(config, "seed", 0),
                    "library_version": LIBRARY_VERSION,
                    "library_sha256": sha256_hex(
                        repr([a.id for a in ATTACKS]).encode()
                    ),
                },
            )
            if getattr(config, "evidence_dir", "")
            else None
        )
        use_lab = getattr(config, "agentic_payloads", True)
        self._use_lab = use_lab
        self.lab: PayloadLab | None = None
        self.policy = PolicyEngine(
            allow_state_changing=getattr(config, "allow_state_changing", False)
        )
        self._last_probe: Any = None
        self._last_verdict: Any = None
        self._idle_rounds = 0
        self._consecutive_errors = 0

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
        stagnation_rounds = max(1, int(getattr(self.config, "stagnation_rounds", 6)))
        error_limit = max(1, int(getattr(self.config, "target_error_limit", 3)))

        for attack in attack_order:
            if self.budget.exhausted:
                result.stop_reason = StopReason(self.budget.exhausted_reason)
                break
            productive = self._run_attack(attack, result)
            self._idle_rounds = 0 if productive else self._idle_rounds + 1

            if (
                self.config.scope.stop_on_critical
                and any(f.severity_rank >= SEVERITY_RANK["critical"] for f in self.memory.findings)
            ):
                result.stop_reason = StopReason.CRITICAL_GATE
                break
            if self._consecutive_errors >= error_limit:
                result.stop_reason = StopReason.TARGET_UNHEALTHY
                self._drop_open_intents(IntentStatus.BLOCKED, "target unhealthy")
                break
            if self._idle_rounds >= stagnation_rounds:
                result.stop_reason = StopReason.STAGNATION
                self._drop_open_intents(IntentStatus.DROPPED, "stagnation")
                self.log(
                    f"[agent] stagnation: {self._idle_rounds} unproductive rounds in a row"
                )
                break

        if result.stop_reason is None:
            result.stop_reason = StopReason.ATTACKS_EXHAUSTED
        result.stopped_reason = result.stop_reason.value

        result.findings = list(self.memory.findings)
        result.probes = self.memory.probes
        result.turns = self.budget.turns
        result.errors = self.memory.errors
        result.audit = self.guard.snapshot()
        result.frontier = self.frontier.summary()
        if self.lab is not None:
            result.payload_lab = self.lab.summary()
        result.planning_log = getattr(self, "_planning_log", [])
        result.read_only_policy = self.policy.snapshot()
        result.ended_at = time.time()
        if self.evidence:
            manifest = self.evidence.seal(
                stop_reason=result.stopped_reason,
                probes=result.probes,
                findings=len(result.findings),
                errors=result.errors,
            )
            result.evidence = self.evidence.summary()
            result.evidence["manifest"] = str(manifest)
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
        # Planning is a hypothesis choice, not a fixed list: spend the budget on
        # categories the target has not been shown to be safe against, then
        # rotate the rest so coverage stays broad.
        self._planning_log = []
        for attack in ordered:
            route = tuple(f"payload-{i}" for i in range(self._payload_budget(attack)))
            if attack.multi_turn:
                route += tuple(f"chain-{i}" for i in range(len(attack.multi_turn)))
            self.frontier.register(attack.id, attack.category, route=route)
            self._planning_log.append({
                "attack_id": attack.id,
                "category": attack.category,
                "why": "uncovered category" if attack.category in uncovered else "coverage rotation",
                "route": list(route),
            })
        return ordered

    def _drop_open_intents(self, status: IntentStatus, reason: str) -> None:
        for intent in self.frontier.open_intents():
            self.frontier.settle(intent.attack_id, status, reason)

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
    def _run_attack(self, attack: Attack, result: RunResult) -> bool:
        """Execute one frontier intent; True when it produced a finding."""
        self.frontier.claim(attack.id)

        # Multi-turn chains get one full conversation.
        if attack.multi_turn and not self.budget.exhausted:
            self._run_chain(attack, result)

        payloads = list(attack.payloads)[: self._payload_budget(attack)]
        self.lab = (
            PayloadLab(
                self._evasion_pool,
                max(6, self.config.mutations_per_payload + 1),
                self.policy,
            )
            if self._use_lab
            else None
        )
        for payload in payloads:
            if self.budget.exhausted or self.memory.has_finding_for(attack.id):
                break
            if self.lab is None:
                variants = [(name, mutated, "static ladder") for name, mutated in self._mutation_sequence(attack.category, payload)]
            else:
                variants = []
                step = self.lab.initial(payload)
                if step is not None:
                    self.lab.history.append(step)
                limit = max(6, self.config.mutations_per_payload + 1)
                while step is not None and len(variants) < limit:
                    variants.append((step.mutation, step.payload, step.rationale))
                    step = self.lab.next(payload)
                    if step is not None:
                        self.lab.history.append(step)
            error_limit = max(1, int(getattr(self.config, "target_error_limit", 3)))
            for mutation_name, mutated, rationale in variants:
                if self.budget.exhausted or self.memory.has_finding_for(attack.id):
                    break
                if self._consecutive_errors >= error_limit:
                    # A dead host must not keep eating variants: the run-level
                    # breaker would stop after this attack anyway.
                    break
                if self.lab is not None:
                    self.log(f"  [{attack.id}] lab: {mutation_name} ({rationale})")
                finding = self._probe_single(attack, result, mutated, mutation_name)
                if self.lab is not None:
                    reason = ""
                    if self._last_verdict is not None:
                        reason = str(getattr(self._last_verdict, "reasoning", "") or "")
                    self.lab.observe(
                        probe_text=getattr(self._last_probe, "text", "") or "",
                        error=getattr(self._last_probe, "error", None),
                        tool_calls=getattr(self._last_probe, "tool_calls", None),
                        verdict_reason=reason,
                    )
                if finding is not None:
                    self._retest(
                        attack,
                        result,
                        finding,
                        [Message(role="user", content=mutated)],
                        payload,
                        mutation_name,
                    )
                    break

        found = self.memory.has_finding_for(attack.id)
        if found:
            self.frontier.settle(attack.id, IntentStatus.DONE)
        elif self.guard.blocked_for(attack.id) and not self.memory.attempts_for(attack.id):
            self.frontier.settle(attack.id, IntentStatus.BLOCKED, "blocked by pre-probe gate")
        else:
            self.frontier.settle(attack.id, IntentStatus.EXHAUSTED, "route exhausted")
        return found

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
                self._retest(
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
        probe, verdict, receipt = outcome
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
        if receipt:
            finding.probe_seq = int(receipt.get("seq", 0))
            finding.evidence_digest = str(receipt.get("digest", ""))
            finding.evidence_path = str(receipt.get("path", ""))
        if self.gate is not None:
            finding.quality = self.gate.evaluate(finding).to_dict()
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
    ) -> tuple[Any, Any, dict[str, Any] | None] | None:
        """One probe: gate, target call, judge, evidence row, attribution.

        Returns None when the gate blocked the probe, the budget is spent, or the
        target errored. A target error counts toward the unhealthy-target breaker
        that ``run`` watches, so a dead host cannot silently consume the budget.
        """
        if self.budget.exhausted:
            return None

        # Read-only guarantee: a payload whose prize is a mutating tool call does
        # not leave a live target unless the operator enabled state-changing
        # probes. The offline mock returns canned text and cannot change anything,
        # so it keeps its coverage; a real endpoint does not get the chance.
        enforce = getattr(self.target, "name", "") != "mock"
        effect = self.policy.check_attack_effect(
            tuple(getattr(attack.expect, "tool_prefixes", ()) or ())
        ) if enforce else None
        if effect is not None and not effect.allowed:
            self.log(f"  [{attack.id}] {mutation_name}: BLOCKED {effect.reason}")
            self.frontier.settle(attack.id, IntentStatus.BLOCKED, "read-only policy")
            return None

        allowed, reason = self.guard.pre_probe(
            attack_id=attack.id, payload=payload, mutation=mutation_name
        )
        if not allowed:
            self.log(f"  [{attack.id}] {mutation_name}: BLOCKED {reason}")
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

        self._last_probe = probe
        self._last_verdict = None
        if not probe.ok:
            self.memory.note_error()
            self._consecutive_errors += 1
            self.guard.post_probe(
                attack_id=attack.id, payload=payload, mutation=mutation_name,
                error=probe.error,
            )
            self._record_evidence(attack, mutation_name, payload, probe, None)
            self.log(f"  [{attack.id}] {mutation_name}: ERROR {probe.error}")
            return None

        self._consecutive_errors = 0
        verdict = self.judge.evaluate(attack, messages, probe, self.canary)
        self._last_verdict = verdict
        self.guard.post_probe(
            attack_id=attack.id, payload=payload, mutation=mutation_name,
            text=probe.text, tool_calls=probe.tool_calls, finding=verdict.finding,
        )
        receipt = self._record_evidence(attack, mutation_name, payload, probe, verdict)
        return probe, verdict, receipt

    def _record_evidence(
        self,
        attack: Attack,
        mutation_name: str,
        payload: str,
        probe: Any,
        verdict: Any,
    ) -> dict[str, Any] | None:
        """Hash-only evidence row: raw payloads and replies never hit the log."""
        if self.evidence is None:
            return None
        digest = self.evidence.record(
            attack_id=attack.id,
            category=attack.category,
            mutation=mutation_name,
            payload_sha256=sha256_hex(payload),
            payload_chars=len(payload),
            response_sha256=sha256_hex(probe.text or ""),
            response_chars=len(probe.text or ""),
            tool_calls=[str(tc.get("name", "")) for tc in probe.tool_calls],
            latency_ms=round(probe.latency_ms, 1),
            error=probe.error,
            finding=None if verdict is None else bool(verdict.finding),
        )
        return {
            "seq": self.evidence.rows,
            "digest": digest,
            "path": str(self.evidence.path),
        }

    def _retest(
        self,
        attack: Attack,
        result: RunResult,
        finding: Finding,
        messages: list[Message],
        payload: str,
        mutation_name: str,
    ) -> None:
        """Hand reproduction to the retester role (ARTEX ``agent/retester.go``).

        The retester picks the technique (variant payload under the same evasion,
        or an exact replay for chains and single-payload attacks), applies an
        evidence bar, and returns a named verdict. An ``inconclusive`` retest does
        not flip the finding to confirmed; a ``not_reproduced`` one sends it to
        manual review instead of publishing it as a confirmed exploit.
        """
        if not getattr(self.config, "exploit_confirmation", True):
            return
        if self.budget.exhausted:
            return

        alternatives = [
            p
            for p in list(attack.payloads)[: self._payload_budget(attack)]
            if p != payload
        ]
        self.budget.throttle()
        retest = self.retester.retest(
            attack=attack,
            messages=messages,
            payload=payload,
            mutation_name=mutation_name,
            alternatives=alternatives,
            send=lambda msgs, variant, label: self._send(
                attack, msgs, variant, f"confirm:{label}", result
            ),
        )
        finding.confirm_with = retest.technique
        finding.confirmed = retest.confirmed
        finding.reproduction_verdict = retest.verdict.value

        if retest.verdict is RetestVerdict.NOT_REPRODUCED:
            finding.needs_manual_review = True
            finding.indicators.append(f"not_reproduced:{retest.technique}")
            self.log(
                f"  [{finding.id}] {finding.attack_id}: NOT REPRODUCED "
                f"({retest.technique}) -> flagged for manual review"
            )
        elif retest.verdict is RetestVerdict.REPRODUCED:
            self.log(f"  [{finding.id}] {finding.attack_id}: reproduced ({retest.technique})")
        else:
            finding.needs_manual_review = True
            self.log(
                f"  [{finding.id}] {finding.attack_id}: retest INCONCLUSIVE "
                f"({retest.notes})"
            )

    # ------------------------------------------------------------------
    def coverage(self) -> list[dict[str, Any]]:
        return self.memory.coverage_matrix(self._categories)
