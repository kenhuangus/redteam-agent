"""A ReAct loop: reason about the current observation, pick one action, observe again.

The loop is generic over a catalog of read-only actions. Two reasoners exist:

* ``RuleReasoner`` scores actions against live hypotheses. It is deterministic,
  testable, and always available.
* ``LLMReasoner`` asks an OpenAI-compatible model for the next action, then
  validates the reply against the catalog and the read-only policy. A rejected or
  malformed reply falls back to ``RuleReasoner`` for that step, so a model outage
  degrades to rules instead of stopping the run.

The engine refuses to re-run the same action with the same arguments unless the
action declares ``repeatable``; repeated identical steps increment stagnation and
stop the loop, mirroring the harness-level stagnation guard.
"""

from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from .policy import Decision, Effect, PolicyEngine, tool_effect
from .surface.model import SurfaceFinding


@dataclass
class Observation:
    """What one action returned."""

    action: str
    ok: bool
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[SurfaceFinding] = field(default_factory=list)
    error: str = ""
    latency_ms: float = 0.0


@dataclass
class ActionSpec:
    """One read-only capability the reasoner may choose."""

    name: str
    description: str
    run: Callable[[dict[str, Any]], Observation]
    tags: tuple[str, ...] = ()          # hypothesis names this action tests
    params: dict[str, str] = field(default_factory=dict)
    cost: float = 1.0
    repeatable: bool = False
    priority: int = 0                 # lower runs earlier among equal scores

    def spec(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "tags": list(self.tags)}


@dataclass
class Hypothesis:
    name: str
    rationale: str
    confidence: float = 0.5
    tested: bool = False
    refuted: bool = False
    evidence: list[str] = field(default_factory=list)

    def touch(self, finding: SurfaceFinding) -> None:
        self.tested = True
        self.evidence.append(f"{finding.check_id}: {finding.title}")
        if finding.is_finding:
            self.confidence = max(self.confidence, min(0.95, self.confidence + 0.2))
        else:
            self.refuted = True
            self.confidence *= 0.4


@dataclass
class Step:
    thought: str
    action: str
    args: dict[str, Any]
    observation: Observation
    reasoner: str = "rules"


@dataclass
class ReactResult:
    goal: str
    steps: list[Step] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    findings: list[SurfaceFinding] = field(default_factory=list)
    stop_reason: str = ""
    elapsed_s: float = 0.0
    policy: dict[str, Any] = field(default_factory=dict)
    blocked_actions: list[dict[str, Any]] = field(default_factory=list)


class ActionCatalog:
    def __init__(self, actions: list[ActionSpec] | None = None) -> None:
        self.actions: dict[str, ActionSpec] = {}
        for action in actions or ():
            self.register(action)

    def register(self, action: ActionSpec) -> None:
        if action.name in self.actions:
            raise ValueError(f"duplicate action {action.name!r}")
        self.actions[action.name] = action

    def get(self, name: str) -> ActionSpec | None:
        return self.actions.get(name)

    def describe(self) -> list[dict[str, Any]]:
        return [a.spec() for a in self.actions.values()]


class RuleReasoner:
    """Pick the highest-value untested action for the strongest live hypothesis."""

    def __init__(self, stagnation_limit: int = 3) -> None:
        self.stagnation_limit = stagnation_limit

    def choose(
        self,
        goal: str,
        hypotheses: list[Hypothesis],
        history: list[Step],
        catalog: ActionCatalog,
        seen: set[tuple[str, str]],
    ) -> tuple[str, ActionSpec, dict[str, Any]] | tuple[str, None, dict[str, Any]]:
        scored: list[tuple[float, str, ActionSpec, dict[str, Any]]] = []
        for action in catalog.actions.values():
            args = self._args_for(action, hypotheses)
            digest = (action.name, json.dumps(args, sort_keys=True))
            if digest in seen and not action.repeatable:
                continue
            gain = 0.0
            for hypothesis in hypotheses:
                if hypothesis.refuted or hypothesis.tested:
                    continue
                if hypothesis.name in action.tags:
                    gain += hypothesis.confidence
            gain += 0.05 * action.tags.count("baseline")  # baseline context is cheap
            gain -= 0.1 * max(0.0, action.cost - 1.0)
            scored.append((gain, action.name, action, args))
        if not scored:
            return ("No untested action remains; the reachable likely-checks are exhausted.", None, {})
        scored.sort(key=lambda row: (-row[0], -row[2].priority, row[1]))
        gain, name, action, args = scored[0]
        live = [h.name for h in hypotheses if h.name in action.tags and not h.tested]
        thought = (
            f"Strongest supported hypotheses: {', '.join(live) or 'baseline'}. "
            f"Run {name} (score {gain:.2f})."
        )
        return thought, action, args

    def _args_for(self, action: ActionSpec, hypotheses: list[Hypothesis]) -> dict[str, Any]:
        args: dict[str, Any] = {}
        for param, kind in action.params.items():
            if kind == "baseline":
                args[param] = ""
            elif kind == "service":
                named = [h.name for h in hypotheses if h.name in action.tags]
                args[param] = named[0] if named else ""
        return args


class LLMReasoner:
    """Ask an OpenAI-compatible chat model for the next action; validate hard.

    The model sees the goal, the hypothesis list and the action catalog, and must
    return ``{"action": "...", "args": {...}, "why": "..."}``. Unknown actions,
    undeclared arguments or a policy-blocked choice fall back to rules.
    """

    def __init__(
        self,
        endpoint: str,
        model: str,
        api_key: str = "",
        timeout_s: float = 60.0,
        fallback: RuleReasoner | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.fallback = fallback or RuleReasoner()
        self.calls = 0
        self.fallbacks = 0

    def choose(self, goal, hypotheses, history, catalog, seen):
        self.calls += 1
        try:
            reply = self._ask(goal, hypotheses, history, catalog)
            action = catalog.get(reply.get("action", ""))
            if action is None:
                raise ValueError("unknown action")
            args = reply.get("args") if isinstance(reply.get("args"), dict) else {}
            allowed = set(action.params)
            if not set(args) <= allowed:
                raise ValueError("undeclared arguments")
            digest = (action.name, json.dumps(args, sort_keys=True))
            if digest in seen and not action.repeatable:
                raise ValueError("repeated step")
            return (str(reply.get("why") or "model-selected step"), action, args)
        except Exception:
            self.fallbacks += 1
            return self.fallback.choose(goal, hypotheses, history, catalog, seen)

    def _ask(self, goal: str, hypotheses: list[Hypothesis], history: list[Step], catalog: ActionCatalog) -> dict[str, Any]:
        system = (
            "You are the reasoning half of a read-only security test. Fake example. "
            "Choose exactly one action from the catalog. Never invent action names or "
            "arguments. Respond with JSON only: "
            '{"action": "<catalog name>", "args": {...}, "why": "<one sentence>"}'
        )
        hist = [
            {
                "think": s.thought,
                "action": s.action,
                "ok": s.observation.ok,
                "summary": s.observation.summary[:300],
                "new_findings": [f.check_id for f in s.observation.findings if f.is_finding],
            }
            for s in history[-8:]
        ]
        user = json.dumps(
            {
                "goal": goal,
                "hypotheses": [
                    {"name": h.name, "rationale": h.rationale, "confidence": round(h.confidence, 2), "tested": h.tested}
                    for h in hypotheses
                ],
                "catalog": catalog.describe(),
                "history": hist,
            },
            ensure_ascii=False,
        )
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": 400,
            "temperature": 0.2,
        }
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            parsed = json.loads(resp.read().decode())
        content = ((parsed.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        return _parse_json_object(content)


def _parse_json_object(text: str) -> dict[str, Any]:
    """Extract one JSON object from a model reply, tolerating code fences and prose."""

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in reply")
    candidate = text[start : end + 1]
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        import re

        match = re.search(r"\{.*\}", candidate, re.S)
        if not match:
            raise
        parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("reply is not an object")
    return parsed


class Reactor:
    """Drive one goal through a bounded think-act-observe loop."""

    def __init__(
        self,
        goal: str,
        catalog: ActionCatalog,
        hypotheses: list[Hypothesis],
        policy: PolicyEngine,
        reasoner: RuleReasoner | LLMReasoner | None = None,
        max_steps: int = 40,
        stagnation_limit: int = 3,
    ) -> None:
        self.goal = goal
        self.catalog = catalog
        self.hypotheses = hypotheses
        self.policy = policy
        self.reasoner = reasoner or RuleReasoner(stagnation_limit)
        self.max_steps = max_steps
        self.stagnation_limit = stagnation_limit

    def run(self) -> ReactResult:
        started = time.perf_counter()
        result = ReactResult(goal=self.goal, hypotheses=self.hypotheses, policy=self.policy.snapshot())
        seen_digests: set[tuple[str, str]] = set()
        idle = 0
        while len(result.steps) < self.max_steps:
            thought, action, args = self.reasoner.choose(
                self.goal, self.hypotheses, result.steps, self.catalog, seen_digests
            )
            if action is None:
                result.stop_reason = "no actions left"
                break
            digest = (action.name, json.dumps(args, sort_keys=True))
            if digest in seen_digests and not action.repeatable:
                idle += 1
                if idle >= self.stagnation_limit:
                    result.stop_reason = "stagnation: repeated action"
                    break
                continue
            # The policy sees the action name and arguments before anything runs.
            decision = self._policy_for(action, args)
            if not decision.allowed:
                result.blocked_actions.append(
                    {"action": action.name, "args": args, "reason": decision.reason}
                )
                # A blocked action is skipped, not fatal: other read-only steps may
                # still run. Three blocked steps in a row stops the loop.
                result.steps.append(
                    Step(f"Blocked by policy: {decision.reason}", action.name, args,
                         Observation(action=action.name, ok=False, error=decision.reason), "rules")
                )
                if len(result.blocked_actions) >= 3:
                    result.stop_reason = "blocked by read-only policy"
                    break
                continue
            seen_digests.add(digest)
            try:
                observation = action.run(args)
            except Exception as exc:  # an action crash is an observation, not a stop
                observation = Observation(action=action.name, ok=False, error=f"{type(exc).__name__}: {exc}")
            # Progress is a completed action whose transport succeeded. A "pass"
            # result is progress (the hypothesis was refuted), not stagnation; the
            # repeated-digest guard above is what catches spinning.
            idle = 0 if observation.ok else idle + 1
            if idle >= self.stagnation_limit:
                result.steps.append(Step(thought, action.name, args, observation, "rules"))
                result.stop_reason = "stagnation: no progress"
                break
            self._update_hypotheses(observation, action)
            result.steps.append(
                Step(thought, action.name, args, observation, "llm" if isinstance(self.reasoner, LLMReasoner) else "rules")
            )
            if idle == 0:
                continue
        result.findings = [
            f for step in result.steps for f in step.observation.findings if f.is_finding
        ]
        result.findings.sort(key=lambda f: f.severity_rank, reverse=True)
        result.stop_reason = result.stop_reason or ("step budget exhausted" if len(result.steps) >= self.max_steps else "goal coverage complete")
        result.policy = self.policy.snapshot()
        result.elapsed_s = (time.perf_counter() - started)
        return result

    def _policy_for(self, action: ActionSpec, args: dict[str, Any]) -> Decision:
        # Action names may carry the surface they touch; host actions with a
        # ``command`` argument are checked as commands, everything else is read.
        if "command" in args:
            return self.policy.check_command(str(args["command"]))
        if "url" in args:
            return self.policy.check_web(str(args.get("method") or "GET"), str(args["url"]))
        return Decision(True, effect=Effect.READ)

    def _update_hypotheses(self, observation: Observation, action: ActionSpec) -> None:
        for hypothesis in self.hypotheses:
            if hypothesis.name in action.tags and observation.findings:
                for finding in observation.findings:
                    hypothesis.touch(finding)
        # Actions can hand the engine new hypotheses, e.g. "tech:wordpress" after
        # fingerprinting. They become live candidates for the next reason step.
        extra = observation.data.get("hypotheses") or []
        for item in extra:
            if isinstance(item, str) and not any(h.name == item for h in self.hypotheses):
                self.hypotheses.append(Hypothesis(name=item, rationale=f"raised by {action.name}", confidence=0.75))
            elif isinstance(item, dict) and isinstance(item.get("name"), str) and not any(h.name == item["name"] for h in self.hypotheses):
                self.hypotheses.append(Hypothesis(name=item["name"], rationale=str(item.get("rationale") or "raised by data"), confidence=float(item.get("confidence") or 0.7)))


def findings_for(result: ReactResult) -> list[SurfaceFinding]:
    """Dedupe findings across steps, keeping the strongest evidence per check."""

    best: dict[str, SurfaceFinding] = {}
    for finding in result.findings:
        keep = best.get(finding.check_id)
        if keep is None:
            best[finding.check_id] = finding
            continue
        if len(finding.evidence) > len(keep.evidence):
            best[finding.check_id] = finding
    return sorted(best.values(), key=lambda f: f.severity_rank, reverse=True)


def attack_effect_of(expect) -> Effect:
    return tool_effect(getattr(expect, "tool_prefixes", ())[0]) if getattr(expect, "tool_prefixes", ()) else Effect.READ
