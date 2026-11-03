"""Scope, authorization, and run configuration for the red-teaming agent.

The authorization fields are an accountability record, not an access barrier:
they make every finding attributable to an engagement. The tool refuses to run
against a host that is not explicitly listed in ``allowed_hosts``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


MOCK_TARGET_NAMES = {"mock"}


class AuthorizationError(RuntimeError):
    """Raised when the run scope is incomplete or out of bounds."""


@dataclass
class Scope:
    target_name: str = "mock"
    target_host: str = ""
    authorized_by: str = ""       # human who approved the test
    authorization_ref: str = ""   # ticket / SOW / contract id
    allowed_hosts: tuple[str, ...] = ()
    max_probes: int = 150
    max_turns: int = 150
    rate_limit_per_min: int = 30
    stop_on_critical: bool = False
    note: str = ""

    @property
    def is_mock(self) -> bool:
        return self.target_name.lower() in MOCK_TARGET_NAMES

    def validate(self) -> None:
        if not self.is_mock:
            if not self.authorized_by.strip():
                raise AuthorizationError("authorized_by is required for a live target")
            if not self.authorization_ref.strip():
                raise AuthorizationError(
                    "authorization_ref is required (ticket, SOW, or engagement id)"
                )
            host = (self.target_host or self.target_name).lower()
            allowed = {h.lower() for h in self.allowed_hosts}
            if host not in allowed:
                raise AuthorizationError(
                    f"host {host!r} is not in allowed_hosts {sorted(allowed)}; "
                    "add it explicitly if this test is authorized"
                )
        if self.max_probes < 1:
            raise AuthorizationError("max_probes must be >= 1")
        if self.rate_limit_per_min < 1:
            raise AuthorizationError("rate_limit_per_min must be >= 1")


@dataclass
class TargetConfig:
    kind: str = "mock"                      # mock | http | openai
    endpoint: str = ""                      # http/openai base URL
    model: str = "gpt-4o-mini"
    system_prompt: str = ""                 # what the agent under test runs
    api_key_env: str = "OPENAI_API_KEY"     # env var NAME, never a literal secret
    extra_headers: dict[str, str] = field(default_factory=dict)
    timeout_s: float = 120.0
    num_predict: int = 256          # ollama completion ceiling (overridden by max_tokens)
    tools: tuple[str, ...] = ()


@dataclass
class JudgeConfig:
    use_llm_judge: bool = False
    judge_model: str = "gpt-4o-mini"
    judge_api_key_env: str = "OPENAI_API_KEY"
    canary: str = "CANARY-RT-7f3a91c4"
    secret_regexes: tuple[str, ...] = (
        r"sk-[A-Za-z0-9]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{36}",
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        r"\b\d{3}-\d{2}-\d{4}\b",              # SSN-shaped
        r"\b(?:\d[ -]?){15,16}\b",             # card-shaped
    )


@dataclass
class RunConfig:
    scope: Scope = field(default_factory=Scope)
    target: TargetConfig = field(default_factory=TargetConfig)
    judges: JudgeConfig = field(default_factory=JudgeConfig)
    output_dir: str = "reports"
    seed: int = 1337
    payloads_per_attack: int = 2
    mutations_per_payload: int = 2
    exploit_confirmation: bool = True
    max_tokens: int = 512
    # Reports quote transcripts as evidence; scrub the canary and any secret-shaped
    # match out of them unless the operator explicitly asks for raw text.
    redact_transcripts: bool = True
    # Planner health knobs, modelled on ARTEX's stagnation detector and provider
    # circuit breaker: stop finding the same nothing, and stop retrying a dead host.
    stagnation_rounds: int = 6
    target_error_limit: int = 3
    # When set, every probe is appended to <dir>/probes.jsonl with a hash chain.
    evidence_dir: str = ""
    quality_gate: bool = True
    # Adaptive payloads: the ReAct lab chooses the next payload family from the
    # previous reply instead of walking a fixed mutation ladder.
    agentic_payloads: bool = True
    # Off by default: a probe whose prize is a mutating tool call is refused so a
    # read-only engagement cannot delete or change anything in the target.
    allow_state_changing: bool = False

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, path: str | Path | dict[str, Any]) -> "RunConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8")) if not isinstance(path, dict) else path
        scope = Scope(**data.get("scope", {}))
        if scope.allowed_hosts:
            scope.allowed_hosts = tuple(scope.allowed_hosts)
        target = TargetConfig(**data.get("target", {}))
        if target.tools:
            target.tools = tuple(target.tools)
        judges = JudgeConfig(**data.get("judges", {}))
        if judges.secret_regexes:
            judges.secret_regexes = tuple(judges.secret_regexes)
        return cls(
            scope=scope,
            target=target,
            judges=judges,
            output_dir=data.get("output_dir", "reports"),
            seed=data.get("seed", 1337),
            payloads_per_attack=data.get("payloads_per_attack", 2),
            mutations_per_payload=data.get("mutations_per_payload", 2),
            exploit_confirmation=data.get("exploit_confirmation", True),
            max_tokens=data.get("max_tokens", 512),
            redact_transcripts=data.get("redact_transcripts", True),
            stagnation_rounds=int(data.get("stagnation_rounds", 6)),
            target_error_limit=int(data.get("target_error_limit", 3)),
            evidence_dir=data.get("evidence_dir", ""),
            quality_gate=data.get("quality_gate", True),
            agentic_payloads=bool(data.get("agentic_payloads", True)),
            allow_state_changing=bool(data.get("allow_state_changing", False)),
        )
