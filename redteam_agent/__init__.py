"""Red-team agent: an adaptive harness for testing AI agents you are authorized to test."""

from __future__ import annotations

__version__ = "0.1.0"

from .agent import Budget, RedTeamAgent, RunResult  # noqa: F401
from .attacks import ATTACKS, ATTACKS_BY_ID, Attack, Expect  # noqa: F401
from .config import AuthorizationError, JudgeConfig, RunConfig, Scope, TargetConfig  # noqa: F401
from .judges import CompositeJudge, LlmJudge, RuleJudge, Verdict  # noqa: F401
from .memory import Finding, Memory  # noqa: F401
from .report import ReportBundle, build_payload, render_markdown, write_reports  # noqa: F401
from .targets import HttpTarget, MockTarget, Message, ProbeResult, build_target  # noqa: F401

__all__ = [
    "ATTACKS",
    "ATTACKS_BY_ID",
    "Attack",
    "AuthorizationError",
    "Budget",
    "CompositeJudge",
    "Expect",
    "Finding",
    "HttpTarget",
    "JudgeConfig",
    "LlmJudge",
    "Memory",
    "Message",
    "MockTarget",
    "ProbeResult",
    "RedTeamAgent",
    "ReportBundle",
    "RuleJudge",
    "RunConfig",
    "RunResult",
    "Scope",
    "TargetConfig",
    "Verdict",
    "build_payload",
    "build_target",
    "render_markdown",
    "write_reports",
]
