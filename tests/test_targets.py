"""Transport-level tests: the max_tokens knob and probe signature parity.

No network: the HTTP target's urlopen is replaced with a fake response so we can
assert what would have been sent on the wire.
"""

from __future__ import annotations

import json

import pytest

from redteam_agent.agent import RedTeamAgent
from redteam_agent.config import JudgeConfig, RunConfig, Scope, TargetConfig
from redteam_agent.judges import Verdict, build_judge
from redteam_agent.targets import Message, build_target
from redteam_agent import targets as targets_module


class _FakeResponse:
    def __init__(self, body: str) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body.encode()

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def test_mock_target_accepts_max_tokens() -> None:
    target = build_target(TargetConfig(kind="mock"))
    probe = target.probe([Message(role="user", content="hello")], max_tokens=64)
    assert probe.ok


def test_http_target_sends_max_tokens(monkeypatch) -> None:
    seen: dict[str, bytes] = {}

    def fake_urlopen(req, timeout=None):  # noqa: ARG001 - signature parity
        seen["body"] = req.data
        return _FakeResponse('{"choices": [{"message": {"content": "hi"}}]}')

    monkeypatch.setattr(
        targets_module.HttpTarget, "_open", lambda self, req: fake_urlopen(req)
    )
    config = TargetConfig(
        kind="http",
        endpoint="https://agent.example.test/v1/chat/completions",
        model="support-agent-v3",
    )
    # max_tokens lives on RunConfig, so the agent can pass it through.
    run_config = RunConfig(max_tokens=77)
    target = build_target(config)
    probe = target.probe(
        [Message(role="user", content="hello")], max_tokens=run_config.max_tokens
    )

    assert probe.ok and probe.text == "hi"
    body = json.loads(seen["body"].decode())
    assert body["max_tokens"] == 77
    assert body["model"] == "support-agent-v3"


def test_http_target_omits_max_tokens_when_not_given(monkeypatch) -> None:
    seen: dict[str, bytes] = {}

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        seen["body"] = req.data
        return _FakeResponse('{"output": "ok"}')

    monkeypatch.setattr(
        targets_module.HttpTarget, "_open", lambda self, req: fake_urlopen(req)
    )
    target = build_target(TargetConfig(kind="http", endpoint="https://x.example.test"))
    assert target.probe([Message(role="user", content="hi")]).text == "ok"
    assert "max_tokens" not in json.loads(seen["body"].decode())


def test_http_target_reports_transport_error(monkeypatch) -> None:
    def boom(req, timeout=None):  # noqa: ARG001
        raise OSError("connection refused")

    monkeypatch.setattr(targets_module.HttpTarget, "_open", lambda self, req: boom(req))
    target = build_target(TargetConfig(kind="http", endpoint="https://x.example.test"))
    probe = target.probe([Message(role="user", content="hi")])
    assert not probe.ok
    assert "connection refused" in probe.error


class _FirstProbeOnlyJudge:
    """Finds on the first evaluation only: a detector that cannot reproduce."""

    def __init__(self) -> None:
        self.calls = 0

    def evaluate(self, attack, messages, probe, canary):  # noqa: ANN001, ARG002
        self.calls += 1
        if self.calls == 1:
            return Verdict(
                attack_id=attack.id,
                category=attack.category,
                framework=attack.framework,
                finding=True,
                severity="high",
                confidence=0.8,
                reasoning="stub: injected finding",
                indicators=["stub"],
                evidence=probe.text,
            )
        return Verdict(
            attack_id=attack.id,
            category=attack.category,
            framework=attack.framework,
            reasoning="stub: no reproduction",
        )


def test_unreproduced_finding_is_flagged_not_confirmed() -> None:
    agent = RedTeamAgent(
        config=RunConfig(
            scope=Scope(target_name="mock", max_probes=10, max_turns=10)
        ),
        target=build_target(TargetConfig(kind="mock")),
        judge=_FirstProbeOnlyJudge(),
        attack_ids=["LLM07-01"],
    )
    result = agent.run()

    assert result.findings, "the stub judge should produce one finding"
    finding = result.findings[0]
    assert finding.confirmed is False
    assert finding.confirm_with.startswith("variant-payload")
    assert finding.needs_manual_review is True
    assert any(i.startswith("not_reproduced:variant-payload") for i in finding.indicators)


def test_confirmation_can_be_disabled() -> None:
    agent = RedTeamAgent(
        config=RunConfig(
            scope=Scope(target_name="mock", max_probes=40, max_turns=40),
            mutations_per_payload=5,
            exploit_confirmation=False,
        ),
        target=build_target(TargetConfig(kind="mock")),
        judge=build_judge(JudgeConfig()),
        attack_ids=["LLM07-01"],
    )
    result = agent.run()

    assert len(result.findings) == 1
    assert result.findings[0].confirmed is None
    assert result.findings[0].confirm_with == ""


def test_finding_reproduces_on_second_probe() -> None:
    agent = RedTeamAgent(
        config=RunConfig(
            scope=Scope(target_name="mock", max_probes=40, max_turns=40),
            mutations_per_payload=5,
        ),
        target=build_target(TargetConfig(kind="mock")),
        judge=build_judge(JudgeConfig()),
        attack_ids=["LLM07-01"],
    )
    result = agent.run()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.confirmed is True
    assert finding.confirm_with.startswith("variant-payload") or finding.confirm_with == "replay"
    assert finding.needs_manual_review is False

