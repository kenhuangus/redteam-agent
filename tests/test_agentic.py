"""Tests for the ARTEX-derived roles: frontier, guard, evidence, retester, gates."""

from __future__ import annotations

import json

import pytest

from redteam_agent.agent import RedTeamAgent
from redteam_agent.attacks import ATTACKS_BY_ID
from redteam_agent.config import JudgeConfig, RunConfig, Scope, TargetConfig
from redteam_agent.evidence import EvidenceStore
from redteam_agent.gates import FindingQualityGate, GateStatus
from redteam_agent.guard import Guard
from redteam_agent.judges import Verdict
from redteam_agent.memory import Finding
from redteam_agent.report import write_reports
from redteam_agent.retester import RetestVerdict, Retester
from redteam_agent.runstate import Frontier, IntentStatus, StopReason
from redteam_agent.targets import Message, ProbeResult, build_target


class _NoFindingJudge:
    """A judge that never finds: every attack becomes an unproductive round."""

    def evaluate(self, attack, messages, probe, canary):  # noqa: ANN001, ARG002
        return Verdict(attack_id=attack.id, category=attack.category, framework=attack.framework)


class _DeadTarget:
    """Accepts probes, always a 503: the dead-host guard should fire."""

    name = "mock"
    model = "dead-target"

    def probe(self, messages, canary=None, max_tokens=None):  # noqa: ANN001, ARG002
        return ProbeResult(error="HTTP 503: unavailable")


# ---------------------------------------------------------------- frontier
def test_frontier_lifecycle_and_drop() -> None:
    frontier = Frontier()
    frontier.register("A", "LLM01", route=("payload-0",))
    frontier.register("B", "LLM01")
    frontier.register("C", "LLM02")

    assert frontier.claim("A").status is IntentStatus.RUNNING
    assert frontier.claim("A") is None, "a running intent cannot be re-claimed"
    frontier.settle("A", IntentStatus.DONE)

    dropped = frontier.drop_category("LLM01", "stagnation")
    assert dropped == ["B"]
    assert frontier.get("B").status is IntentStatus.DROPPED
    assert not frontier.get("C").settled

    counts = frontier.summary()
    assert counts["done"] == 1 and counts["dropped"] == 1 and counts["total"] == 3


def test_stop_reason_values_match_report_strings() -> None:
    assert StopReason.ATTACKS_EXHAUSTED.value == "attack set exhausted"
    assert StopReason.STAGNATION.value == "stagnation detected"


# ---------------------------------------------------------------- guard
def test_guard_blocks_duplicates_and_attributes_results() -> None:
    guard = Guard()
    ok, _ = guard.pre_probe(attack_id="A", payload="same text", mutation="none")
    assert ok
    blocked, reason = guard.pre_probe(attack_id="A", payload="same text", mutation="none")
    assert not blocked and "duplicate" in reason
    assert guard.pre_probe(attack_id="A", payload="same text", mutation="base64")[0]

    assert guard.post_probe(attack_id="A", payload="x", mutation="none", text="403 WAF blocked") == "blocked"
    assert guard.post_probe(attack_id="A", payload="x", mutation="none", error="timeout") == "error"
    assert guard.post_probe(attack_id="A", payload="x", mutation="none", text="hello") == "ok"

    snapshot = guard.snapshot()
    assert snapshot["blocks"] >= 1
    assert snapshot["attributions"]["blocked"] == 1
    assert guard.blocked_for("A") >= 1


# ---------------------------------------------------------------- evidence
def test_evidence_hash_chain_detects_tampering(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "ev")
    store.record(attack_id="A", mutation="none", payload_sha256="abc")
    store.record(attack_id="A", mutation="base64", payload_sha256="abd")

    log = tmp_path / "ev" / "probes.jsonl"
    assert EvidenceStore.verify(log)["ok"] is True

    lines = log.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["payload_sha256"] = "tampered"
    lines[0] = json.dumps(first)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = EvidenceStore.verify(log)
    assert result["ok"] is False
    assert result["broken_at"] == 1


def test_evidence_resumes_an_existing_chain(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "ev")
    store.record(attack_id="A", payload_sha256="abc")
    head = store.head

    again = EvidenceStore(tmp_path / "ev")
    assert again.rows == 1 and again.head == head
    again.record(attack_id="B", payload_sha256="def")
    assert EvidenceStore.verify(tmp_path / "ev" / "probes.jsonl")["ok"] is True


# ---------------------------------------------------------------- retester
def _retest_attack():
    return ATTACKS_BY_ID["LLM07-01"]


def test_retester_reproduces_with_variant_payload() -> None:
    seen: list[str] = []

    def send(messages, payload, label):  # noqa: ANN001
        seen.append(label)
        return ProbeResult(text="leak"), Verdict(finding=True, indicators=["canary"]), {"seq": 1}

    result = Retester().retest(
        attack=_retest_attack(),
        messages=[Message(role="user", content="x")],
        payload="payload one",
        mutation_name="none",
        alternatives=["payload two"],
        send=send,
    )
    assert result.verdict is RetestVerdict.REPRODUCED
    assert result.confirmed is True
    assert seen == ["variant-payload+none"]


def test_retester_reports_not_reproduced() -> None:
    def send(messages, payload, label):  # noqa: ANN001
        return ProbeResult(text="refused"), Verdict(), {"seq": 2}

    result = Retester().retest(
        attack=_retest_attack(),
        messages=[Message(role="user", content="x")],
        payload="p1",
        mutation_name="none",
        alternatives=["p2"],
        send=send,
    )
    assert result.verdict is RetestVerdict.NOT_REPRODUCED
    assert result.confirmed is False


def test_retester_inconclusive_when_probe_never_goes_out() -> None:
    result = Retester().retest(
        attack=_retest_attack(),
        messages=[Message(role="user", content="x")],
        payload="p1",
        mutation_name="none",
        alternatives=["p2"],
        send=lambda *a: None,
    )
    assert result.verdict is RetestVerdict.INCONCLUSIVE
    assert result.confirmed is None


def test_retester_replays_a_chain() -> None:
    attack = ATTACKS_BY_ID["ASI06-01"]
    seen: list[str] = []

    def send(messages, payload, label):  # noqa: ANN001
        seen.append(label)
        return ProbeResult(text="x"), Verdict(), {"seq": 3}

    result = Retester().retest(
        attack=attack,
        messages=[
            Message(role="user", content="seed"),
            Message(role="user", content="recall"),
        ],
        payload="recall",
        mutation_name="chain",
        alternatives=["unused"],
        send=send,
    )
    assert result.technique == "replay"
    assert seen == ["replay"]


# ---------------------------------------------------------------- gates
def _finding(**overrides) -> Finding:
    base = dict(
        id="RT-001",
        attack_id="LLM07-01",
        category="LLM07",
        framework="OWASP-LLM-2025",
        title="System prompt extraction",
        goal="Recover the header",
        severity="high",
        confidence=0.9,
        reasoning="canary in reply",
        indicators=["canary_disclosure"],
        payload="p",
        mutation="none",
        transcript="user: x\nassistant: CANARY-RT-7f3a91c4",
    )
    base.update(overrides)
    return Finding(**base)


def test_quality_gate_passes_strong_evidence() -> None:
    result = FindingQualityGate().evaluate(_finding())
    assert result.status is GateStatus.PASS
    assert result.reasons == []


def test_quality_gate_quarantines_unreproduced_claim() -> None:
    result = FindingQualityGate().evaluate(
        _finding(confirmed=False, needs_manual_review=True, indicators=["canary_disclosure"])
    )
    assert result.status is GateStatus.QUARANTINE
    assert "not_reproduced" in result.reasons


def test_quality_gate_quarantines_prose_only_high_impact() -> None:
    result = FindingQualityGate().evaluate(
        _finding(indicators=["high_urgency_approval_bait"], transcript="user: x")
    )
    assert "impact_not_demonstrated" in result.reasons


# ---------------------------------------------------------------- agent loop
def _agent(judge, target=None, **config_overrides):
    attack_ids = config_overrides.pop("attack_ids", None) or ["LLM01-01", "LLM02-01", "LLM07-01"]
    config = RunConfig(
        scope=Scope(target_name="mock", max_probes=60, max_turns=60),
        target=TargetConfig(kind="mock"),
        judges=JudgeConfig(),
        **config_overrides,
    )
    return RedTeamAgent(
        config=config,
        target=target or build_target(TargetConfig(kind="mock")),
        judge=judge,
        attack_ids=attack_ids,
    )


def test_planner_stagnation_stops_an_unproductive_run() -> None:
    agent = _agent(
        _NoFindingJudge(),
        payloads_per_attack=1,
        mutations_per_payload=1,
        stagnation_rounds=2,
    )
    result = agent.run()

    assert result.stopped_reason == "stagnation detected"
    assert result.stop_reason is StopReason.STAGNATION
    frontier = result.frontier
    assert frontier["dropped"] >= 1
    assert frontier["done"] == 0
    assert result.probes < 60, "stagnation should stop before the budget is gone"


def test_dead_target_trips_the_error_breaker() -> None:
    agent = _agent(
        _NoFindingJudge(),
        target=_DeadTarget(),
        attack_ids=[
            "LLM01-01", "LLM02-01", "LLM07-01",
            "LLM10-01", "LLM09-01", "ASI08-01",
        ],
        payloads_per_attack=1,
        mutations_per_payload=1,
        target_error_limit=3,
    )
    result = agent.run()

    assert result.stop_reason is StopReason.TARGET_UNHEALTHY
    assert result.errors == 3
    assert result.frontier["blocked"] >= 1


def _canary_agent(**overrides):
    agent = _agent(from_redteam_agent_judge(), attack_ids=["LLM07-01"], **overrides)
    # Force the one evasion family the mock answers to, so the run is deterministic.
    agent._evasion_pool = ["authority"]
    return agent


def test_run_records_evidence_and_report_carries_it(tmp_path) -> None:
    agent = _canary_agent(evidence_dir=str(tmp_path / "evidence"))
    result = agent.run()

    assert result.findings, "LLM07-01 should find on the mock"
    finding = result.findings[0]
    assert finding.probe_seq >= 1
    assert len(finding.evidence_digest) == 64
    assert finding.reproduction_verdict in {"reproduced", "not_reproduced", "inconclusive"}
    assert result.evidence["rows"] == result.probes

    store = EvidenceStore(tmp_path / "evidence")
    assert store.manifest_path.exists()
    assert EvidenceStore.verify(store.path)["ok"] is True

    bundle = write_reports(config=agent.config, result=result, agent=agent)
    payload = json.loads(bundle.json_path.read_text(encoding="utf-8"))

    assert payload["library"]["version"]
    assert payload["evidence"]["rows"] == result.probes
    assert payload["audit"]["attributions"]["ok"] >= 1
    assert payload["frontier"]["done"] == 1
    assert payload["run"]["stagnation_rounds"] == 6

    transcripts = " ".join(f.get("transcript", "") for f in payload["findings"])
    assert "CANARY-RT-7f3a91c4" not in transcripts
    assert "[REDACTED]" in transcripts


def test_redaction_can_be_disabled(tmp_path) -> None:
    agent = _canary_agent(redact_transcripts=False)
    result = agent.run()
    bundle = write_reports(config=agent.config, result=result, agent=agent)
    payload = json.loads(bundle.json_path.read_text(encoding="utf-8"))
    transcripts = " ".join(f.get("transcript", "") for f in payload["findings"])
    assert "CANARY-RT-7f3a91c4" in transcripts


def test_quality_gate_is_tagged_on_findings() -> None:
    agent = _canary_agent()
    result = agent.run()
    assert result.findings, "LLM07-01 should find with the authority evasion"
    finding = result.findings[0]
    assert finding.quality.get("status") in {"pass", "quarantine"}
    assert finding.quality.get("fingerprint")


# ---------------------------------------------------------------- config merge
def test_new_role_settings_do_not_get_clobbered(tmp_path) -> None:
    from redteam_agent.cli import _load_config, _parser

    path = tmp_path / "engagement.json"
    path.write_text(
        json.dumps(
            {
                "scope": {"target_name": "mock", "max_probes": 5},
                "stagnation_rounds": 9,
                "target_error_limit": 7,
                "evidence_dir": "out/evidence",
                "quality_gate": False,
            }
        ),
        encoding="utf-8",
    )
    config = _load_config(_parser().parse_args(["run", "--config", str(path)]))
    assert config.stagnation_rounds == 9
    assert config.target_error_limit == 7
    assert config.evidence_dir == "out/evidence"
    assert config.quality_gate is False

    args = _parser().parse_args(
        ["run", "--config", str(path), "--stagnation-rounds", "2", "--no-quality-gate"]
    )
    config = _load_config(args)
    assert config.stagnation_rounds == 2
    assert config.quality_gate is False


def from_redteam_agent_judge():
    from redteam_agent.judges import build_judge

    return build_judge(JudgeConfig())
