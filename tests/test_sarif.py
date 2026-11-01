"""SARIF export and CI gate tests."""

from __future__ import annotations

import json

from redteam_agent import cli
from redteam_agent.agent import RedTeamAgent
from redteam_agent.config import JudgeConfig, RunConfig, Scope, TargetConfig
from redteam_agent.judges import build_judge
from redteam_agent.report import SARIF_LEVELS, build_sarif, write_sarif
from redteam_agent.targets import build_target


def _run(attack_ids: list[str], max_probes: int = 40):
    agent = RedTeamAgent(
        config=RunConfig(
            scope=Scope(target_name="mock", max_probes=max_probes, max_turns=max_probes),
            mutations_per_payload=5,
        ),
        target=build_target(TargetConfig(kind="mock")),
        judge=build_judge(JudgeConfig()),
        attack_ids=attack_ids,
    )
    return agent.run()


def test_sarif_shape_and_levels(tmp_path) -> None:
    result = _run(["ASI10-01"])
    assert result.findings, "ASI10-01 should be found on the mock"

    sarif = build_sarif(config=RunConfig(), result=result)
    assert sarif["$schema"].startswith("https://")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "redteam-agent"
    assert run["invocations"][0]["executionSuccessful"] is True

    finding = result.findings[0]
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert rule_ids == [finding.attack_id]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["properties"]["framework"] == finding.framework
    assert rule["defaultConfiguration"]["level"] == SARIF_LEVELS[finding.severity]

    assert len(run["results"]) == 1
    result_entry = run["results"][0]
    assert result_entry["ruleId"] == finding.attack_id
    assert result_entry["level"] == SARIF_LEVELS[finding.severity]
    assert finding.attack_id in result_entry["message"]["text"]
    assert result_entry["partialFingerprints"]["redteamFinding/v1"]

    out = write_sarif(tmp_path / "out" / "redteam.sarif", sarif)
    assert out.exists()
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_sarif_omits_raw_transcripts() -> None:
    """CI logs must not publish the secrets or PII the run itself captured."""
    result = _run(["LLM06-01", "LLM02-01"])
    assert result.findings
    dumped = json.dumps(build_sarif(config=RunConfig(), result=result))
    for finding in result.findings:
        assert "assistant:" not in dumped
        assert finding.transcript[:40] not in dumped


def test_sarif_rules_are_unique_per_attack() -> None:
    result = _run(["LLM06-01", "LLM01-01"], max_probes=120)
    sarif = build_sarif(config=RunConfig(), result=result)
    driver = sarif["runs"][0]["tool"]["driver"]
    rule_ids = [rule["id"] for rule in driver["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert len(sarif["runs"][0]["results"]) == len(result.findings)


def test_fail_on_gate_exit_code(tmp_path) -> None:
    argv = [
        "run",
        "--target",
        "mock",
        "--only",
        "ASI10-01",
        "--mutations",
        "5",
        "--max-probes",
        "40",
        "--fail-on",
        "critical",
        "--sarif",
        str(tmp_path / "gate.sarif"),
        "--output-dir",
        str(tmp_path),
        "--quiet",
    ]
    assert cli.main(argv) == 3
    assert (tmp_path / "gate.sarif").exists()


def test_fail_on_gate_passes_when_below_threshold(tmp_path) -> None:
    argv = [
        "run",
        "--target",
        "mock",
        "--only",
        "LLM09-01",
        "--mutations",
        "5",
        "--max-probes",
        "40",
        "--fail-on",
        "critical",
        "--output-dir",
        str(tmp_path),
        "--quiet",
    ]
    assert cli.main(argv) == 0


def test_fail_on_none_always_exits_zero(tmp_path) -> None:
    argv = [
        "run",
        "--target",
        "mock",
        "--only",
        "ASI10-01",
        "--mutations",
        "5",
        "--max-probes",
        "40",
        "--output-dir",
        str(tmp_path),
        "--quiet",
    ]
    assert cli.main(argv) == 0


def test_fail_on_low_gate_catches_small_findings(tmp_path) -> None:
    gate = "low"
    argv = [
        "run",
        "--target",
        "mock",
        "--only",
        "LLM09-01",
        "--mutations",
        "5",
        "--max-probes",
        "40",
        "--fail-on",
        gate,
        "--output-dir",
        str(tmp_path),
        "--quiet",
    ]
    assert cli.main(argv) == 3


def test_gate_above_the_actual_severity_exits_zero(tmp_path) -> None:
    """LLM09-01 is low; a medium gate must not fire."""
    argv = [
        "run",
        "--target",
        "mock",
        "--only",
        "LLM09-01",
        "--mutations",
        "5",
        "--max-probes",
        "40",
        "--fail-on",
        "medium",
        "--output-dir",
        str(tmp_path),
        "--quiet",
    ]
    assert cli.main(argv) == 0
