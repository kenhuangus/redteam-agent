"""End-to-end runs against the offline mock target.

The load-bearing test here is coverage: every attack in the library must be
proven out against the mock with a reasonably wide budget. If a new attack is
added without either success criteria or a matching built-in detector, this
suite fails.
"""

import json

import pytest

from redteam_agent.agent import RedTeamAgent
from redteam_agent.attacks import ATTACKS, ATTACKS_BY_ID, categories
from redteam_agent.config import JudgeConfig, RunConfig, Scope, TargetConfig
from redteam_agent.judges import build_judge
from redteam_agent.report import write_reports
from redteam_agent.targets import build_target


def _agent(**overrides):
    defaults = dict(
        valid=True,
        target_kind="mock",
        payloads_per_attack=3,
        mutations_per_payload=5,
        seed=1337,
    )
    defaults.update(overrides)
    config = RunConfig(
        scope=Scope(target_name="mock", max_probes=260, max_turns=260),
        target=TargetConfig(kind=defaults["target_kind"]),
        judges=JudgeConfig(),
        payloads_per_attack=defaults["payloads_per_attack"],
        mutations_per_payload=defaults["mutations_per_payload"],
        seed=defaults["seed"],
    )
    return RedTeamAgent(
        config=config,
        target=build_target(config.target),
        judge=build_judge(config.judges),
    )


@pytest.fixture(scope="module")
def wide_run():
    return _agent().run()


def test_wide_run_reports_findings(wide_run):
    assert wide_run.findings
    assert wide_run.stopped_reason == "attack set exhausted"
    assert wide_run.model == "mock-supportassist-v1"


def test_every_attack_is_proven_against_mock(wide_run):
    """Falsifiability guarantee: an attack that cannot demonstrate risk is unusable."""
    found = {f.attack_id for f in wide_run.findings}
    missing = sorted(a.id for a in ATTACKS if a.id not in found)
    assert not missing, f"attacks with no finding on mock: {missing}"


def test_every_category_is_covered(wide_run):
    matrix = {row["category"]: row for row in wide_run.memory.coverage_matrix(categories())}
    for category in categories():
        assert matrix[category]["probes"] > 0, category
        assert matrix[category]["exposed"], category


def test_finding_ids_are_unique_and_sequential(wide_run):
    """IDs record discovery order; severity ranking happens at report time."""
    ids = [f.id for f in wide_run.findings]
    assert len(ids) == len(set(ids))
    assert ids == [f"RT-{i:03d}" for i in range(1, len(ids) + 1)]


def test_probe_and_turn_accounting(wide_run):
    assert wide_run.probes == wide_run.turns
    assert wide_run.probes <= 260


def test_budget_is_enforced():
    agent = _agent()
    agent.budget.max_probes = 4
    result = agent.run()

    assert result.probes == 4
    assert result.stopped_reason == "probe budget exhausted"


def test_stop_on_critical_gate():
    agent = _agent()
    agent.config.scope.stop_on_critical = True
    result = agent.run()

    assert result.stopped_reason == "stop_on_critical gate hit"
    assert any(f.severity_rank >= 4 for f in result.findings)


def test_attack_filter_limits_scope():
    agent = RedTeamAgent(
        config=RunConfig(
            scope=Scope(target_name="mock", max_probes=60, max_turns=60),
            mutations_per_payload=5,
        ),
        target=build_target(TargetConfig(kind="mock")),
        judge=build_judge(JudgeConfig()),
        attack_ids=["LLM07-01"],
    )
    result = agent.run()

    assert {f.attack_id for f in result.findings} == {"LLM07-01"}


def test_unknown_attack_id_raises():
    with pytest.raises(ValueError, match="unknown attack id"):
        RedTeamAgent(
            config=RunConfig(),
            target=build_target(TargetConfig(kind="mock")),
            judge=build_judge(JudgeConfig()),
            attack_ids=["NOT-A-CONTROL"],
        )


@pytest.mark.parametrize("seed", [1, 2])
def test_run_is_deterministic_for_a_seed(seed):
    first = _agent(seed=seed).run()
    second = _agent(seed=seed).run()

    assert [f.attack_id for f in first.findings] == [f.attack_id for f in second.findings]
    assert [f.mutation for f in first.findings] == [f.mutation for f in second.findings]


def test_memory_poisoning_requires_a_chain(wide_run):
    poisoning = [f for f in wide_run.findings if f.attack_id == ATTACKS_BY_ID["ASI06-01"].id]
    assert poisoning, "ASI06-01 should be found by the wide run"
    assert poisoning[0].mutation == "chain"
    assert "|" in poisoning[0].transcript


def test_each_finding_keeps_the_model_reply(wide_run):
    """A transcript must quote the reply, or the finding cannot be reviewed."""
    assert wide_run.findings
    for finding in wide_run.findings:
        assert "assistant:" in finding.transcript, finding.attack_id
        reply = finding.transcript.split("\nassistant:", 1)[1].strip()
        assert reply, finding.attack_id


def test_reports_written_and_parseable(wide_run, tmp_path):
    agent = _agent()
    config = agent.config
    bundle = write_reports(config=config, result=wide_run, agent=agent, output_dir=str(tmp_path))

    files = list(tmp_path.glob("redteam-*.json"))
    mds = list(tmp_path.glob("redteam-*.md"))
    assert len(files) == 1 and len(mds) == 1

    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert payload["schema"] == "redteam-agent/report/v1"
    assert payload["summary"]["findings_total"] > 0
    assert payload["coverage"]
    assert all(row["exposed"] for row in payload["coverage"])
    assert payload["findings"][0]["remediation"]
    assert len(payload["findings"]) == len(wide_run.findings)

    markdown = mds[0].read_text(encoding="utf-8")
    assert markdown.startswith("# AI Red-Team Report")
    assert "assistant:" in markdown
    assert "OWASP" in markdown
    assert "## Limitations" in markdown
