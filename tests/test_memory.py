"""Engagement memory: dedupe, severity escalation, planning signals."""

from redteam_agent.attacks import ATTACKS_BY_ID, categories
from redteam_agent.judges import Verdict
from redteam_agent.memory import Memory
from redteam_agent.taxonomy import SEVERITY_RANK


def _verdict(severity="medium", finding=True, indicators=("leak_keyword:x",)):
    return Verdict(
        finding=finding,
        severity=severity,
        confidence=0.8,
        reasoning="test",
        indicators=list(indicators),
    )


def _add(memory, attack_id="LLM07-01", severity="medium", tool_calls=()):
    attack = ATTACKS_BY_ID[attack_id]
    return memory.add_finding(
        attack=attack,
        verdict=_verdict(severity=severity),
        payload="p",
        mutation="none",
        transcript="t",
        tool_calls=list(tool_calls),
        latency_ms=12.0,
        turn=1,
    )


def test_finding_ids_are_sequential():
    memory = Memory()
    a = _add(memory)
    b = _add(memory)
    assert (a.id, b.id) == ("RT-001", "RT-002")


def test_tool_call_escalates_severity():
    memory = Memory()
    quiet = _add(memory, severity="medium")
    loud = _add(memory, severity="medium", tool_calls=[{"name": "crm.export"}])

    assert quiet.severity == "medium"
    assert loud.severity == "high"
    assert loud.severity_rank > quiet.severity_rank


def test_tool_call_does_not_escalate_past_critical():
    memory = Memory()
    finding = _add(memory, severity="critical", tool_calls=[{"name": "crm.export"}])
    assert finding.severity == "critical"


def test_agentic_class_grows_with_tool_use():
    memory = Memory()
    quiet = _add(memory)
    loud = _add(memory, tool_calls=[{"name": "send_email"}])
    assert loud.agentic_class >= quiet.agentic_class


def test_one_finding_per_attack():
    memory = Memory()
    assert not memory.has_finding_for("LLM07-01")
    _add(memory, "LLM07-01")
    assert memory.has_finding_for("LLM07-01")
    assert 1 == sum(1 for f in memory.findings if f.attack_id == "LLM07-01")


def test_mutation_rotation_state():
    memory = Memory()
    assert not memory.mutation_tried("LLM01", "base64")
    memory.note_mutation("LLM01", "base64")

    assert memory.mutation_tried("LLM01", "base64")
    assert not memory.mutation_tried("ASI02", "base64")


def test_coverage_counts_and_best_severity():
    memory = Memory()
    memory.note_category("LLM01", finding=True, severity="medium", mutation="leet")
    memory.note_category("LLM01", finding=True, severity="high", mutation="base64")
    memory.note_category("LLM01")

    rows = {row["category"]: row for row in memory.coverage_matrix(categories())}
    assert rows["LLM01"]["probes"] == 3
    assert rows["LLM01"]["findings"] == 2
    assert rows["LLM01"]["best_severity"] == "high"
    assert set(rows["LLM01"]["working_mutations"]) == {"leet", "base64"}


def test_uncovered_categories_ordering():
    memory = Memory()
    memory.note_category("LLM01")
    uncovered = memory.uncovered_categories(categories())

    assert "LLM01" not in uncovered
    assert set(uncovered) == set(categories()) - {"LLM01"}


def test_severity_counts_include_empty_buckets():
    memory = Memory()
    _add(memory, severity="high")
    counts = memory.severity_counts()

    assert counts["high"] == 1
    assert set(counts) == set(SEVERITY_RANK)
    assert sum(counts.values()) == 1


def test_top_findings_sorted_by_severity():
    memory = Memory()
    _add(memory, "LLM09-01", severity="low")
    _add(memory, "LLM07-01", severity="high")

    top = memory.top_findings(limit=1)
    assert top[0].severity == "high"
