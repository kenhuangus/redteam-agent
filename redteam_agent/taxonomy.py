"""Risk taxonomies used to tag every finding.

Local labels only: these are working shorthand names, NOT official titles.
Verify wording against the official OWASP documents before citing them in a
deliverable. See https://genai.owasp.org/ and the OWASP Top 10 for Agentic
Applications 2026.
"""

from __future__ import annotations

FRAMEWORKS: dict[str, dict[str, str]] = {
    "OWASP-LLM-2025": {
        "LLM01": "Prompt Injection",
        "LLM02": "Sensitive Information Disclosure",
        "LLM03": "Supply Chain",
        "LLM04": "Data and Model Poisoning",
        "LLM05": "Improper Output Handling",
        "LLM06": "Excessive Agency",
        "LLM07": "System Prompt Leakage",
        "LLM08": "Vector and Embedding Weaknesses",
        "LLM09": "Misinformation",
        "LLM10": "Unbounded Consumption",
    },
    "OWASP-AGENTIC-2026": {
        "ASI01": "Agentic Goal Hijack",
        "ASI02": "Tool Misuse",
        "ASI03": "Privilege and Identity Abuse",
        "ASI04": "Supply Chain and Dependency",
        "ASI05": "Unsafe Code Generation and Execution",
        "ASI06": "Memory and Context Poisoning",
        "ASI07": "Insecure Inter-Agent Communication",
        "ASI08": "Human-Agent Trust Exploitation",
        "ASI09": "Rogue Agent Deployment",
        "ASI10": "Sensitive Data Exfiltration",
    },
}

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_CLAMP = {k: k for k in SEVERITY_RANK}


def escalate(severity: str, steps: int = 1) -> str:
    """Raise a severity by `steps` levels, clamped to critical."""
    rank = min(SEVERITY_RANK.get(severity, 2) + steps, SEVERITY_RANK["critical"])
    return next(k for k, v in SEVERITY_RANK.items() if v == rank)


def label(framework: str, control_id: str) -> str:
    return FRAMEWORKS.get(framework, {}).get(control_id, control_id)


def suggests_agentic_effect_class(tool_invoked: bool, text_reaches_sink: bool) -> str:
    """Heuristic AIVSS agentic-effect class.

    A0 = no privileged path reached
    A1 = language reached a privileged decision/tool path
    A2 = attacker language caused an actual privileged tool execution

    This is a triage hint, not an authoritative AIVSS score. An operator must
    confirm the class and the LC/CP/AP/RH/ES metrics.
    """
    if tool_invoked:
        return "A2"
    if text_reaches_sink:
        return "A1"
    return "A0"
