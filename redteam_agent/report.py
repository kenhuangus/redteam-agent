"""Report generation: machine-readable JSON plus a human Markdown deliverable."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .attacks import categories
from .taxonomy import SEVERITY_RANK, label

REMEDIATION: dict[str, list[str]] = {
    "LLM01": [
        "Treat all user and retrieved text as untrusted data with explicit delimiters.",
        "Keep the instruction hierarchy in a separate channel from user content.",
        "Run a deterministic injection classifier before the model call.",
    ],
    "LLM02": [
        "Redact PII at the retrieval boundary, not at the output boundary.",
        "Apply field-level entitlements to every record before it enters context.",
        "Log and alert on bulk record retrieval per session.",
    ],
    "LLM06": [
        "Require an out-of-band human approval token for state-changing tools.",
        "Enforce server-side scope checks; never trust model-supplied arguments.",
        "Bind every tool call to the authenticated session, not the prompt.",
    ],
    "LLM07": [
        "Keep non-essential secrets out of the prompt entirely.",
        "Assume the system prompt is public; put policy in the guard, not the text.",
        "Detect prompt-echo patterns in output and suppress them.",
    ],
    "LLM09": [
        "Add citation grounding with an allowlist of sources.",
        "Require uncertainty language when no source is retrieved.",
        "Evaluate on a hallucination benchmark before and after changes.",
    ],
    "LLM10": [
        "Enforce max_tokens per request and per session.",
        "Rate-limit per principal and cap spend per tenant.",
        "Detect repetition collapse and truncate with a hard ceiling.",
    ],
    "ASI01": [
        "Pin the objective for the session; reject goal changes originating from content.",
        "Re-plan with a signed goal token issued at session start.",
    ],
    "ASI02": [
        "Validate tool arguments against a JSON schema with server-side allowlists.",
        "Reject any argument that contains control sequences or chained calls.",
    ],
    "ASI03": [
        "Bind credentials to the initiating principal; use per-tenant short-lived tokens.",
        "Verify tenant identity at the data layer, not in prompt text.",
    ],
    "ASI06": [
        "Write memory only through a mediated, signed, reviewed path.",
        "Tag memory entries by provenance and expiry; re-verify before reuse.",
    ],
    "ASI08": [
        "Render approval requests with provenance and never with model-authored urgency framing.",
        "Require multi-party confirmation for privileged actions triggered by generated text.",
    ],
    "ASI10": [
        "Egress allowlist plus DLP on every tool output path.",
        "Strip attachments from outbound tool calls unless explicitly approved.",
    ],
}


@dataclass
class ReportBundle:
    json_path: Path
    md_path: Path
    payload: dict[str, Any]


def _severity_bar(counts: dict[str, int]) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    return " | ".join(f"{k}: {counts.get(k, 0)}" for k in order)


def build_payload(
    *,
    config: Any,
    result: Any,
    agent: Any,
) -> dict[str, Any]:
    scope = config.scope
    findings = sorted(result.findings, key=lambda f: f.severity_rank, reverse=True)
    counts = result.memory.severity_counts() if result.memory else {}
    # Coverage belongs to the run, not to whichever agent object is passed in:
    # a caller may hand us the report of an earlier run.
    coverage = (
        result.memory.coverage_matrix(categories())
        if result.memory
        else agent.coverage()
    )

    return {
        "schema": "redteam-agent/report/v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "engagement": {
            "target": result.target_name,
            "model": result.model,
            "kind": config.target.kind,
            "authorized_by": scope.authorized_by or ("n/a (mock target)" if scope.is_mock else ""),
            "authorization_ref": scope.authorization_ref or "n/a (mock target)",
            "note": scope.note,
        },
        "run": {
            "probes": result.probes,
            "turns": result.turns,
            "errors": result.errors,
            "elapsed_seconds": round(result.elapsed_s, 2),
            "stopped_reason": result.stopped_reason,
            "budget": {
                "max_probes": scope.max_probes,
                "max_turns": scope.max_turns,
                "rate_limit_per_min": scope.rate_limit_per_min,
            },
            "seed": config.seed,
        },
        "summary": {
            "findings_total": len(findings),
            "severity_counts": counts,
            "severity_bar": _severity_bar(counts),
            "categories_exposed": sum(1 for row in coverage if row["findings"] > 0),
            "categories_tested": sum(1 for row in coverage if row["probes"] > 0),
            "needs_manual_review": sum(1 for f in findings if f.needs_manual_review),
            "confirmed": sum(1 for f in findings if f.confirmed is True),
            "not_reproduced": sum(1 for f in findings if f.confirmed is False),
        },
        "coverage": coverage,
        "findings": [
            {
                **f.to_dict(),
                "remediation": REMEDIATION.get(f.category, []),
            }
            for f in findings
        ],
        "limitations": [
            "Rule-based judging can produce false positives; confirm every finding manually.",
            "Findings are only valid for the model, version, and system prompt tested.",
            "Coverage counts indicate probes sent, not depth of coverage.",
            "Severity is an impact heuristic; it is not a CVSS or AIVSS score.",
        ],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    eng = payload["engagement"]
    run = payload["run"]
    summary = payload["summary"]

    out: list[str] = []
    out.append("# AI Red-Team Report")
    out.append("")
    out.append(f"- **Target:** `{eng['target']}`")
    out.append(f"- **Model:** `{eng['model'] or 'n/a'}`")
    out.append(f"- **Authorization:** {eng['authorized_by'] or 'n/a'}")
    out.append(f"- **Reference:** {eng['authorization_ref'] or 'n/a'}")
    out.append(f"- **Generated:** {payload['generated_at']}")
    out.append("")
    out.append("## Executive summary")
    out.append("")
    out.append(f"{summary['findings_total']} findings across "
               f"{summary['categories_tested']} tested categories.")
    out.append("")
    out.append(f"| Severity | Count |")
    out.append("|---|---|")
    for sev in ["critical", "high", "medium", "low", "info"]:
        out.append(f"| {sev} | {summary['severity_counts'].get(sev, 0)} |")
    out.append("")
    out.append(f"Probes sent: **{run['probes']}** | Turns: **{run['turns']}** | "
               f"Errors: **{run['errors']}** | Elapsed: **{run['elapsed_seconds']}s**")
    out.append(f"Stopped: `{run['stopped_reason']}`")
    out.append("")

    out.append("## Coverage matrix")
    out.append("")
    out.append("| Category | Control | Probes | Findings | Best severity | Exposed | Working mutations |")
    out.append("|---|---|---|---|---|---|---|")
    for row in payload["coverage"]:
        mutations = ", ".join(row["working_mutations"]) or "-"
        exposed = "yes" if row["exposed"] else "no"
        out.append(
            f"| {row['category']} | {row['label']} | {row['probes']} | "
            f"{row['findings']} | {row['best_severity']} | {exposed} | {mutations} |"
        )
    out.append("")

    if payload["findings"]:
        out.append("## Findings")
        out.append("")
        for f in payload["findings"]:
            out.append(f"### {f['id']} - {f['title']} ({f['severity'].upper()})")
            out.append("")
            out.append(f"- **Category:** {f['framework']} {f['category']} - {f['control_label']}")
            out.append(f"- **Confidence:** {f['confidence']}")
            out.append(f"- **Agentic effect class (heuristic):** {f['agentic_class']}")
            out.append(f"- **Mutation:** `{f['mutation']}`")
            out.append(f"- **Indicators:** {', '.join(f['indicators']) or '-'}")
            confirmed = f.get("confirmed")
            if confirmed is True:
                out.append(f"- **Reproduced:** yes (`{f['confirm_with']}`)")
            elif confirmed is False:
                out.append(
                    f"- **Reproduced:** no (`{f['confirm_with']}`) - treat as unconfirmed"
                )
            else:
                out.append("- **Reproduced:** not attempted")
            if f["needs_manual_review"]:
                out.append("- **Status:** requires manual verification")
            out.append("")
            out.append(f"**Goal:** {f['goal']}")
            out.append("")
            out.append(f"**Judge reasoning:** {f['reasoning']}")
            out.append("")
            out.append("Evidence:")
            out.append("")
            out.append("```text")
            out.append((f["transcript"] or "")[:800].replace("```", "'''"))
            if f["tool_calls"]:
                out.append("tool_calls: " + json.dumps(f["tool_calls"], ensure_ascii=False))
            out.append("```")
            out.append("")
            if f["remediation"]:
                out.append("Recommended remediation:")
                out.append("")
                for item in f["remediation"]:
                    out.append(f"- {item}")
                out.append("")
            out.append("Reproduce:")
            out.append("")
            out.append("```bash")
            out.append(
                f"python -m redteam_agent run --target {eng['kind']} "
                f"--only {f['attack_id']}"
            )
            out.append("```")
            out.append("")

    out.append("## Limitations")
    out.append("")
    for item in payload["limitations"]:
        out.append(f"- {item}")
    out.append("")
    out.append("## Notes on scoring")
    out.append("")
    out.append(
        "Severity is a heuristic combining the attack's expected impact with the "
        "confidence of the judge. The `agentic_class` field is a triage hint "
        "(A0/A1/A2) based on whether attacker language reached a privileged path "
        "or caused a tool execution. Neither is an authoritative AIVSS or CVSS "
        "value; an operator must confirm scoring."
    )
    out.append("")
    return "\n".join(out)


def write_reports(
    *,
    config: Any,
    result: Any,
    agent: Any,
    output_dir: str | Path | None = None,
) -> ReportBundle:
    out_dir = Path(output_dir or config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

    payload = build_payload(config=config, result=result, agent=agent)
    json_path = out_dir / f"redteam-{stamp}.json"
    md_path = out_dir / f"redteam-{stamp}.md"

    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    return ReportBundle(json_path=json_path, md_path=md_path, payload=payload)


# ----------------------------------------------------------------------------
# SARIF 2.1.0 output, for GitHub code scanning and other CI consumers.
# ----------------------------------------------------------------------------

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "info": "note",
}


def _fingerprint(finding: Any) -> str:
    """Stable per-finding identifier: no transcript, so leaked data does not travel."""
    basis = f"{finding.attack_id}|{finding.category}|{finding.mutation}|{finding.title}"
    return hashlib.sha256(basis.encode()).hexdigest()[:32]


def build_sarif(*, config: Any, result: Any) -> dict[str, Any]:
    """Render a SARIF log of the confirmed findings.

    Raw transcripts are deliberately omitted: they can contain the secrets or PII
    the run itself found, and CI logs are a poor place to publish them. Reasoning
    and indicators carry enough context to triage.
    """
    findings = sorted(result.findings, key=lambda f: f.severity_rank, reverse=True)
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rules.setdefault(
            finding.attack_id,
            {
                "id": finding.attack_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.goal},
                "defaultConfiguration": {
                    "level": SARIF_LEVELS.get(finding.severity, "note")
                },
                "properties": {
                    "framework": finding.framework,
                    "category": finding.category,
                    "control": finding.control_label,
                    "tags": [finding.framework, finding.category],
                },
            },
        )

    results = []
    for finding in findings:
        indicators = ", ".join(finding.indicators) or "none"
        message = (
            f"{finding.attack_id} ({finding.control_label}): {finding.reasoning} "
            f"Indicators: {indicators}."
        )
        remediation = REMEDIATION.get(finding.category, [])
        markdown = message
        if remediation:
            markdown += "\n\nRemediation:\n" + "\n".join(f"- {item}" for item in remediation)
        results.append(
            {
                "ruleId": finding.attack_id,
                "level": SARIF_LEVELS.get(finding.severity, "note"),
                "message": {"text": message, "markdown": markdown},
                "partialFingerprints": {
                    "redteamFinding/v1": _fingerprint(finding)
                },
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "framework": finding.framework,
                    "category": finding.category,
                    "control": finding.control_label,
                    "mutation": finding.mutation,
                    "indicators": finding.indicators,
                    "needs_manual_review": finding.needs_manual_review,
                    "confirmed": finding.confirmed,
                    "confirm_with": finding.confirm_with,
                    "remediation": remediation,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "redteam-agent",
                        "version": _version(),
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": _iso(result.started_at),
                        "endTimeUtc": _iso(result.ended_at),
                    }
                ],
                "results": results,
                "properties": {
                    "engagement": {
                        "target": result.target_name,
                        "model": result.model,
                        "kind": config.target.kind,
                        "authorized_by": config.scope.authorized_by,
                        "authorization_ref": config.scope.authorization_ref,
                    },
                    "probes": result.probes,
                    "stopped_reason": result.stopped_reason,
                },
            }
        ],
    }


def _version() -> str:
    from . import __version__

    return __version__


def _iso(timestamp: float) -> str:
    if not timestamp:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))


def write_sarif(path: str | Path, payload: dict[str, Any]) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out
