"""Surface scan reports: JSON for tooling, Markdown for the operator."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

from .model import SurfaceScan


def build_surface_payload(scan: SurfaceScan, extra: dict | None = None) -> dict:
    counts = scan.severity_counts()
    return {
        "schema": "redteam-agent/surface-scan/v1",
        "target": scan.target,
        "kind": scan.kind,
        "authorization": {
            "authorized_by": scan.authorized_by,
            "reference": scan.authorization_ref,
            "mode": "read-only",
        },
        "started_at": scan.started_at,
        "ended_at": scan.ended_at,
        "elapsed_seconds": round(scan.elapsed_s, 2),
        "command": scan.command,
        "summary": {
            "findings": len(scan.findings),
            "checks": len(scan.results),
            "errors": sum(1 for r in scan.results if r.status == "error"),
            "severity_counts": counts,
            "worst": scan.findings[0].severity if scan.findings else "",
        },
        "findings": [f.to_dict() for f in scan.findings],
        "checks": [r.to_dict() for r in scan.results],
        "extra": extra or {},
    }


def render_surface_markdown(scan: SurfaceScan, extra: dict | None = None) -> str:
    counts = scan.severity_counts()
    lines = [
        f"# Read-only surface scan — {scan.kind} — {scan.target}",
        "",
        f"- Started: {scan.started_at}",
        f"- Elapsed: {scan.elapsed_s:.2f}s",
        f"- Mode: read-only (no check writes, installs or restarts)",
        f"- Authorization: {scan.authorized_by or 'not recorded'}"
        + (f" ({scan.authorization_ref})" if scan.authorization_ref else ""),
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity} | {counts.get(severity, 0)} |")
    lines.append("")
    if extra:
        lines.append("## Discovery")
        lines.append("")
        for key, value in extra.items():
            lines.append(f"- {key}: `{json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value}`")
        lines.append("")
    if not scan.findings:
        lines.append("No finding passed the check's evidence bar. This is a clean result for the checks that ran,")
        lines.append("not a proof that the target is secure.")
        lines.append("")
    lines.append("## Findings")
    lines.append("")
    for finding in scan.findings:
        lines.append(f"### {finding.severity.upper()} — {finding.title}")
        lines.append("")
        lines.append(f"- Check: `{finding.check_id}`")
        lines.append(f"- Framework: `{finding.framework}` category `{finding.category}`")
        lines.append(f"- Confidence: {finding.confidence:.2f}" + (" — manual review required" if finding.manual_review else ""))
        if finding.evidence:
            lines.append(f"- Evidence: {finding.evidence}")
        if finding.remediation:
            lines.append(f"- Fix: {finding.remediation}")
        if finding.reproduction:
            lines.append(f"- Reproduce: `{finding.reproduction}`")
        lines.append("")
    lines.append("## Checks")
    lines.append("")
    lines.append("| Check | Status | Severity | Detail |")
    lines.append("|---|---|---|---|")
    for result in scan.results:
        detail = result.notes if result.status == "error" else result.evidence
        detail = (detail or "").replace("|", "\\|")[:180]
        lines.append(f"| {result.check_id} | {result.status} | {result.severity} | {detail} |")
    lines.append("")
    return "\n".join(lines)


def write_surface_reports(scan: SurfaceScan, output_dir: str = "reports", extra: dict | None = None) -> tuple[Path, Path, dict]:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    slug = "".join(ch for ch in scan.target.lower() if ch.isalnum() or ch in "-.")[:60] or "target"
    payload = build_surface_payload(scan, extra)
    json_path = out / f"surface-{scan.kind}-{slug}-{stamp}.json"
    md_path = out / f"surface-{scan.kind}-{slug}-{stamp}.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render_surface_markdown(scan, extra), encoding="utf-8")
    return json_path, md_path, payload
