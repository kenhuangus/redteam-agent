"""Agentic surface selection: fingerprint first, then let the ReAct loop choose checks.

The orchestrator is the surface equivalent of a planner-plus-worker pair. It
fingerprints the target once (HTTP baseline, OS identity), turns the fingerprint
into live hypotheses, and hands a read-only action catalog to a ``Reactor``. The
reasoner decides which check family to run next and may raise new hypotheses from
what a check returned; nothing mutates the target because every action passes the
policy before dispatch.
"""

from __future__ import annotations

import datetime
import time
import urllib.parse
from dataclasses import dataclass

from ..policy import PolicyEngine
from ..react import ActionCatalog, ActionSpec, Hypothesis, LLMReasoner, Observation, Reactor, ReactResult, RuleReasoner
from .macos import MacOSAuditor
from .model import SurfaceScan
from .linux import LinuxAuditor
from .webapp import (
    WebSession,
    check_cors,
    check_cookies,
    check_directory_listing,
    check_exposed_paths,
    check_host_header,
    check_methods,
    check_open_redirect,
    check_reflected_params,
    check_robots,
    check_security_headers,
    check_server_disclosure,
    check_tls,
    fingerprint_web,
)
from .windows import WindowsAuditor

TECH_FOLLOWUPS = (
    ("wordpress", ["/wp-json/wp/v2/users", "/readme.html"]),
    ("jvm", ["/actuator/health", "/actuator/env"]),
    ("iis", ["/web.config"]),
    ("php", ["/phpinfo.php"]),
)


@dataclass
class ScanConfig:
    url: str = ""
    ssh_target: str = ""
    os_hint: str = ""             # windows | macos | linux
    authorized_by: str = ""
    authorization_ref: str = ""
    max_steps: int = 32
    max_requests: int = 40
    delay_s: float = 0.0
    timeout_s: float = 15.0
    allow_state_changing: bool = False
    llm_endpoint: str = ""
    llm_model: str = ""
    llm_api_key: str = ""


def _obs(action: str, findings, summary: str = "", data: dict | None = None) -> Observation:
    return Observation(action=action, ok=True, summary=summary, findings=list(findings), data=data or {})


def _scan_from_result(target: str, kind: str, config: ScanConfig, result: ReactResult, started: float) -> SurfaceScan:
    # Every action's findings are kept; the loop's filtered list only holds failures.
    seen: set[str] = set()
    results = []
    for step in result.steps:
        for finding in step.observation.findings:
            key = finding.check_id + finding.status
            if key in seen:
                continue
            seen.add(key)
            results.append(finding)
    scan = SurfaceScan(
        target=target,
        kind=kind,
        authorized_by=config.authorized_by,
        authorization_ref=config.authorization_ref,
        results=results,
        started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        elapsed_s=time.perf_counter() - started,
        command=f"scan {kind} {target}",
    )
    scan.ended_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    return scan


def _reasoner(config: ScanConfig, stagnation_limit: int = 4) -> RuleReasoner | LLMReasoner:
    rules = RuleReasoner(stagnation_limit)
    if config.llm_endpoint and config.llm_model:
        return LLMReasoner(config.llm_endpoint, config.llm_model, config.llm_api_key, fallback=rules)
    return rules


# ---------------------------------------------------------------------------
# Web application
# ---------------------------------------------------------------------------
def _web_actions(session: WebSession, baseline, profile: dict) -> ActionCatalog:
    actions = []

    def wrap(name, fn, tags, priority):
        def run(args: dict) -> Observation:
            findings = fn(session, baseline)
            summary = f"{name}: " + "; ".join(
                f"{f.check_id}={f.status}" for f in findings[:6]
            )
            return _obs(name, findings, summary)

        actions.append(ActionSpec(name=name, description=f"Web check {name}", run=run,
                                  tags=tags, priority=priority))

    wrap("headers", check_security_headers, ("security-headers",), 10)
    wrap("tls", check_tls, ("tls",), 11)
    wrap("cors", check_cors, ("cors",), 12)
    wrap("cookies", check_cookies, ("cookies",), 13)
    wrap("disclosure", check_server_disclosure, ("disclosure",), 14)
    wrap("methods", check_methods, ("security-headers",), 15)
    wrap("dirlist", check_directory_listing, ("security-headers",), 16)
    wrap("hostheader", check_host_header, ("security-headers",), 17)
    wrap("robots", check_robots, ("security-headers",), 18)
    wrap("exposed", check_exposed_paths, ("exposed-paths",), 20)
    wrap("reflection", check_reflected_params, ("reflection",), 21)
    wrap("openredirect", check_open_redirect, ("redirect",), 22)
    for tech, paths in TECH_FOLLOWUPS:
        if tech in profile.get("tech", []):
            def make(tech=tech, paths=paths):
                def run(args: dict) -> Observation:
                    findings = []
                    for path in paths:
                        probe = session.get(path)
                        if probe.error:
                            continue
                        if probe.ok and probe.status == 200:
                            marker = f"reached {path} ({len(probe.body)} bytes, body withheld)"
                            findings.append(_tech_finding(tech, path, probe.url, probe.status, marker))
                    return _obs(f"artifacts_{tech}", findings, f"{tech} artifact probes: {len(findings)} reachable")
                return ActionSpec(name=f"artifacts_{tech}", description=f"{tech} artifacts", run=run,
                                  tags=("exposed-paths", "known-artifacts"), priority=23)
            actions.append(make())
    return ActionCatalog(actions)


def _tech_finding(tech: str, path: str, url: str, status: int, evidence: str):
    from .model import SurfaceFinding

    return SurfaceFinding(
        check_id=f"WEB.TECH.{tech}", title=f"{tech} endpoint reachable: {path}", framework="OWASP-WEB-2021",
        category="A05", severity="low", target=url,
        evidence=f"GET {url} -> {status}; {evidence}",
        remediation="Confirm the endpoint is meant to be public and rate-limit it",
        reproduction=f"curl -s {url} -o /dev/null -w '%{{http_code}}'", confidence=0.6, manual_review=True,
        indicators=[tech, path],
    )


def scan_web(config: ScanConfig) -> SurfaceScan:
    started = time.perf_counter()
    policy = PolicyEngine(allow_state_changing=config.allow_state_changing)
    session = WebSession(
        config.url,
        allowed_hosts=(urllib.parse.urlsplit(config.url).hostname or "",),
        policy=policy,
        timeout_s=config.timeout_s,
        max_requests=config.max_requests,
        delay_s=config.delay_s,
    )
    baseline = session.get(config.url)
    if baseline.error:
        from .model import error_result

        scan = SurfaceScan(target=session.base, kind="web", results=[
            error_result("WEB.BASELINE", "Baseline fetch", "OWASP-WEB-2021", "A05", session.base, baseline.error)
        ])
        scan.elapsed_s = time.perf_counter() - started
        return scan
    profile = fingerprint_web(session, baseline)
    hypotheses = [Hypothesis(name=name, rationale="fingerprint", confidence=0.85) for name in profile["hypotheses"]]
    catalog = _web_actions(session, baseline, profile)
    reactor = Reactor(
        goal=f"Find read-only web risks in {session.base} without changing it",
        catalog=catalog, hypotheses=hypotheses, policy=policy,
        reasoner=_reasoner(config), max_steps=config.max_steps, stagnation_limit=4,
    )
    result = reactor.run()
    return _scan_from_result(session.base, "web", config, result, started)


# ---------------------------------------------------------------------------
# Host: Windows, macOS, Linux
# ---------------------------------------------------------------------------
def _host_catalog(kind: str, auditor, policy: PolicyEngine) -> ActionCatalog:
    actions: list[ActionSpec] = []
    checks: list[tuple[str, object, str]] = []
    if kind == "windows":
        checks = [
            ("defender", auditor.check_defender, "W9"),
            ("firewall", auditor.check_firewall, "W12"),
            ("legacy", auditor.check_legacy_protocols, "W12"),
            ("remote", auditor.check_remote_access, "W12"),
            ("privilege", auditor.check_privilege, "W4"),
            ("services", auditor.check_service_paths, "W4"),
            ("accounts", auditor.check_weak_accounts, "W4"),
            ("ports", auditor.check_network_listeners, "W12"),
            ("autoruns", [auditor.check_autoruns], "W2"),
            ("smb-signing", auditor.check_smb_signing, "W12"),
            ("patches", [auditor.check_patches], "W2"),
        ]
    elif kind == "macos":
        checks = [
            ("integrity", auditor.check_integrity, "M2"),
            ("encryption", auditor.check_encryption, "M3"),
            ("firewall", [auditor.check_firewall], "M12"),
            ("ssh", auditor.check_ssh, "M4"),
            ("sudo", [auditor.check_sudo], "M4"),
            ("listening", auditor.check_listening, "M12"),
            ("login", auditor.check_login_settings, "M5"),
            ("updates", [auditor.check_updates], "M2"),
        ]
    else:
        checks = [
            ("ssh", auditor.check_ssh, "L4"),
            ("accounts", auditor.check_accounts, "L4"),
            ("files", auditor.check_files, "L6"),
            ("listening", [auditor.check_listening], "L12"),
            ("updates", [auditor.check_updates], "L2"),
            ("audit", [auditor.check_audit], "L8"),
            ("cron", [auditor.check_cron], "L8"),
            ("firewall", [auditor.check_firewall], "L12"),
        ]
    for priority, (name, target, category) in enumerate(checks, start=10):
        def make(name=name, target=target):
            def run(args: dict) -> Observation:
                produced = target() if callable(target) else list(target)
                if not isinstance(produced, list):
                    produced = [produced]
                summary = f"{name}: " + "; ".join(f"{f.check_id}={f.status}" for f in produced[:5])
                return _obs(name, produced, summary)
            return ActionSpec(name=name, description=f"Host check {name}", run=run,
                              tags=(name,), priority=priority)
        actions.append(make())
    # Platform identity is a prerequisite: it runs first and supplies the kind tags.
    def platform(args: dict) -> Observation:
        if kind == "windows":
            finding = auditor.check_platform()
        elif kind == "macos":
            finding = auditor.check_platform()
        else:
            finding = auditor.check_platform()
        return _obs("platform", [finding], f"platform: {finding.title}", {
            "hypotheses": [kind]
        })

    actions.append(ActionSpec(name="platform", description="Identify the host", run=platform,
                              tags=("platform",), priority=1))
    return ActionCatalog(actions)


def scan_host(config: ScanConfig) -> SurfaceScan:
    started = time.perf_counter()
    policy = PolicyEngine(allow_state_changing=config.allow_state_changing)
    kind, auditor = _detect_host(config, policy)
    catalog = _host_catalog(kind, auditor, policy)
    hypotheses = [Hypothesis(name="platform", rationale="identify the target", confidence=1.0)]
    reactor = Reactor(
        goal=f"Audit this {kind} host read-only and report real weaknesses",
        catalog=catalog, hypotheses=hypotheses, policy=policy,
        reasoner=_reasoner(config), max_steps=config.max_steps, stagnation_limit=4,
    )
    result = reactor.run()
    target = config.ssh_target or "localhost"
    return _scan_from_result(target, kind, config, result, started)


def _detect_host(config: ScanConfig, policy: PolicyEngine):
    hint = (config.os_hint or "").lower()
    if hint == "windows":
        return "windows", WindowsAuditor(policy)
    if hint == "macos" or hint == "mac":
        return "macos", MacOSAuditor(ssh_target=config.ssh_target, policy=policy)
    if hint == "linux":
        return "linux", LinuxAuditor(ssh_target=config.ssh_target, policy=policy)
    if config.ssh_target:
        probe = LinuxAuditor(ssh_target=config.ssh_target, policy=policy).check_platform()
        if "Darwin" in probe.evidence or "macOS" in probe.evidence:
            return "macos", MacOSAuditor(ssh_target=config.ssh_target, policy=policy)
        return "linux", LinuxAuditor(ssh_target=config.ssh_target, policy=policy)
    return "windows", WindowsAuditor(policy)
