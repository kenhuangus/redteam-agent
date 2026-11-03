"""Command-line interface.

    python -m redteam_agent demo
    python -m redteam_agent run --target mock --verbose
    python -m redteam_agent run --target http --endpoint https://... \\
        --allow-host api.internal.example --authorized-by "K. Huang" \\
        --authorization-ref REDTEAM-2026-014
    python -m redteam_agent list-attacks
    python -m redteam_agent validate --config engagement.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .agent import RedTeamAgent
from .attacks import ATTACKS
from .config import AuthorizationError, JudgeConfig, RunConfig, Scope, TargetConfig
from .taxonomy import SEVERITY_RANK
from .judges import build_judge
from .report import build_sarif, write_reports, write_sarif
from .targets import build_target


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redteam_agent",
        description="Authorized AI/agent red-teaming harness for targets you own.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # ---------------------------------------------------------------- run
    run = sub.add_parser("run", help="execute an engagement and write reports")
    run.add_argument("--config", help="JSON engagement config")
    run.add_argument("--target", help="mock | http | openai")
    run.add_argument("--endpoint", help="chat-completions URL for the http target")
    run.add_argument("--model", help="model id sent to the target")
    run.add_argument("--system-prompt", help="system prompt under test")
    run.add_argument("--system-prompt-file", help="file holding the system prompt")
    run.add_argument("--api-key-env", default=None,
                     help="env var NAME holding the target API key")
    run.add_argument("--no-redact-transcripts", action="store_true",
                     help="keep canary and secret shapes in the report transcripts")
    run.add_argument("--stagnation-rounds", type=int, default=None,
                     help="stop after N consecutive unproductive attack rounds")
    run.add_argument("--target-error-limit", type=int, default=None,
                     help="stop after N consecutive probe errors (dead host guard)")
    run.add_argument("--evidence-dir", default=None,
                     help="write probes.jsonl + manifest.json evidence log here")
    run.add_argument("--no-quality-gate", action="store_true",
                     help="skip the finding quality gate metadata")
    run.add_argument("--static-payloads", action="store_true",
                     help="use the fixed mutation ladder instead of the ReAct payload lab")
    run.add_argument("--allow-state-changing", action="store_true",
                     help="permit probes whose prize is a mutating tool call (sandbox the target first)")
    run.add_argument("--allowed-host", action="append", default=[],
                     help="hostname allowed by scope (repeatable)")
    run.add_argument("--authorized-by", default="", help="approving human")
    run.add_argument("--authorization-ref", default="", help="ticket / SOW id")
    run.add_argument("--note", default="", help="scope note recorded in the report")
    run.add_argument("--max-probes", type=int, default=None)
    run.add_argument("--max-turns", type=int, default=None)
    run.add_argument("--rate-limit", type=int, default=None, help="probes per minute")
    run.add_argument("--stop-on-critical", action="store_true")
    run.add_argument("--payloads", type=int, default=None, help="payloads per attack")
    run.add_argument("--mutations", type=int, default=None, help="mutations per payload")
    run.add_argument("--seed", type=int, default=None)
    run.add_argument("--output-dir", default=None, help="report directory (default: config or reports)")
    run.add_argument("--llm-judge", action="store_true",
                     help="enable an LLM judge (needs an API key)")
    run.add_argument("--judge-model", default=None)
    run.add_argument("--canary", default=None)
    run.add_argument("--only", action="append", default=[],
                     help="restrict to specific attack ids (repeatable)")
    run.add_argument("--verbose", "-v", action="store_true")
    run.add_argument("--quiet", "-q", action="store_true")
    run.add_argument("--json", action="store_true", help="print JSON to stdout")
    run.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="none",
        help="exit 3 when a finding reaches this severity (for CI gates)",
    )
    run.add_argument(
        "--sarif",
        nargs="?",
        const="redteam.sarif",
        default=None,
        help="also write SARIF 2.1.0 (default path: redteam.sarif)",
    )

    # ------------------------------------------------------------ validate
    val = sub.add_parser("validate", help="check scope without probing")
    val.add_argument("--config", required=True)

    # -------------------------------------------------------- list-attacks
    sub.add_parser("list-attacks", help="print the attack library")

    # ------------------------------------------------------------ scan-web
    scan = sub.add_parser("scan-web", help="read-only web-application scan")
    scan.add_argument("--url", required=True, help="https://app.example/ path")
    scan.add_argument("--authorized-by", default="", help="approving human (required)")
    scan.add_argument("--authorization-ref", default="", help="ticket / SOW id")
    scan.add_argument("--max-requests", type=int, default=40)
    scan.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    scan.add_argument("--timeout", type=float, default=15.0)
    scan.add_argument("--max-steps", type=int, default=32, help="ReAct step budget")
    scan.add_argument("--planner-endpoint", default="", help="OpenAI-compatible model for the ReAct reasoner")
    scan.add_argument("--planner-model", default="")
    scan.add_argument("--planner-api-key-env", default="")
    scan.add_argument("--output-dir", default="reports")
    scan.add_argument("--fail-on", default="none", choices=["none", "low", "medium", "high", "critical"])
    scan.add_argument("--json", action="store_true", help="print the JSON payload")

    # ---------------------------------------------------------- audit-host
    host = sub.add_parser("audit-host", help="read-only Windows/macOS/Linux endpoint audit")
    host.add_argument("--os", default="auto", choices=["auto", "windows", "macos", "linux"])
    host.add_argument("--ssh", default="", help="ssh target such as user@host (macOS/Linux)")
    host.add_argument("--authorized-by", default="")
    host.add_argument("--authorization-ref", default="")
    host.add_argument("--max-steps", type=int, default=26)
    host.add_argument("--timeout", type=float, default=30.0)
    host.add_argument("--delay", type=float, default=0.0)
    host.add_argument("--planner-endpoint", default="")
    host.add_argument("--planner-model", default="")
    host.add_argument("--planner-api-key-env", default="")
    host.add_argument("--output-dir", default="reports")
    host.add_argument("--fail-on", default="none", choices=["none", "low", "medium", "high", "critical"])
    host.add_argument("--json", action="store_true")

    # ---------------------------------------------------------------- demo
    demo = sub.add_parser("demo", help="offline run against the mock target")
    demo.add_argument("--verbose", "-v", action="store_true")
    demo.add_argument("--output-dir", default="reports")
    return p


def _stderr_logger(enabled: bool):
    if not enabled:
        return None

    def logger(message: str) -> None:
        print(message, file=sys.stderr)

    return logger


def _load_config(args: argparse.Namespace) -> RunConfig:
    config = RunConfig.from_json(args.config) if args.config else RunConfig()
    scope, target, judges = config.scope, config.target, config.judges

    if args.target:
        target.kind = args.target
        scope.target_name = args.target
    if args.endpoint:
        target.endpoint = args.endpoint
        host = urlsplit(args.endpoint).hostname or args.endpoint
        scope.target_host = host
        if not scope.allowed_hosts:
            scope.allowed_hosts = (host,)
    if args.allowed_host:
        scope.allowed_hosts = tuple(args.allowed_host)
    if args.model:
        target.model = args.model
    if args.system_prompt_file:
        target.system_prompt = (
            Path(args.system_prompt_file).read_text(encoding="utf-8").strip()
        )
    elif args.system_prompt:
        target.system_prompt = args.system_prompt
    if args.api_key_env:
        target.api_key_env = args.api_key_env

    scope.authorized_by = args.authorized_by or scope.authorized_by
    scope.authorization_ref = args.authorization_ref or scope.authorization_ref
    scope.note = args.note or scope.note
    if args.max_probes is not None:
        scope.max_probes = args.max_probes
    if args.max_turns is not None:
        scope.max_turns = args.max_turns
    if args.rate_limit is not None:
        scope.rate_limit_per_min = args.rate_limit
    if args.stop_on_critical:
        scope.stop_on_critical = True

    if args.llm_judge:
        judges.use_llm_judge = True
    # argparse defaults must stay None here: a non-None default would overwrite a
    # value the engagement config file already set.
    if args.judge_model:
        judges.judge_model = args.judge_model
    if args.canary:
        judges.canary = args.canary
    if args.no_redact_transcripts:
        config.redact_transcripts = False
    if args.stagnation_rounds is not None:
        config.stagnation_rounds = max(1, args.stagnation_rounds)
    if args.target_error_limit is not None:
        config.target_error_limit = max(1, args.target_error_limit)
    if args.evidence_dir:
        config.evidence_dir = args.evidence_dir
    if args.no_quality_gate:
        config.quality_gate = False
    if args.static_payloads:
        config.agentic_payloads = False
    if args.allow_state_changing:
        config.allow_state_changing = True

    config.scope = scope
    config.target = target
    config.judges = judges
    if args.output_dir is not None:
        config.output_dir = args.output_dir
    if args.seed is not None:
        config.seed = args.seed
    if args.payloads is not None:
        config.payloads_per_attack = max(1, args.payloads)
    if args.mutations is not None:
        config.mutations_per_payload = max(1, args.mutations)
    return config


def _build(config: RunConfig, *, verbose: bool, attack_ids=None) -> tuple[RedTeamAgent, object]:
    target = build_target(config.target)
    agent = RedTeamAgent(
        config=config,
        target=target,
        judge=build_judge(config.judges),
        logger=_stderr_logger(verbose),
        attack_ids=attack_ids,
    )
    return agent, target


def _check_credentials(config: RunConfig) -> bool:
    """Surface the common failure up front instead of as N probe errors.

    A missing key is only fatal for the OpenAI SDK target: the SDK requires one.
    A plain HTTP endpoint may be unauthenticated, so that case warns and proceeds.
    """
    kind = config.target.kind.lower()
    if kind not in ("http", "openai"):
        return True
    name = config.target.api_key_env
    if os.environ.get(name, "").strip():
        return True
    message = f"target API key env var {name!r} is unset or empty"
    if kind == "openai":
        print(f"setup error: {message}", file=sys.stderr)
        return False
    print(
        f"warning: {message}; if the endpoint requires auth every probe will error",
        file=sys.stderr,
    )
    return True


def cmd_run(args: argparse.Namespace) -> int:
    config = _load_config(args)
    try:
        config.scope.validate()
    except AuthorizationError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2

    if not _check_credentials(config):
        return 2

    try:
        agent, _target = _build(config, verbose=args.verbose, attack_ids=args.only or None)
    except (ValueError, RuntimeError) as exc:
        print(f"setup error: {exc}", file=sys.stderr)
        return 2

    result = agent.run()
    bundle = write_reports(config=config, result=result, agent=agent)

    if args.sarif:
        sarif_path = write_sarif(args.sarif, build_sarif(config=config, result=result))
        if not args.quiet:
            print(f"SARIF: {sarif_path}", file=sys.stderr)

    if args.json:
        print(json.dumps(bundle.payload, indent=2, ensure_ascii=False))
    elif not args.quiet:
        print(bundle.md_path.read_text(encoding="utf-8"))
    else:
        print(bundle.md_path)

    gate = args.fail_on
    if gate != "none":
        threshold = SEVERITY_RANK[gate]
        worst = max((f.severity_rank for f in result.findings), default=-1)
        if worst >= threshold:
            print(
                f"gate: a {gate}-or-worse finding was reported (exit 3)",
                file=sys.stderr,
            )
            return 3
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    config = RunConfig.from_json(args.config)
    try:
        config.scope.validate()
    except AuthorizationError as exc:
        print(f"INVALID: {exc}")
        return 2
    print("VALID scope")
    print(json.dumps(config.to_json(), indent=2))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    print(f"{'id':<10} {'framework':<18} {'cat':<6} {'sev':<9} title")
    for attack in ATTACKS:
        print(
            f"{attack.id:<10} {attack.framework:<18} {attack.category:<6} "
            f"{attack.severity_on_success:<9} {attack.title}"
        )
    return 0


def cmd_scan_web(args: argparse.Namespace) -> int:
    from .surface.orchestrator import ScanConfig, scan_web
    from .surface.report import write_surface_reports

    if not args.authorized_by:
        print("scope error: --authorized-by is required for a web scan", file=sys.stderr)
        return 2
    api_key = os.environ.get(args.planner_api_key_env, "") if args.planner_api_key_env else ""
    config = ScanConfig(
        url=args.url,
        authorized_by=args.authorized_by,
        authorization_ref=args.authorization_ref,
        max_requests=args.max_requests,
        delay_s=args.delay,
        timeout_s=args.timeout,
        max_steps=args.max_steps,
        llm_endpoint=args.planner_endpoint,
        llm_model=args.planner_model,
        llm_api_key=api_key,
    )
    scan = scan_web(config)
    json_path, md_path, payload = write_surface_reports(scan, args.output_dir)
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(md_path.read_text(encoding="utf-8"))
    gate = args.fail_on
    if gate != "none" and scan.findings:
        if scan.findings[0].severity_rank >= SEVERITY_RANK[gate]:
            print(f"gate: a {gate}-or-worse finding was reported (exit 3)", file=sys.stderr)
            return 3
    return 0


def cmd_audit_host(args: argparse.Namespace) -> int:
    from .surface.orchestrator import ScanConfig, scan_host
    from .surface.report import write_surface_reports

    api_key = os.environ.get(args.planner_api_key_env, "") if args.planner_api_key_env else ""
    config = ScanConfig(
        os_hint="" if args.os == "auto" else args.os,
        ssh_target=args.ssh,
        authorized_by=args.authorized_by,
        authorization_ref=args.authorization_ref,
        max_steps=args.max_steps,
        timeout_s=args.timeout,
        delay_s=args.delay,
        llm_endpoint=args.planner_endpoint,
        llm_model=args.planner_model,
        llm_api_key=api_key,
    )
    scan = scan_host(config)
    json_path, md_path, payload = write_surface_reports(scan, args.output_dir)
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(md_path.read_text(encoding="utf-8"))
    gate = args.fail_on
    if gate != "none" and scan.findings:
        if scan.findings[0].severity_rank >= SEVERITY_RANK[gate]:
            print(f"gate: a {gate}-or-worse finding was reported (exit 3)", file=sys.stderr)
            return 3
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    config = RunConfig(
        scope=Scope(target_name="mock", max_probes=60, max_turns=60),
        target=TargetConfig(kind="mock"),
        judges=JudgeConfig(),
        output_dir=args.output_dir,
        seed=1337,
        payloads_per_attack=2,
        mutations_per_payload=3,
    )
    agent, _target = _build(config, verbose=args.verbose)
    result = agent.run()
    bundle = write_reports(config=config, result=result, agent=agent)
    print(bundle.md_path.read_text(encoding="utf-8"))
    print(f"\nJSON: {bundle.json_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    handlers = {
        "run": cmd_run,
        "validate": cmd_validate,
        "list-attacks": cmd_list,
        "demo": cmd_demo,
        "scan-web": cmd_scan_web,
        "audit-host": cmd_audit_host,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
