"""Scope/authorization and CLI config-merging tests."""

import json

import pytest

from redteam_agent.cli import _load_config, _parser
from redteam_agent.config import (
    AuthorizationError,
    JudgeConfig,
    RunConfig,
    Scope,
    TargetConfig,
)


def test_mock_scope_needs_no_authorization():
    Scope(target_name="mock").validate()


def test_live_target_requires_approver():
    scope = Scope(
        target_name="http",
        target_host="api.internal.example",
        allowed_hosts=("api.internal.example",),
    )
    with pytest.raises(AuthorizationError, match="authorized_by"):
        scope.validate()


def test_live_target_requires_reference():
    scope = Scope(
        target_name="http",
        target_host="api.internal.example",
        authorized_by="K. Huang",
        allowed_hosts=("api.internal.example",),
    )
    with pytest.raises(AuthorizationError, match="authorization_ref"):
        scope.validate()


def test_host_must_be_allowlisted():
    scope = Scope(
        target_name="http",
        target_host="api.internal.example",
        authorized_by="K. Huang",
        authorization_ref="REDTEAM-2026-014",
        allowed_hosts=("other.example",),
    )
    with pytest.raises(AuthorizationError, match="not in allowed_hosts"):
        scope.validate()


def test_allowlisted_host_passes():
    Scope(
        target_name="http",
        target_host="API.internal.example",
        authorized_by="K. Huang",
        authorization_ref="REDTEAM-2026-014",
        allowed_hosts=("api.internal.example",),
    ).validate()


def test_budget_floor_is_enforced():
    with pytest.raises(AuthorizationError, match="max_probes"):
        Scope(target_name="mock", max_probes=0).validate()


def _write(tmp_path, data):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_from_json_preserves_tuples_and_defaults(tmp_path):
    path = _write(
        tmp_path,
        {
            "scope": {
                "target_name": "http",
                "target_host": "api.internal.example",
                "allowed_hosts": ["api.internal.example"],
                "max_probes": 25,
            },
            "target": {"kind": "http", "endpoint": "https://api.internal.example/v1"},
            "judges": {"secret_regexes": [r"sk-[A-Za-z0-9]{20,}"]},
        },
    )
    config = RunConfig.from_json(path)

    assert isinstance(config.scope, Scope)
    assert config.scope.allowed_hosts == ("api.internal.example",)
    assert config.scope.max_probes == 25
    assert config.judges.secret_regexes == (r"sk-[A-Za-z0-9]{20,}",)
    assert config.target.kind == "http"
    assert config.payloads_per_attack == 2


def test_cli_flags_do_not_clobber_config_file(tmp_path):
    """Regression: argparse defaults must not overwrite file-provided budgets."""
    path = _write(
        tmp_path,
        {
            "scope": {"target_name": "mock", "max_probes": 12, "max_turns": 9},
            "payloads_per_attack": 3,
            "mutations_per_payload": 4,
            "seed": 99,
        },
    )
    args = _parser().parse_args(["run", "--config", path])
    config = _load_config(args)

    assert config.scope.max_probes == 12
    assert config.scope.max_turns == 9
    assert config.payloads_per_attack == 3
    assert config.mutations_per_payload == 4
    assert config.seed == 99


def test_cli_flags_override_config_file(tmp_path):
    path = _write(tmp_path, {"scope": {"target_name": "mock", "max_probes": 12}})
    args = _parser().parse_args(
        ["run", "--config", path, "--max-probes", "7", "--payloads", "1"]
    )
    config = _load_config(args)

    assert config.scope.max_probes == 7
    assert config.payloads_per_attack == 1


def test_endpoint_populates_scope_host():
    args = _parser().parse_args(
        ["run", "--target", "http", "--endpoint", "https://api.internal.example/v1/chat"]
    )
    config = _load_config(args)

    assert config.target.kind == "http"
    assert config.scope.target_name == "http"
    assert config.scope.target_host == "api.internal.example"
    assert config.scope.allowed_hosts == ("api.internal.example",)
