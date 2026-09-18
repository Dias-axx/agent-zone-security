from __future__ import annotations

import textwrap
from pathlib import Path

from control import validate as validate_module


def _write_policy(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body))


BASE_POLICY = """
    role: test-role
    identity:
      type: standalone
      ttl_seconds: 300
    capabilities:
      tools: []
      confirm_required: []
    egress:
      default: deny
      allowlist: []
    zones:
      home: agent-restricted
      reachable: []
    response:
      on_violation: alert
"""


def test_well_formed_policy_has_no_errors(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, BASE_POLICY)
    assert validate_module.validate_policy(policy_path) == []


def test_missing_egress_default_rejected(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, BASE_POLICY.replace("default: deny", "default: allow"))
    errors = validate_module.validate_policy(policy_path)
    assert any("egress.default" in e for e in errors)


def test_wildcard_egress_entry_rejected(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, BASE_POLICY.replace("allowlist: []", 'allowlist: ["*.example.com"]'))
    errors = validate_module.validate_policy(policy_path)
    assert any("malformed egress allowlist" in e for e in errors)


def test_ttl_above_ceiling_rejected(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, BASE_POLICY.replace("ttl_seconds: 300", "ttl_seconds: 999999"))
    errors = validate_module.validate_policy(policy_path)
    assert any("exceeds ceiling" in e for e in errors)


def test_delegated_identity_without_source_rejected(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, BASE_POLICY.replace("type: standalone", "type: delegated"))
    errors = validate_module.validate_policy(policy_path)
    assert any("delegates_scope_from" in e for e in errors)


def test_missing_on_violation_rejected(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, BASE_POLICY.replace("on_violation: alert", "on_violation: nonsense"))
    errors = validate_module.validate_policy(policy_path)
    assert any("response.on_violation" in e for e in errors)


def test_registry_zone_mismatch_rejected() -> None:
    entry = {"id": "agt-x", "zone": "corp-prod", "delegated_by": None}
    policy = {"zones": {"home": "agent-restricted"}, "identity": {"type": "standalone"}}
    errors = validate_module.validate_entry(entry, policy)
    assert any("does not match policy home zone" in e for e in errors)


def test_registry_zone_match_has_no_error() -> None:
    entry = {"id": "agt-x", "zone": "agent-restricted", "delegated_by": None}
    policy = {"zones": {"home": "agent-restricted"}, "identity": {"type": "standalone"}}
    assert validate_module.validate_entry(entry, policy) == []


def test_registry_delegated_without_delegated_by_rejected() -> None:
    entry = {"id": "agt-x", "zone": "agent-restricted", "delegated_by": None}
    policy = {"zones": {"home": "agent-restricted"}, "identity": {"type": "delegated"}}
    errors = validate_module.validate_entry(entry, policy)
    assert any("delegated_by" in e for e in errors)


def test_seed_registry_is_internally_consistent() -> None:
    assert validate_module.validate_registry() == []
