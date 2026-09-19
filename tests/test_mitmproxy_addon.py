"""Tests for deploy/mitmproxy/policy_addon.py's pure decision logic
(evaluate_request, load_agent_policies). These do not require mitmproxy to be
installed — only the module's top-level `try: import mitmproxy` branch is
skipped, which is exactly the fallback the module documents for this case.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent
ADDON_PATH = REPO_ROOT / "deploy" / "mitmproxy" / "policy_addon.py"


def _load_addon_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("policy_addon", ADDON_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["policy_addon"] = module
    spec.loader.exec_module(module)
    return module


policy_addon = _load_addon_module()


def test_load_agent_policies_reads_the_real_registry() -> None:
    policies = policy_addon.load_agent_policies(
        registry_path=REPO_ROOT / "registry" / "agents.yaml", app_root=REPO_ROOT
    )
    assert "agt-log-reader-001" in policies
    assert policies["agt-log-reader-001"]["role"] == "read-only-agent"


def test_evaluate_request_allows_allowlisted_destination() -> None:
    policies = policy_addon.load_agent_policies(
        registry_path=REPO_ROOT / "registry" / "agents.yaml", app_root=REPO_ROOT
    )
    result = policy_addon.evaluate_request("agt-log-reader-001", "internal-logs.example.com", policies)
    assert result["verdict"] == "allow"
    assert result["agent_id"] == "agt-log-reader-001"


def test_evaluate_request_denies_non_allowlisted_destination() -> None:
    policies = policy_addon.load_agent_policies(
        registry_path=REPO_ROOT / "registry" / "agents.yaml", app_root=REPO_ROOT
    )
    result = policy_addon.evaluate_request("agt-log-reader-001", "evil.example.net", policies)
    assert result["verdict"] == "deny"
    assert result["rule_id"] == "AGT-EGRESS-001"


def test_evaluate_request_fails_closed_on_unknown_agent() -> None:
    policies = policy_addon.load_agent_policies(
        registry_path=REPO_ROOT / "registry" / "agents.yaml", app_root=REPO_ROOT
    )
    result = policy_addon.evaluate_request("agt-does-not-exist", "internal-logs.example.com", policies)
    assert result["verdict"] == "deny"


def test_evaluate_request_fails_closed_on_missing_agent_id() -> None:
    policies = policy_addon.load_agent_policies(
        registry_path=REPO_ROOT / "registry" / "agents.yaml", app_root=REPO_ROOT
    )
    result = policy_addon.evaluate_request(None, "internal-logs.example.com", policies)
    assert result["verdict"] == "deny"
