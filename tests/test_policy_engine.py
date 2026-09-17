from __future__ import annotations

from control.policy_engine import Decision, Request, evaluate

READ_ONLY_POLICY = {
    "role": "read-only-agent",
    "identity": {"type": "standalone", "ttl_seconds": 900},
    "capabilities": {"tools": ["log.read"], "confirm_required": []},
    "egress": {"default": "deny", "allowlist": [".internal.example.com"]},
    "zones": {"home": "agent-restricted", "reachable": []},
}

DELEGATED_POLICY = {
    "role": "deploy-agent",
    "identity": {"type": "delegated", "ttl_seconds": 1800},
    "capabilities": {
        "tools": ["deploy.plan", "deploy.apply", "deploy.rollback"],
        "confirm_required": ["deploy.apply"],
    },
    "egress": {"default": "deny", "allowlist": []},
    "zones": {"home": "agent-restricted", "reachable": []},
}


def test_tool_deny_out_of_scope() -> None:
    verdict = evaluate(READ_ONLY_POLICY, Request("tool", "a1", "deploy.apply"))
    assert verdict.decision == Decision.DENY
    assert verdict.rule_id == "AGT-TOOL-001"


def test_tool_allow_in_scope() -> None:
    verdict = evaluate(READ_ONLY_POLICY, Request("tool", "a1", "log.read"))
    assert verdict.decision == Decision.ALLOW


def test_confirm_required_never_coerces_to_allow() -> None:
    request = Request("tool", "a1", "deploy.apply")
    verdict = evaluate(DELEGATED_POLICY, request, delegating_scope={"deploy.apply"})
    assert verdict.decision == Decision.CONFIRM


def test_and_gate_denies_tool_outside_delegating_user_scope() -> None:
    request = Request("tool", "a1", "deploy.rollback")
    verdict = evaluate(DELEGATED_POLICY, request, delegating_scope={"deploy.plan"})
    assert verdict.decision == Decision.DENY
    assert verdict.rule_id == "AGT-TOOL-001"


def test_and_gate_allows_tool_in_both_role_and_user_scope() -> None:
    request = Request("tool", "a1", "deploy.plan")
    verdict = evaluate(DELEGATED_POLICY, request, delegating_scope={"deploy.plan"})
    assert verdict.decision == Decision.ALLOW


def test_delegated_agent_without_scope_denies_everything() -> None:
    verdict = evaluate(DELEGATED_POLICY, Request("tool", "a1", "deploy.plan"), delegating_scope=None)
    assert verdict.decision == Decision.DENY


def test_egress_allow_suffix_match() -> None:
    verdict = evaluate(READ_ONLY_POLICY, Request("egress", "a1", "logs.internal.example.com"))
    assert verdict.decision == Decision.ALLOW


def test_egress_deny_not_allowlisted() -> None:
    verdict = evaluate(READ_ONLY_POLICY, Request("egress", "a1", "evil.example.net"))
    assert verdict.decision == Decision.DENY
    assert verdict.rule_id == "AGT-EGRESS-001"


def test_egress_malformed_default_denies() -> None:
    policy = {**READ_ONLY_POLICY, "egress": {"default": "allow", "allowlist": []}}
    verdict = evaluate(policy, Request("egress", "a1", "anything.example.com"))
    assert verdict.decision == Decision.DENY
    assert verdict.rule_id == "AGT-EGRESS-000"


def test_egress_wildcard_entry_denies() -> None:
    policy = {**READ_ONLY_POLICY, "egress": {"default": "deny", "allowlist": ["*.example.com"]}}
    verdict = evaluate(policy, Request("egress", "a1", "foo.example.com"))
    assert verdict.decision == Decision.DENY
    assert verdict.rule_id == "AGT-EGRESS-000"


def test_egress_bare_dot_entry_denies() -> None:
    policy = {**READ_ONLY_POLICY, "egress": {"default": "deny", "allowlist": ["."]}}
    verdict = evaluate(policy, Request("egress", "a1", "foo.example.com"))
    assert verdict.decision == Decision.DENY
    assert verdict.rule_id == "AGT-EGRESS-000"


def test_zone_allow_home() -> None:
    verdict = evaluate(READ_ONLY_POLICY, Request("zone", "a1", "agent-restricted"))
    assert verdict.decision == Decision.ALLOW


def test_zone_allow_reachable() -> None:
    policy = {**READ_ONLY_POLICY, "zones": {"home": "agent-restricted", "reachable": ["deploy-staging"]}}
    verdict = evaluate(policy, Request("zone", "a1", "deploy-staging"))
    assert verdict.decision == Decision.ALLOW


def test_zone_deny_unlisted() -> None:
    verdict = evaluate(READ_ONLY_POLICY, Request("zone", "a1", "corp-prod"))
    assert verdict.decision == Decision.DENY
    assert verdict.rule_id == "AGT-ZONE-001"


def test_unknown_request_kind_denies() -> None:
    verdict = evaluate(READ_ONLY_POLICY, Request("unknown", "a1", "x"))
    assert verdict.decision == Decision.DENY
    assert verdict.rule_id == "AGT-CORE-001"
