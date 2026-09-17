from __future__ import annotations

import pytest

from detection.engine import RuleEvalError, evaluate_event, evaluate_logic, load_rules
from detection.normalise import NormalisedEvent


def test_rules_load_from_repo() -> None:
    rules = load_rules()
    rule_ids = {rule.rule_id for rule in rules}
    assert {"AGT-ZONE-001", "AGT-EGRESS-001", "AGT-SECRET-001", "AGT-WALLET-001"} <= rule_ids


def test_evaluate_logic_boolean_and() -> None:
    assert evaluate_logic("a == 1 and b == 2", {"a": 1, "b": 2}) is True
    assert evaluate_logic("a == 1 and b == 2", {"a": 1, "b": 3}) is False


def test_evaluate_logic_rejects_unknown_identifier() -> None:
    with pytest.raises(RuleEvalError):
        evaluate_logic("nonexistent == 1", {})


def test_evaluate_logic_rejects_unsupported_node() -> None:
    with pytest.raises(RuleEvalError):
        evaluate_logic("__import__('os')", {})


def test_zone_denial_triggers_rule() -> None:
    rules = load_rules()
    event = NormalisedEvent(
        source="hubble", agent_id="a1", kind="zone", target="corp-prod", verdict="deny", raw={}
    )
    triggered = {rule.rule_id for rule in evaluate_event(event, rules)}
    assert "AGT-ZONE-001" in triggered


def test_wallet_rule_fires_above_threshold() -> None:
    rules = load_rules()
    event = NormalisedEvent(
        source="otel", agent_id="a1", kind="tool", target="log.read", verdict="allow", raw={}
    )
    below = evaluate_event(event, rules, counters={"call_count": 5})
    above = evaluate_event(event, rules, counters={"call_count": 25})
    assert "AGT-WALLET-001" not in {r.rule_id for r in below}
    assert "AGT-WALLET-001" in {r.rule_id for r in above}
