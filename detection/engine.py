"""Detection rule engine. Rules are declarative YAML with a `logic` expression
string; this module is the only place that interprets logic. Evaluation uses a
restricted AST walk (boolean ops, comparisons, names, constants, lists only) —
never Python's eval/exec — so a rule file cannot execute arbitrary code.
"""

from __future__ import annotations

import ast
import operator
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from detection.normalise import NormalisedEvent

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "detection" / "rules"

_CMPOPS: dict[type[ast.cmpop], Callable[[Any, Any], bool]] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}


class RuleEvalError(ValueError):
    """Raised when a rule's logic expression uses a construct outside the
    permitted subset, or references an unknown identifier."""


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    mitre_atlas: str
    owasp_asi: str
    severity: str
    logic: str


def _safe_eval(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body, context)
    if isinstance(node, ast.BoolOp):
        is_and = isinstance(node.op, ast.And)
        is_or = isinstance(node.op, ast.Or)
        if not (is_and or is_or):
            raise RuleEvalError(f"boolean operator {type(node.op).__name__} not permitted")
        # Short-circuit like real and/or: once the outcome is decided, later operands
        # are never evaluated. This matters because context is deliberately partial
        # (e.g. `call_count` only exists for tool events) — a rule like
        # `kind == 'zone' or call_count > 20` must not raise just because a
        # non-tool event doesn't carry `call_count`.
        result: Any = _safe_eval(node.values[0], context)
        for value_node in node.values[1:]:
            if is_and and not result:
                return result
            if is_or and result:
                return result
            result = _safe_eval(value_node, context)
        return result
    if isinstance(node, ast.Compare):
        left = _safe_eval(node.left, context)
        for op_node, comparator in zip(node.ops, node.comparators, strict=True):
            op = _CMPOPS.get(type(op_node))
            if op is None:
                raise RuleEvalError(f"comparator {type(op_node).__name__} not permitted")
            right = _safe_eval(comparator, context)
            if not op(left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.Name):
        if node.id not in context:
            raise RuleEvalError(f"unknown identifier '{node.id}'")
        return context[node.id]
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List):
        return [_safe_eval(elt, context) for elt in node.elts]
    raise RuleEvalError(f"unsupported expression node {type(node).__name__}")


@cache
def _parse(logic: str) -> ast.Expression:
    # The set of distinct logic strings is bounded by the rule files on disk, so an
    # unbounded cache here is safe and avoids re-parsing the same expression for
    # every event on a hot stream-consumption path.
    return ast.parse(logic, mode="eval")


def evaluate_logic(logic: str, context: dict[str, Any]) -> bool:
    tree = _parse(logic)
    return bool(_safe_eval(tree, context))


def load_rules() -> list[DetectionRule]:
    rules = []
    for path in sorted(RULES_DIR.glob("*.yaml")):
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        rules.append(
            DetectionRule(
                rule_id=data["rule_id"],
                name=data["name"],
                mitre_atlas=data.get("mitre_atlas", ""),
                owasp_asi=data.get("owasp_asi", ""),
                severity=data.get("severity", "medium"),
                logic=data["logic"],
            )
        )
    return rules


def evaluate_event(
    event: NormalisedEvent, rules: list[DetectionRule], counters: dict[str, int] | None = None
) -> list[DetectionRule]:
    context: dict[str, Any] = {
        "source": event.source,
        "agent_id": event.agent_id,
        "kind": event.kind,
        "target": event.target,
        "verdict": event.verdict,
        **(counters or {}),
    }
    triggered = []
    for rule in rules:
        try:
            if evaluate_logic(rule.logic, context):
                triggered.append(rule)
        except RuleEvalError:
            # A rule referencing a field this event does not carry simply does not
            # match it — that is not a system error and must not raise or deny.
            continue
    return triggered
