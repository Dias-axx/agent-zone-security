"""Policy decision point for tool, egress and zone requests.

Every evaluation returns a Verdict. Fail-closed is the governing rule throughout:
any malformed policy input, missing field or unrecognised request kind resolves to
DENY, never to a permissive fallback.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    CONFIRM = "confirm"


@dataclass(frozen=True)
class Request:
    kind: str  # "tool" | "egress" | "zone"
    agent_id: str
    target: str
    session_id: str = ""


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str
    rule_id: str
    request: Request


def _is_delegated(policy: dict[str, Any]) -> bool:
    return bool(policy.get("identity", {}).get("type") == "delegated")


def effective_tool_scope(policy: dict[str, Any], delegating_scope: set[str] | None) -> set[str]:
    role_scope = set(policy.get("capabilities", {}).get("tools", []))
    if _is_delegated(policy):
        # AND gate: a delegated agent's effective permission is the intersection of
        # its role scope and the scope of the human it acts for. It can never exceed
        # that human. Absence of a delegating scope denies everything, it never
        # falls back to the role scope alone.
        if delegating_scope is None:
            return set()
        return role_scope & delegating_scope
    return role_scope


def evaluate_tool(
    policy: dict[str, Any], request: Request, delegating_scope: set[str] | None = None
) -> Verdict:
    scope = effective_tool_scope(policy, delegating_scope)
    confirm_set = set(policy.get("capabilities", {}).get("confirm_required", []))

    if request.target not in scope:
        return Verdict(
            Decision.DENY, f"tool '{request.target}' not in effective scope", "AGT-TOOL-001", request
        )
    if request.target in confirm_set:
        return Verdict(
            Decision.CONFIRM,
            f"tool '{request.target}' requires explicit confirmation",
            "AGT-TOOL-002",
            request,
        )
    return Verdict(Decision.ALLOW, f"tool '{request.target}' permitted", "AGT-TOOL-OK", request)


def is_valid_egress_entry(entry: str) -> bool:
    if not entry or entry == "." or "*" in entry:
        return False
    return True


def evaluate_egress(policy: dict[str, Any], request: Request) -> Verdict:
    egress = policy.get("egress", {})
    default = egress.get("default")
    if default != "deny":
        return Verdict(
            Decision.DENY,
            "egress.default must be 'deny'; malformed policy resolved as denial",
            "AGT-EGRESS-000",
            request,
        )

    allowlist = egress.get("allowlist", [])
    for entry in allowlist:
        if not is_valid_egress_entry(entry):
            return Verdict(
                Decision.DENY,
                f"malformed allowlist entry '{entry}'; policy resolved as denial",
                "AGT-EGRESS-000",
                request,
            )

    target = request.target
    for entry in allowlist:
        if entry.startswith("."):
            suffix = entry[1:]
            if target == suffix or target.endswith(entry):
                return Verdict(
                    Decision.ALLOW,
                    f"egress target '{target}' matches suffix entry '{entry}'",
                    "AGT-EGRESS-OK",
                    request,
                )
        elif target == entry:
            return Verdict(
                Decision.ALLOW,
                f"egress target '{target}' matches allowlist entry '{entry}'",
                "AGT-EGRESS-OK",
                request,
            )

    return Verdict(Decision.DENY, f"egress target '{target}' not in allowlist", "AGT-EGRESS-001", request)


def evaluate_zone(policy: dict[str, Any], request: Request) -> Verdict:
    zones = policy.get("zones", {})
    home = zones.get("home")
    reachable = set(zones.get("reachable", []))
    target = request.target

    if target == home or target in reachable:
        return Verdict(
            Decision.ALLOW, f"zone '{target}' permitted (home or reachable)", "AGT-ZONE-OK", request
        )
    return Verdict(Decision.DENY, f"zone '{target}' is neither home nor reachable", "AGT-ZONE-001", request)


def evaluate(
    policy: dict[str, Any], request: Request, delegating_scope: set[str] | None = None
) -> Verdict:
    if request.kind == "tool":
        return evaluate_tool(policy, request, delegating_scope)
    if request.kind == "egress":
        return evaluate_egress(policy, request)
    if request.kind == "zone":
        return evaluate_zone(policy, request)
    return Verdict(Decision.DENY, f"unknown request kind '{request.kind}'", "AGT-CORE-001", request)
