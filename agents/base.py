"""Deterministic mock agent: replays a scripted action list against the policy
engine. No network access, no model calls — so PoC scenarios reproduce identically
in CI at zero cost.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from control.audit import AuditLog, AuditRecord, now_iso
from control.policy_engine import Request, Verdict, evaluate

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ScriptedAction:
    kind: str  # "tool" | "egress" | "zone"
    target: str
    session_id: str = "demo-session"


class MockAgent:
    def __init__(
        self,
        agent_id: str,
        role: str,
        policy_path: str,
        delegated_by: str | None = None,
        delegating_scope: set[str] | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.role = role
        self.delegated_by = delegated_by
        self.delegating_scope = delegating_scope
        with (REPO_ROOT / policy_path).open(encoding="utf-8") as fh:
            self.policy: dict[str, Any] = yaml.safe_load(fh)
        self.audit_log = audit_log

    def run(self, actions: list[ScriptedAction]) -> list[Verdict]:
        verdicts: list[Verdict] = []
        for action in actions:
            request = Request(
                kind=action.kind, agent_id=self.agent_id, target=action.target, session_id=action.session_id
            )
            verdict = evaluate(self.policy, request, delegating_scope=self.delegating_scope)
            verdicts.append(verdict)
            if self.audit_log is not None:
                scope = (
                    sorted(self.policy.get("capabilities", {}).get("tools", []))
                    if action.kind == "tool"
                    else []
                )
                self.audit_log.record(
                    AuditRecord(
                        timestamp=now_iso(),
                        agent_id=self.agent_id,
                        role=self.role,
                        delegated_by=self.delegated_by,
                        kind=action.kind,
                        target=action.target,
                        scope=scope,
                        decision=verdict.decision.value,
                        rule_id=verdict.rule_id,
                        reason=verdict.reason,
                        session_id=action.session_id,
                    )
                )
        return verdicts
