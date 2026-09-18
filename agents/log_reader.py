"""log_reader: allow-path baseline agent. Stays inside its role for every scripted
action — used to demonstrate that a well-behaved agent is not obstructed."""

from __future__ import annotations

from agents.base import MockAgent, ScriptedAction
from control.audit import AuditLog

SCRIPT = [
    ScriptedAction(kind="tool", target="log.read"),
    ScriptedAction(kind="tool", target="log.search"),
    ScriptedAction(kind="egress", target="internal-logs.example.com"),
    ScriptedAction(kind="zone", target="agent-restricted"),
]


def build_agent(audit_log: AuditLog | None = None) -> MockAgent:
    return MockAgent(
        agent_id="agt-log-reader-001",
        role="read-only-agent",
        policy_path="policy/examples/read-only-agent.yaml",
        audit_log=audit_log,
    )
