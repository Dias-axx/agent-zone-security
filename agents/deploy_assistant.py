"""deploy_assistant: delegated role. Its policy grants deploy.rollback, but the
human it acts for (alice@example.internal) does not carry that permission in her
own IAM scope. The AND gate in control/policy_engine.py must deny it regardless of
the role's own grant — see poc/scenario_and_gate.py.
"""

from __future__ import annotations

from agents.base import MockAgent, ScriptedAction
from control.audit import AuditLog

# Simulated IAM-derived scope of the human operator this agent is delegated from.
# In a real deployment this would be looked up from the identity provider, not
# hardcoded — this constant exists only to make the mock agent deterministic.
DELEGATING_USER_SCOPE = {"deploy.plan", "deploy.stage", "deploy.apply"}

SCRIPT = [
    ScriptedAction(kind="tool", target="deploy.plan"),
    ScriptedAction(kind="tool", target="deploy.apply"),  # in role and user scope, but requires confirmation
    ScriptedAction(kind="tool", target="deploy.rollback"),  # role scope only -> denied by AND gate
]


def build_agent(audit_log: AuditLog | None = None) -> MockAgent:
    return MockAgent(
        agent_id="agt-deploy-assistant-001",
        role="deploy-agent",
        policy_path="policy/examples/deploy-agent.yaml",
        delegated_by="alice@example.internal",
        delegating_scope=DELEGATING_USER_SCOPE,
        audit_log=audit_log,
    )
