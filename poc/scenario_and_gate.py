"""PoC: AND gate for delegated identity. A delegated agent's effective permission
is the intersection of its role scope and the scope of the human it acts for.
deploy.rollback is in the role's own tool scope but not in the delegating user's
IAM scope — it must be denied even though the role alone would allow it. This is
the single most important behaviour in the repo: implementing this as an OR turns
every delegated agent into a privilege-escalation path.
"""

from __future__ import annotations

import sys

from agents.deploy_assistant import DELEGATING_USER_SCOPE, build_agent
from control.policy_engine import Decision, Request, evaluate


def main() -> int:
    agent = build_agent()

    plan = evaluate(
        agent.policy,
        Request(kind="tool", agent_id=agent.agent_id, target="deploy.plan"),
        delegating_scope=DELEGATING_USER_SCOPE,
    )
    rollback = evaluate(
        agent.policy,
        Request(kind="tool", agent_id=agent.agent_id, target="deploy.rollback"),
        delegating_scope=DELEGATING_USER_SCOPE,
    )

    print(f"[{plan.decision.value.upper()}] {plan.rule_id}: {plan.reason}")
    print(f"[{rollback.decision.value.upper()}] {rollback.rule_id}: {rollback.reason}")
    role_tools = agent.policy["capabilities"]["tools"]
    print(f"role scope includes deploy.rollback: {'deploy.rollback' in role_tools}")
    print(f"delegating user scope: {sorted(DELEGATING_USER_SCOPE)}")

    if plan.decision != Decision.ALLOW:
        print("FAIL: expected deploy.plan (in both role and user scope) to be allowed", file=sys.stderr)
        return 1
    if rollback.decision != Decision.DENY or rollback.rule_id != "AGT-TOOL-001":
        print(
            "FAIL: expected deploy.rollback (role scope only, not user scope) to be denied by the AND gate",
            file=sys.stderr,
        )
        return 1

    print("PASS: delegated agent cannot exceed the permission scope of the human it acts for")
    return 0


if __name__ == "__main__":
    sys.exit(main())
