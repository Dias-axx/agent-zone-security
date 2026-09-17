"""PoC: zone containment. An agent may operate in its home zone, but a scripted
attempt to cross into an unauthorised zone is denied with AGT-ZONE-001.
"""

from __future__ import annotations

import sys

from agents.log_reader import build_agent
from control.policy_engine import Decision, Request, evaluate


def main() -> int:
    agent = build_agent()

    home = evaluate(agent.policy, Request(kind="zone", agent_id=agent.agent_id, target="agent-restricted"))
    cross = evaluate(agent.policy, Request(kind="zone", agent_id=agent.agent_id, target="corp-prod"))

    print(f"[{home.decision.value.upper()}] {home.rule_id}: {home.reason}")
    print(f"[{cross.decision.value.upper()}] {cross.rule_id}: {cross.reason}")

    if home.decision != Decision.ALLOW:
        print("FAIL: expected home zone to be allowed", file=sys.stderr)
        return 1
    if cross.decision != Decision.DENY or cross.rule_id != "AGT-ZONE-001":
        print("FAIL: expected cross-zone traversal to be denied with AGT-ZONE-001", file=sys.stderr)
        return 1

    print("PASS: zone enforcement contains the agent to its home zone")
    return 0


if __name__ == "__main__":
    sys.exit(main())
