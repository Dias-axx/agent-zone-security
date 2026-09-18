"""PoC: egress containment. A read-only agent may reach its allowlisted log store,
but a scripted attempt to reach an arbitrary external host is denied by
default-deny egress with an explicit allowlist.
"""

from __future__ import annotations

import sys

from agents.log_reader import build_agent
from control.policy_engine import Decision, Request, evaluate


def main() -> int:
    agent = build_agent()

    allowed_target = "internal-logs.example.com"
    denied_target = "evil.example.net"
    allowed = evaluate(agent.policy, Request(kind="egress", agent_id=agent.agent_id, target=allowed_target))
    denied = evaluate(agent.policy, Request(kind="egress", agent_id=agent.agent_id, target=denied_target))

    print(f"[{allowed.decision.value.upper()}] {allowed.rule_id}: {allowed.reason}")
    print(f"[{denied.decision.value.upper()}] {denied.rule_id}: {denied.reason}")

    if allowed.decision != Decision.ALLOW:
        print("FAIL: expected allowlisted egress target to be allowed", file=sys.stderr)
        return 1
    if denied.decision != Decision.DENY or denied.rule_id != "AGT-EGRESS-001":
        print("FAIL: expected non-allowlisted target denied with AGT-EGRESS-001", file=sys.stderr)
        return 1

    print("PASS: default-deny egress with explicit allowlist enforced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
