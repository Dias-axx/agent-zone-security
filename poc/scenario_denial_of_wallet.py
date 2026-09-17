"""PoC: denial-of-wallet containment. A read-only agent issues a high volume of
tool calls, each individually within its own scope and each individually allowed
by the policy engine. Volume-based detection (AGT-WALLET-001) flags the pattern
that per-call policy evaluation alone cannot see, and the response chain
escalates per the role's own response.on_violation setting.
"""

from __future__ import annotations

import sys

from agents.log_reader import build_agent
from control.policy_engine import Decision, Request, evaluate
from control.response import escalate
from detection.engine import evaluate_event, load_rules
from detection.normalise import NormalisedEvent

CALL_VOLUME = 25


def main() -> int:
    agent = build_agent()
    rules = load_rules()
    triggered_ids: set[str] = set()

    for call_count in range(1, CALL_VOLUME + 1):
        verdict = evaluate(agent.policy, Request(kind="tool", agent_id=agent.agent_id, target="log.read"))
        if verdict.decision != Decision.ALLOW:
            print("FAIL: expected in-scope tool call to be allowed", file=sys.stderr)
            return 1

        detection_event = NormalisedEvent(
            source="otel", agent_id=agent.agent_id, kind="tool", target="log.read", verdict="allow", raw={}
        )
        for rule in evaluate_event(detection_event, rules, counters={"call_count": call_count}):
            triggered_ids.add(rule.rule_id)

    print(f"Issued {CALL_VOLUME} allowed tool calls; detection rules triggered: {sorted(triggered_ids)}")

    if "AGT-WALLET-001" not in triggered_ids:
        print("FAIL: expected AGT-WALLET-001 to fire on excessive call volume", file=sys.stderr)
        return 1

    on_violation = agent.policy.get("response", {}).get("on_violation", "alert")
    response_events = escalate(agent.agent_id, on_violation, dry_run=True)
    for response_event in response_events:
        action = response_event.action.value.upper()
        print(f"[RESPONSE:{action}] dry_run={response_event.dry_run} {response_event.detail}")

    print("PASS: denial-of-wallet pattern detected and response chain executed (dry-run)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
