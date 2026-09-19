"""Reads normalised events as NDJSON from stdin (one JSON object per line, in
the shape go/internal/flow.Normalized emits) and evaluates each one against
detection/rules/*.yaml. This is the Python side of the pipeline described in
go/cmd/flow-consumer/main.go's header comment:

    hubble observe -o json | flow-consumer | python -m detection.consume_stream

Rule evaluation stays in Python per the project's language split (see
handover spec, "Language policy"); the Go binary only parses Hubble's own
output into the common event schema.

Run as: python -m detection.consume_stream
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import Any

from detection.engine import DetectionRule, evaluate_event, load_rules
from detection.normalise import NormalisedEvent


def parse_line(line: str) -> NormalisedEvent:
    payload: dict[str, Any] = json.loads(line)
    return NormalisedEvent(
        source=payload.get("source", "unknown"),
        agent_id=payload.get("agent_id", "unknown"),
        kind=payload.get("kind", "unknown"),
        target=payload.get("target", "unknown"),
        verdict=payload.get("verdict", "unknown"),
        raw=payload.get("raw", {}),
    )


def consume(lines: Any, rules: list[DetectionRule]) -> int:
    triggered_count = 0
    # Running per-agent tool-call total for this stream. detection/rules/wallet-abuse.yaml
    # ("call_count > 20") needs this counter in the evaluation context; without it the
    # rule can never match a real event (an unknown identifier makes rule evaluation a
    # no-match, not an error - see detection/engine.py), so AGT-WALLET-001 would never
    # fire outside of a test that injects call_count by hand.
    tool_call_counts: dict[str, int] = defaultdict(int)
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = parse_line(line)
        except json.JSONDecodeError as exc:
            print(f"consume_stream: skipping unparsable line: {exc}", file=sys.stderr)
            continue

        counters: dict[str, int] = {}
        if event.kind == "tool":
            tool_call_counts[event.agent_id] += 1
            counters["call_count"] = tool_call_counts[event.agent_id]

        for rule in evaluate_event(event, rules, counters=counters):
            triggered_count += 1
            print(
                f"[{rule.rule_id}] {rule.name} "
                f"(agent={event.agent_id} target={event.target} verdict={event.verdict})"
            )
    return triggered_count


def main() -> int:
    rules = load_rules()
    triggered_count = consume(sys.stdin, rules)
    print(f"consume_stream: {triggered_count} rule match(es) over the input stream", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
