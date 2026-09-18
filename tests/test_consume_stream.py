from __future__ import annotations

import io

from detection.consume_stream import consume, parse_line
from detection.engine import load_rules


def test_parse_line_roundtrip() -> None:
    line = (
        '{"source":"hubble","agent_id":"agt-1","kind":"zone",'
        '"target":"corp-prod","verdict":"deny","raw":{}}'
    )
    event = parse_line(line)
    assert event.source == "hubble"
    assert event.agent_id == "agt-1"
    assert event.kind == "zone"
    assert event.target == "corp-prod"
    assert event.verdict == "deny"


def test_consume_counts_rule_matches_and_skips_bad_lines() -> None:
    rules = load_rules()
    lines = io.StringIO(
        '{"source":"hubble","agent_id":"agt-1","kind":"zone","target":"corp-prod","verdict":"deny","raw":{}}\n'
        "not json\n"
        '{"source":"hubble","agent_id":"agt-1","kind":"zone","target":"agent-restricted","verdict":"allow","raw":{}}\n'
    )
    triggered = consume(lines, rules)
    assert triggered == 1


def test_consume_empty_stream_triggers_nothing() -> None:
    assert consume(io.StringIO(""), load_rules()) == 0
