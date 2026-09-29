from __future__ import annotations

from pathlib import Path

from control.activity_reader import filter_records, read_records, summarize_by_agent
from control.audit import AuditLog, AuditRecord


def _record(
    agent_id: str = "agt-1",
    role: str = "read-only-agent",
    kind: str = "tool",
    target: str = "log.read",
    decision: str = "allow",
    rule_id: str = "AGT-TOOL-OK",
    timestamp: str = "2026-09-20T10:00:00+00:00",
) -> AuditRecord:
    return AuditRecord(
        timestamp=timestamp,
        agent_id=agent_id,
        role=role,
        delegated_by=None,
        kind=kind,
        target=target,
        scope=[target],
        decision=decision,
        rule_id=rule_id,
        reason="test",
        session_id="s1",
    )


def test_read_records_returns_empty_for_missing_file(tmp_path: Path) -> None:
    assert read_records(tmp_path / "does-not-exist.jsonl") == []


def test_read_records_skips_malformed_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text('{"agent_id": "agt-1"}\nnot json\n{"agent_id": "agt-2"}\n', encoding="utf-8")

    records = read_records(path)

    assert [r["agent_id"] for r in records] == ["agt-1", "agt-2"]


def test_read_records_reads_real_auditlog_output(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record(_record(agent_id="agt-1"))
    log.record(_record(agent_id="agt-2", decision="deny"))

    records = read_records(path)

    assert len(records) == 2
    assert records[1]["decision"] == "deny"


def test_filter_records_by_agent_id() -> None:
    records = [{"agent_id": "agt-1"}, {"agent_id": "agt-2"}]
    assert filter_records(records, agent_id="agt-2") == [{"agent_id": "agt-2"}]


def test_filter_records_by_decision_and_kind() -> None:
    records = [
        {"decision": "allow", "kind": "tool"},
        {"decision": "deny", "kind": "tool"},
        {"decision": "deny", "kind": "zone"},
    ]
    assert filter_records(records, decision="deny", kind="zone") == [{"decision": "deny", "kind": "zone"}]


def test_filter_records_by_since() -> None:
    records = [
        {"timestamp": "2026-09-20T10:00:00+00:00"},
        {"timestamp": "2026-09-20T12:00:00+00:00"},
    ]
    assert filter_records(records, since="2026-09-20T11:00:00+00:00") == [
        {"timestamp": "2026-09-20T12:00:00+00:00"}
    ]


def test_filter_records_with_no_filters_returns_all() -> None:
    records = [{"agent_id": "agt-1"}, {"agent_id": "agt-2"}]
    assert filter_records(records) == records


def test_summarize_by_agent_counts_decisions_and_picks_latest() -> None:
    records = [
        {
            "agent_id": "agt-1",
            "role": "read-only-agent",
            "decision": "allow",
            "kind": "tool",
            "target": "log.read",
            "timestamp": "2026-09-20T10:00:00+00:00",
        },
        {
            "agent_id": "agt-1",
            "role": "read-only-agent",
            "decision": "deny",
            "kind": "egress",
            "target": "evil.example.com",
            "timestamp": "2026-09-20T11:00:00+00:00",
        },
        {
            "agent_id": "agt-2",
            "role": "deploy-agent",
            "decision": "allow",
            "kind": "tool",
            "target": "deploy.run",
            "timestamp": "2026-09-20T09:00:00+00:00",
        },
    ]

    summary = summarize_by_agent(records)

    assert [s["agent_id"] for s in summary] == ["agt-1", "agt-2"]
    agt1 = summary[0]
    assert agt1["total_events"] == 2
    assert agt1["decisions"] == {"allow": 1, "deny": 1}
    assert agt1["last_seen"] == "2026-09-20T11:00:00+00:00"
    assert agt1["last_decision"] == "deny"
    assert agt1["last_target"] == "evil.example.com"


def test_summarize_by_agent_empty_input() -> None:
    assert summarize_by_agent([]) == []
