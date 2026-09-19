from __future__ import annotations

import json
from pathlib import Path

from control.audit import AuditLog, AuditRecord, JSONLFileSink, now_iso


def _record(agent_id: str = "agt-1") -> AuditRecord:
    return AuditRecord(
        timestamp=now_iso(),
        agent_id=agent_id,
        role="read-only-agent",
        delegated_by=None,
        kind="tool",
        target="log.read",
        scope=["log.read"],
        decision="allow",
        rule_id="AGT-TOOL-OK",
        reason="tool permitted",
        session_id="s1",
    )


def test_jsonl_file_sink_appends_one_line_per_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JSONLFileSink(path)
    sink.write(_record())
    sink.write(_record(agent_id="agt-2"))

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["agent_id"] == "agt-1"
    assert json.loads(lines[1])["agent_id"] == "agt-2"


def test_audit_log_writes_to_file_sink_by_default(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record(_record())
    assert len(log.path.read_text().splitlines()) == 1


def test_audit_log_dispatches_to_extra_sinks(tmp_path: Path) -> None:
    captured: list[AuditRecord] = []

    class FakeSink:
        def write(self, record: AuditRecord) -> None:
            captured.append(record)

    log = AuditLog(tmp_path / "audit.jsonl", extra_sinks=(FakeSink(),))
    record = _record()
    log.record(record)

    assert captured == [record]
    assert len(log.path.read_text().splitlines()) == 1
