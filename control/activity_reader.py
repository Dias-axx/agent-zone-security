"""Pure read/filter/aggregate functions over the JSONL audit log written by
control.audit.AuditLog / JSONLFileSink. No I/O side effects beyond reading
the file, so these are unit-testable and reusable outside control.activity_api
(a script, a notebook, another sink consumer).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def read_records(path: Path) -> list[dict[str, Any]]:
    """Reads every JSON line from `path`, skipping lines that are not valid
    JSON. AuditLog.record() writes one complete JSON-terminated line per
    write() call, so a malformed line only happens if the reader catches a
    concurrent writer mid-append (the last line) or the file was hand-edited
    — either way, skipping it rather than raising keeps the dashboard usable.
    """
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def filter_records(
    records: list[dict[str, Any]],
    agent_id: str | None = None,
    decision: str | None = None,
    kind: str | None = None,
    since: str | None = None,
) -> list[dict[str, Any]]:
    """`since` compares against the ISO-8601 UTC `timestamp` field
    lexically — safe because control.audit.now_iso() always produces
    fixed-format UTC timestamps, which sort the same lexically and
    chronologically.
    """
    filtered = records
    if agent_id:
        filtered = [r for r in filtered if r.get("agent_id") == agent_id]
    if decision:
        filtered = [r for r in filtered if r.get("decision") == decision]
    if kind:
        filtered = [r for r in filtered if r.get("kind") == kind]
    if since:
        filtered = [r for r in filtered if r.get("timestamp", "") >= since]
    return filtered


def summarize_by_agent(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per agent_id: role, decision counts, and the most recent
    record's timestamp/kind/target/decision as an at-a-glance "last activity".
    Sorted by last_seen descending (most recently active agent first).
    """
    by_agent: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        by_agent.setdefault(r.get("agent_id", "unknown"), []).append(r)

    summary: list[dict[str, Any]] = []
    for agent_id, agent_records in by_agent.items():
        agent_records.sort(key=lambda r: r.get("timestamp", ""))
        last = agent_records[-1]
        decisions = Counter(r.get("decision", "unknown") for r in agent_records)
        summary.append(
            {
                "agent_id": agent_id,
                "role": last.get("role"),
                "total_events": len(agent_records),
                "decisions": dict(decisions),
                "last_seen": last.get("timestamp"),
                "last_kind": last.get("kind"),
                "last_target": last.get("target"),
                "last_decision": last.get("decision"),
            }
        )
    summary.sort(key=lambda s: s["last_seen"] or "", reverse=True)
    return summary
