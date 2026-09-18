"""Append-only audit trail. Every policy evaluation is recorded, allows included.

Backend is JSONL for v1. One record per line keeps the schema forwarder-friendly —
a SIEM shipper (QRadar, Sentinel) can tail the file without any format change.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class AuditRecord:
    timestamp: str
    agent_id: str
    role: str
    delegated_by: str | None
    kind: str
    target: str
    scope: list[str]
    decision: str
    rule_id: str
    reason: str
    session_id: str


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def record(self, record: AuditRecord) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(record)) + "\n")
