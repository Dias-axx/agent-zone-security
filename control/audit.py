"""Append-only audit trail. Every policy evaluation is recorded, allows included.

Backend is pluggable via AuditSink: JSONLFileSink (the v1 default, and the only
sink AuditLog used before this module supported more than one) plus optional
extra sinks. One record per line keeps the JSONL schema forwarder-friendly, and
SyslogSink exists so a SIEM (QRadar, Sentinel, or any syslog-speaking collector)
can receive every record in real time instead of by tailing a file — without
changing the record schema, per the original design intent.

Single-process caveat: JSONLFileSink appends to a local file and SyslogSink
sends to whatever syslog endpoint it's configured with; neither one, by itself,
gives you a durable trail if the process's disk or network is what fails. Run
with both configured (local file for local forensics, syslog for off-host
durability) rather than relying on either alone.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol


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


class AuditSink(Protocol):
    """A destination for audit records. Implementations must not raise on a
    single bad record — a forwarder outage must not take down the caller
    evaluating policy, only the destination named in the failure."""

    def write(self, record: AuditRecord) -> None: ...


class JSONLFileSink:
    """Appends one JSON object per line to a local file. This is the v1
    default and, on its own, the same single-process/single-file trail the
    project originally shipped with."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def write(self, record: AuditRecord) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(record)) + "\n")


class SyslogSink:
    """Forwards each record as a single JSON-payload syslog message. Uses only
    the standard library (logging.handlers.SysLogHandler) — no SIEM client
    dependency. Point address at your collector (e.g. ("localhost", 514) for
    a local rsyslog relay, or a remote QRadar/Sentinel-facing syslog endpoint).

    A send failure (collector unreachable) raises from write(); callers that
    want audit evaluation to continue even when the forwarder is down should
    catch that at the call site or wrap this sink accordingly — silently
    swallowing it here would hide a real outage from whoever depends on the
    forwarded stream.
    """

    def __init__(
        self,
        address: tuple[str, int] = ("localhost", 514),
        facility: int = logging.handlers.SysLogHandler.LOG_LOCAL0,
    ) -> None:
        self._logger = logging.getLogger(f"agent_zone_control.audit.syslog.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        handler = logging.handlers.SysLogHandler(address=address, facility=facility)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def write(self, record: AuditRecord) -> None:
        self._logger.info(json.dumps(asdict(record)))


class AuditLog:
    """Dispatches every record to a JSONLFileSink at `path` plus any
    `extra_sinks` supplied. Backward compatible with the v1 constructor
    (`AuditLog(path)`): adding `extra_sinks` is additive, the local JSONL
    trail is always kept.
    """

    def __init__(self, path: Path, extra_sinks: tuple[AuditSink, ...] = ()) -> None:
        self._file_sink = JSONLFileSink(path)
        self._sinks: tuple[AuditSink, ...] = (self._file_sink, *extra_sinks)

    @property
    def path(self) -> Path:
        return self._file_sink.path

    def record(self, record: AuditRecord) -> None:
        for sink in self._sinks:
            sink.write(record)
