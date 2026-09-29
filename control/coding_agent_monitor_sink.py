"""Optional AuditSink that forwards each record to a running Coding-Agent-Monitor
instance (https://github.com/Dias-axx/coding-agent-monitor), so its dashboard
shows policy-engine allow/deny/confirm lines as a live view next to normal
agent-session logs — in addition to, never instead of, this repo's own
JSONL/Syslog audit trail (control/audit.py's JSONLFileSink/SyslogSink).

Coding-Agent-Monitor is explicitly a best-effort, in-memory, non-durable tool
by its own design (its README: "if the monitor is down or unreachable, [...]
fall back to running normally [...] instead of failing the agent"). This sink
matches that stance rather than fighting it: a forwarding failure is logged to
stderr and swallowed, never raised — it must never block or fail the policy
evaluation it is attached to, and it must never become the source of truth for
anything. Uses only the standard library (urllib.request); no extra
dependency for two small JSON POSTs.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

from control.audit import AuditRecord

DEFAULT_TIMEOUT_SECONDS = 2.0


class CodingAgentMonitorSink:
    """Registers one Coding-Agent-Monitor session per agent_id on first sight
    and appends a log line to it on every subsequent write.

    Coding-Agent-Monitor's own `register()` resets an existing session's log
    history if called again with the same id (see its store.js) — so this
    sink tracks which agent_ids it has already registered within this
    process and registers each one exactly once, instead of on every write.
    """

    def __init__(self, base_url: str, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._known_agent_ids: set[str] = set()

    def _post(self, path: str, payload: dict[str, object]) -> None:
        request = urllib.request.Request(
            f"{self._base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self._timeout_seconds):
            pass

    def _ensure_registered(self, agent_id: str, role: str) -> None:
        if agent_id in self._known_agent_ids:
            return
        self._post("/api/agents", {"id": agent_id, "name": f"{agent_id} ({role})"})
        self._known_agent_ids.add(agent_id)

    def write(self, record: AuditRecord) -> None:
        try:
            self._ensure_registered(record.agent_id, record.role)
            stream = "stderr" if record.decision == "deny" else "stdout"
            text = f"[{record.rule_id}] {record.kind} {record.target} -> {record.decision}: {record.reason}"
            self._post(f"/api/agents/{record.agent_id}/log", {"text": text, "stream": stream})
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            print(
                f"CodingAgentMonitorSink: failed to forward record for {record.agent_id}: {exc}",
                file=sys.stderr,
            )
