from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

from control.audit import AuditRecord, now_iso
from control.coding_agent_monitor_sink import CodingAgentMonitorSink

FakeUrlopen = Callable[..., Any]


def _record(**overrides: object) -> AuditRecord:
    base: dict[str, object] = {
        "timestamp": now_iso(),
        "agent_id": "agt-1",
        "role": "read-only-agent",
        "delegated_by": None,
        "kind": "tool",
        "target": "log.read",
        "scope": ["log.read"],
        "decision": "allow",
        "rule_id": "AGT-TOOL-OK",
        "reason": "tool permitted",
        "session_id": "s1",
    }
    base.update(overrides)
    return AuditRecord(**base)  # type: ignore[arg-type]


def _fake_urlopen(calls: list[tuple[str, dict[str, Any]]]) -> FakeUrlopen:
    def fake(request: urllib.request.Request, timeout: float | None = None) -> MagicMock:
        assert isinstance(request.data, bytes)
        calls.append((request.full_url, json.loads(request.data)))
        return MagicMock(__enter__=lambda self: self, __exit__=lambda self, *a: None)

    return fake


def test_first_write_registers_then_logs() -> None:
    sink = CodingAgentMonitorSink("http://localhost:8787")
    calls: list[tuple[str, dict[str, Any]]] = []

    with patch("control.coding_agent_monitor_sink.urllib.request.urlopen", side_effect=_fake_urlopen(calls)):
        sink.write(_record())

    assert len(calls) == 2
    assert calls[0] == (
        "http://localhost:8787/api/agents",
        {"id": "agt-1", "name": "agt-1 (read-only-agent)"},
    )
    url, payload = calls[1]
    assert url == "http://localhost:8787/api/agents/agt-1/log"
    assert payload["stream"] == "stdout"
    assert "AGT-TOOL-OK" in payload["text"]


def test_second_write_for_same_agent_does_not_re_register() -> None:
    sink = CodingAgentMonitorSink("http://localhost:8787")
    calls: list[tuple[str, dict[str, Any]]] = []

    with patch("control.coding_agent_monitor_sink.urllib.request.urlopen", side_effect=_fake_urlopen(calls)):
        sink.write(_record())
        sink.write(_record())

    register_calls = [c for c in calls if c[0].endswith("/api/agents")]
    log_calls = [c for c in calls if c[0].endswith("/log")]
    assert len(register_calls) == 1
    assert len(log_calls) == 2


def test_deny_decision_logs_to_stderr_stream() -> None:
    sink = CodingAgentMonitorSink("http://localhost:8787")
    calls: list[tuple[str, dict[str, Any]]] = []

    with patch("control.coding_agent_monitor_sink.urllib.request.urlopen", side_effect=_fake_urlopen(calls)):
        sink.write(_record(decision="deny", rule_id="AGT-ZONE-001"))

    log_payload = calls[1][1]
    assert log_payload["stream"] == "stderr"


def test_write_never_raises_when_registration_fails() -> None:
    sink = CodingAgentMonitorSink("http://localhost:8787")

    def raise_error(request: urllib.request.Request, timeout: float | None = None) -> None:
        raise urllib.error.URLError("connection refused")

    with patch("control.coding_agent_monitor_sink.urllib.request.urlopen", side_effect=raise_error):
        sink.write(_record())  # must not raise


def test_write_never_raises_when_log_post_fails_after_registration() -> None:
    sink = CodingAgentMonitorSink("http://localhost:8787")
    call_count = 0

    def flaky(request: urllib.request.Request, timeout: float | None = None) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return MagicMock(__enter__=lambda self: self, __exit__=lambda self, *a: None)
        raise urllib.error.URLError("timeout")

    with patch("control.coding_agent_monitor_sink.urllib.request.urlopen", side_effect=flaky):
        sink.write(_record())  # must not raise despite the log POST failing

    assert "agt-1" in sink._known_agent_ids


def test_registration_retried_after_a_failed_first_attempt() -> None:
    sink = CodingAgentMonitorSink("http://localhost:8787")
    calls: list[tuple[str, dict[str, Any]]] = []
    attempt = 0

    def fail_once_then_succeed(request: urllib.request.Request, timeout: float | None = None) -> MagicMock:
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            raise urllib.error.URLError("connection refused")
        assert isinstance(request.data, bytes)
        calls.append((request.full_url, json.loads(request.data)))
        return MagicMock(__enter__=lambda self: self, __exit__=lambda self, *a: None)

    target = "control.coding_agent_monitor_sink.urllib.request.urlopen"
    with patch(target, side_effect=fail_once_then_succeed):
        sink.write(_record())  # registration fails, swallowed
        sink.write(_record())  # registration retried since it never succeeded

    register_calls = [c for c in calls if c[0].endswith("/api/agents")]
    assert len(register_calls) == 1
