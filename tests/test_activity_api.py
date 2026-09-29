from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from control.activity_api import make_handler
from control.audit import AuditLog, AuditRecord


def _record(agent_id: str, decision: str, kind: str = "tool", target: str = "log.read") -> AuditRecord:
    from control.audit import now_iso

    return AuditRecord(
        timestamp=now_iso(),
        agent_id=agent_id,
        role="read-only-agent",
        delegated_by=None,
        kind=kind,
        target=target,
        scope=[target],
        decision=decision,
        rule_id="AGT-TEST",
        reason="test",
        session_id="s1",
    )


@pytest.fixture
def running_server(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    """Starts a real activity_api server on an ephemeral localhost port,
    backed by a real audit log file, so tests exercise the actual HTTP
    handler rather than calling its methods directly."""
    audit_path = tmp_path / "audit.jsonl"
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(audit_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}", audit_path
    finally:
        server.shutdown()
        thread.join()


def _get_json(url: str) -> list[dict[str, Any]]:
    with urllib.request.urlopen(url) as response:  # noqa: S310 (test-only, localhost)
        result: list[dict[str, Any]] = json.loads(response.read())
        return result


def test_dashboard_root_serves_html(running_server: tuple[str, Path]) -> None:
    base_url, _ = running_server
    with urllib.request.urlopen(base_url + "/") as response:  # noqa: S310
        assert response.status == 200
        assert response.headers["Content-Type"].startswith("text/html")
        body = response.read().decode("utf-8")
    assert "<title>Agent Activity</title>" in body


def test_activity_endpoint_returns_empty_list_for_no_log(running_server: tuple[str, Path]) -> None:
    base_url, _ = running_server
    assert _get_json(base_url + "/api/activity") == []


def test_activity_endpoint_returns_real_recorded_events(running_server: tuple[str, Path]) -> None:
    base_url, audit_path = running_server
    log = AuditLog(audit_path)
    log.record(_record("agt-1", "allow"))
    log.record(_record("agt-2", "deny", kind="egress", target="evil.example.com"))

    events = _get_json(base_url + "/api/activity")

    assert isinstance(events, list)
    assert len(events) == 2
    agent_ids = {e["agent_id"] for e in events}
    assert agent_ids == {"agt-1", "agt-2"}


def test_activity_endpoint_filters_by_query_params(running_server: tuple[str, Path]) -> None:
    base_url, audit_path = running_server
    log = AuditLog(audit_path)
    log.record(_record("agt-1", "allow"))
    log.record(_record("agt-2", "deny", kind="egress", target="evil.example.com"))

    events = _get_json(base_url + "/api/activity?decision=deny")

    assert len(events) == 1
    assert events[0]["agent_id"] == "agt-2"
    assert events[0]["decision"] == "deny"


def test_agents_endpoint_summarizes_real_recorded_events(running_server: tuple[str, Path]) -> None:
    base_url, audit_path = running_server
    log = AuditLog(audit_path)
    log.record(_record("agt-1", "allow"))
    log.record(_record("agt-1", "deny", kind="egress", target="evil.example.com"))

    summary = _get_json(base_url + "/api/agents")

    assert isinstance(summary, list)
    assert len(summary) == 1
    assert summary[0]["agent_id"] == "agt-1"
    assert summary[0]["total_events"] == 2
    assert summary[0]["decisions"] == {"allow": 1, "deny": 1}


def test_unknown_path_returns_404(running_server: tuple[str, Path]) -> None:
    base_url, _ = running_server
    try:
        urllib.request.urlopen(base_url + "/does-not-exist")  # noqa: S310
        pytest.fail("expected an HTTPError")
    except urllib.error.HTTPError as e:
        assert e.code == 404
