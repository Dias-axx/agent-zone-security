from __future__ import annotations

import pytest

from control.response import ResponseAction, escalate


def test_alert_only_chain() -> None:
    events = escalate("a1", "alert", dry_run=True)
    assert [e.action for e in events] == [ResponseAction.ALERT]


def test_terminate_chain_preserves_before_terminate() -> None:
    events = escalate("a1", "terminate", dry_run=True)
    actions = [e.action for e in events]
    assert actions == [
        ResponseAction.ALERT,
        ResponseAction.ISOLATE,
        ResponseAction.REVOKE,
        ResponseAction.PRESERVE,
        ResponseAction.TERMINATE,
    ]
    assert actions.index(ResponseAction.PRESERVE) < actions.index(ResponseAction.TERMINATE)
    assert actions.index(ResponseAction.ISOLATE) < actions.index(ResponseAction.TERMINATE)


def test_all_events_are_dry_run_by_default_chain() -> None:
    events = escalate("a1", "revoke", dry_run=True)
    assert all(e.dry_run for e in events)


def test_unknown_on_violation_raises() -> None:
    with pytest.raises(ValueError):
        escalate("a1", "nonsense", dry_run=True)
