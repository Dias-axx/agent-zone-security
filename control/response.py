"""Response chain: alert -> isolate -> revoke -> preserve -> terminate.

Ordering is deliberate: isolation happens before termination so a forensic
snapshot can be taken before the pod that would otherwise carry it is deleted.
Do not reorder.

Every action is dry-run by default. In Phase 1-2 all actions are simulated and
logged only; wiring to a live cluster (isolate/terminate via NetworkPolicy/pod
delete, revoke via the token issuer) is Phase 3 scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from control.token_issuer import TokenIssuer


class ResponseAction(StrEnum):
    ALERT = "alert"
    ISOLATE = "isolate"
    REVOKE = "revoke"
    PRESERVE = "preserve"
    TERMINATE = "terminate"


# Escalation depth is keyed by the role policy's response.on_violation value.
# There is no global default: a role that does not declare on_violation must be
# treated as a validation error (see control.validate), not silently mapped here.
ESCALATION_CHAIN: dict[str, list[ResponseAction]] = {
    "alert": [ResponseAction.ALERT],
    "isolate": [ResponseAction.ALERT, ResponseAction.ISOLATE],
    "revoke": [ResponseAction.ALERT, ResponseAction.ISOLATE, ResponseAction.REVOKE],
    "terminate": [
        ResponseAction.ALERT,
        ResponseAction.ISOLATE,
        ResponseAction.REVOKE,
        ResponseAction.PRESERVE,
        ResponseAction.TERMINATE,
    ],
}


@dataclass(frozen=True)
class ResponseEvent:
    agent_id: str
    action: ResponseAction
    dry_run: bool
    detail: str


def alert(agent_id: str, detail: str, *, dry_run: bool = True) -> ResponseEvent:
    return ResponseEvent(agent_id, ResponseAction.ALERT, dry_run, detail)


def isolate(agent_id: str, *, dry_run: bool = True) -> ResponseEvent:
    detail = "apply deny-all NetworkPolicy" if not dry_run else "[dry-run] would apply deny-all NetworkPolicy"
    return ResponseEvent(agent_id, ResponseAction.ISOLATE, dry_run, detail)


def revoke(
    agent_id: str, token_id: str, issuer: TokenIssuer | None, *, dry_run: bool = True
) -> ResponseEvent:
    if not dry_run:
        # Fail closed: a live revoke with no issuer to revoke against must not be
        # allowed to fall through and report "revoke token X" as if it happened.
        if issuer is None:
            raise ValueError("revoke: issuer is required when dry_run=False")
        issuer.revoke(token_id)
        detail = f"revoke token {token_id}"
    else:
        detail = f"[dry-run] would revoke token {token_id}"
    return ResponseEvent(agent_id, ResponseAction.REVOKE, dry_run, detail)


def preserve(agent_id: str, *, dry_run: bool = True) -> ResponseEvent:
    detail = "preserve forensic snapshot" if not dry_run else "[dry-run] would preserve forensic snapshot"
    return ResponseEvent(agent_id, ResponseAction.PRESERVE, dry_run, detail)


def terminate(agent_id: str, *, dry_run: bool = True) -> ResponseEvent:
    detail = "terminate pod" if not dry_run else "[dry-run] would terminate pod"
    return ResponseEvent(agent_id, ResponseAction.TERMINATE, dry_run, detail)


def escalate(
    agent_id: str,
    on_violation: str,
    *,
    token_id: str | None = None,
    issuer: TokenIssuer | None = None,
    dry_run: bool = True,
) -> list[ResponseEvent]:
    if on_violation not in ESCALATION_CHAIN:
        raise ValueError(f"unknown response.on_violation value '{on_violation}'")

    events: list[ResponseEvent] = []
    for action in ESCALATION_CHAIN[on_violation]:
        if action == ResponseAction.ALERT:
            events.append(alert(agent_id, "policy violation detected", dry_run=dry_run))
        elif action == ResponseAction.ISOLATE:
            events.append(isolate(agent_id, dry_run=dry_run))
        elif action == ResponseAction.REVOKE:
            events.append(revoke(agent_id, token_id or "unknown", issuer, dry_run=dry_run))
        elif action == ResponseAction.PRESERVE:
            events.append(preserve(agent_id, dry_run=dry_run))
        elif action == ResponseAction.TERMINATE:
            events.append(terminate(agent_id, dry_run=dry_run))
    return events
