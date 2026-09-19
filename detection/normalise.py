"""Normalise heterogeneous event sources (Hubble flow logs, egress proxy logs,
OTel tool-call traces, Vault audit logs) into one common event schema so
detection/engine.py can evaluate declarative rules without per-source logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalisedEvent:
    source: str  # "hubble" | "proxy" | "otel" | "vault" | "policy_engine" | "output_scanner"
    agent_id: str
    kind: str  # "zone" | "egress" | "tool" | "secret_access" | "tool_output"
    target: str
    verdict: str  # "allow" | "deny" | "unknown"
    raw: dict[str, Any]


def from_hubble_flow(flow: dict[str, Any]) -> NormalisedEvent:
    verdict = "deny" if flow.get("verdict") == "DROPPED" else "allow"
    agent_id = flow.get("source", {}).get("labels", {}).get("agent_id", "unknown")
    target = flow.get("destination", {}).get("namespace", "unknown")
    return NormalisedEvent(
        source="hubble", agent_id=agent_id, kind="zone", target=target, verdict=verdict, raw=flow
    )


def from_proxy_log(entry: dict[str, Any]) -> NormalisedEvent:
    return NormalisedEvent(
        source="proxy",
        agent_id=entry.get("agent_id", "unknown"),
        kind="egress",
        target=entry.get("destination", "unknown"),
        verdict=entry.get("verdict", "unknown"),
        raw=entry,
    )


def from_otel_trace(span: dict[str, Any]) -> NormalisedEvent:
    attributes = span.get("attributes", {})
    return NormalisedEvent(
        source="otel",
        agent_id=attributes.get("agent.id", "unknown"),
        kind="tool",
        target=span.get("name", "unknown"),
        verdict=attributes.get("policy.decision", "unknown"),
        raw=span,
    )


def from_tool_output_scan(agent_id: str, tool: str, marker: str) -> NormalisedEvent:
    """One event per heuristic marker found by detection.output_scanner in a
    tool's output. verdict is always "deny" here in the sense of "this marker
    should not be present" — it is not a policy engine decision, it is a
    content-inspection finding (see detection/output_scanner.py's docstring
    for what that does and does not prove)."""
    return NormalisedEvent(
        source="output_scanner",
        agent_id=agent_id,
        kind="tool_output",
        target=tool,
        verdict="deny",
        raw={"marker": marker},
    )


def from_vault_audit(entry: dict[str, Any]) -> NormalisedEvent:
    agent_id = entry.get("auth", {}).get("metadata", {}).get("agent_id", "unknown")
    target = entry.get("request", {}).get("path", "unknown")
    verdict = "deny" if entry.get("error") else "allow"
    return NormalisedEvent(
        source="vault", agent_id=agent_id, kind="secret_access", target=target, verdict=verdict, raw=entry
    )
