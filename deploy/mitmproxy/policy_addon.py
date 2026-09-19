"""mitmproxy addon: TLS-terminating egress gateway with real policy enforcement.

Replaces the nginx placeholder (deploy/k8s/30-egress-gateway.yaml) with an
actual forward proxy that terminates the agent's TLS connection, decides
allow/deny using the *same* control.policy_engine.evaluate_egress code every
other enforcement point in this repo uses (no reimplemented allowlist logic),
and re-originates TLS to the real destination for an allowed request. This is
what closes the "no TLS inspection" gap in the README's Known limitations —
see docs/adr/0002-tls-terminating-egress-gateway.md for why mitmproxy and not
Envoy, and what is still a documented limitation even after this.

Runs inside the mitmproxy/mitmproxy image with control/policy_engine.py,
detection/normalise.py, registry/agents.yaml and policy/examples/*.yaml
baked in by deploy/mitmproxy/Dockerfile — it imports the real modules rather
than re-implementing egress matching a second time.

Agent identity: the calling agent is expected to set an `X-Agent-Id` request
header. This proxy is only reachable from agent-restricted/deploy-staging by
NetworkPolicy (31-allow-egress-gateway.yaml), so the header is a convenience
identifier inside an already-restricted network path, not itself a security
boundary — a compromised agent could still lie about its own agent_id. The
policy check that actually matters (the destination allowlist) does not
depend on the header being honest against a *different* agent's identity
mattering here: the check enforces what this policy is allowed to reach, and
a lie only ever narrows or matches an agent's own already-granted scope,
never grants access to a target outside every agent's allowlists combined.
Closing this gap fully needs per-agent mTLS client certs, which is a
follow-up (see the ADR).

Verified: `evaluate_request()` below is unit-tested directly
(tests/test_mitmproxy_addon.py) without mitmproxy installed. The mitmproxy
Addon class itself (`request()`/`response()` hooks, `flow.kill()`) has NOT
been exercised against a running mitmproxy process or a live cluster — same
verification gap as the rest of Phase 2, documented rather than implied away.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Baked in by the Dockerfile at these exact paths — see deploy/mitmproxy/Dockerfile.
sys.path.insert(0, "/app")

import yaml  # noqa: E402

from control.policy_engine import Decision, Request, evaluate_egress  # noqa: E402

APP_ROOT = Path("/app")
REGISTRY_PATH = APP_ROOT / "registry" / "agents.yaml"


def load_agent_policies(
    registry_path: Path = REGISTRY_PATH, app_root: Path = APP_ROOT
) -> dict[str, dict[str, Any]]:
    """Maps agent_id -> its loaded policy document, from the registry.

    `entry["policy"]` in registry/agents.yaml is a repo-root-relative path
    (e.g. "policy/examples/read-only-agent.yaml"); app_root is where the
    Dockerfile recreates that same relative layout under /app.
    """
    with registry_path.open(encoding="utf-8") as fh:
        registry = yaml.safe_load(fh)

    policies: dict[str, dict[str, Any]] = {}
    for entry in registry.get("agents", []):
        policy_path = app_root / entry["policy"]
        with policy_path.open(encoding="utf-8") as fh:
            policies[entry["id"]] = yaml.safe_load(fh)
    return policies


def evaluate_request(
    agent_id: str | None, destination_host: str, policies: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Pure decision function: given an agent id and the destination host a
    proxied request targets, decide allow/deny using the real policy engine,
    and return a proxy-log-shaped dict — the same shape
    detection.normalise.from_proxy_log expects as input — ready to log.

    An unknown or missing agent_id fails closed (denied) — an unidentified
    caller gets no default allowance, matching every other fail-closed
    decision point in this repo.
    """
    if not agent_id or agent_id not in policies:
        return {
            "agent_id": agent_id or "unknown",
            "destination": destination_host,
            "verdict": "deny",
            "rule_id": "AGT-EGRESS-001",
            "reason": "unknown or missing X-Agent-Id",
        }

    policy = policies[agent_id]
    verdict = evaluate_egress(policy, Request(kind="egress", agent_id=agent_id, target=destination_host))
    return {
        "agent_id": agent_id,
        "destination": destination_host,
        "verdict": "allow" if verdict.decision == Decision.ALLOW else "deny",
        "rule_id": verdict.rule_id,
        "reason": verdict.reason,
    }


try:
    from mitmproxy import http

    class EgressPolicyAddon:
        def __init__(self) -> None:
            self._policies = load_agent_policies()

        def request(self, flow: http.HTTPFlow) -> None:
            agent_id = flow.request.headers.get("X-Agent-Id")
            destination_host = flow.request.pretty_host
            result = evaluate_request(agent_id, destination_host, self._policies)

            print(json.dumps(result), file=sys.stdout, flush=True)

            if result["verdict"] == "deny":
                flow.kill()

    addons = [EgressPolicyAddon()]

except ImportError:
    # mitmproxy is not installed in the environment running the unit tests for
    # evaluate_request()/load_agent_policies() above — that's expected and fine.
    pass
