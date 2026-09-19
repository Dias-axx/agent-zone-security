# ADR 0002: mitmproxy as the TLS-terminating egress gateway

**Status**: Accepted. `evaluate_request()`'s decision logic is unit-tested
directly, and the built image (`deploy/mitmproxy/Dockerfile`) was built and
actually run as a standalone container in this repo's build session — real
proxied HTTP requests through it produced the real decisions below (this is
genuine command output, not a paraphrase):

```
{"agent_id": "agt-log-reader-001", "destination": "internal-logs.example.com", "verdict": "allow", "rule_id": "AGT-EGRESS-OK", "reason": "egress target 'internal-logs.example.com' matches suffix entry '.internal-logs.example.com'"}
{"agent_id": "agt-log-reader-001", "destination": "evil.example.net", "verdict": "deny", "rule_id": "AGT-EGRESS-001", "reason": "egress target 'evil.example.net' not in allowlist"}
   << Connection killed.
{"agent_id": "nonexistent", "destination": "internal-logs.example.com", "verdict": "deny", "rule_id": "AGT-EGRESS-001", "reason": "unknown or missing X-Agent-Id"}
   << Connection killed.
```

The allowed request then failed on DNS resolution (`internal-logs.example.com`
doesn't resolve to anything in this sandbox) — expected, and orthogonal to the
policy decision, which is what this proves. **What is still unverified**: this
ran as a standalone container, not deployed into the k3d/Cilium cluster from
Phase 2 (still blocked there — see `docs/architecture.md`), so the
NetworkPolicy-restricted-reachability part of the design and CA trust
distribution to real agent pods remain unconfirmed. One real bug was found and
fixed during this: the mitmproxy base image does not bundle PyYAML, so
`deploy/mitmproxy/Dockerfile` installs it explicitly — building the image is
what caught this, which is the whole point of actually running it instead of
only reading the code.

## Context

The README originally listed "no TLS inspection" as a deliberate, permanent
scope decision: the egress gateway (`deploy/k8s/30-egress-gateway.yaml`) was
an nginx placeholder that proved the *network* shape (only the gateway is
reachable from an agent zone) but never terminated or inspected TLS, so the
proxy only ever saw SNI and destination IP, never a decrypted request.

That gap was revisited on request: an actual TLS-terminating forward proxy is
buildable and worth having, as long as it is scoped honestly (see
Consequences) rather than oversold as "solves TLS inspection" outright.

## Decision

Use mitmproxy (`mitmproxy/mitmproxy:12.2`, explicit/regular proxy mode) as the
egress gateway's proxy engine, with a custom addon
(`deploy/mitmproxy/policy_addon.py`) that imports
`control.policy_engine.evaluate_egress` directly rather than reimplementing
allowlist matching in Python-for-mitmproxy a second time.

## Alternatives considered

- **Envoy** (already in the cluster via Cilium, see ADR 0001): Envoy's
  dynamic forward proxy filter is built for *originating* new outbound TLS
  connections with SNI-based routing, not for terminating and re-signing an
  arbitrary client's TLS connection with dynamically generated leaf
  certificates per destination. That's a materially different feature
  (dynamic CA-signed certificate generation per intercepted host) that Envoy
  does not provide out of the box; building it would mean writing and
  operating that logic ourselves, which is exactly the problem mitmproxy
  already solves.
- **A bespoke Python/Go TLS proxy**: rejected for the same reason — dynamic
  per-host certificate generation, trusted-by-the-client, correct TLS
  session handling, is a well-understood but non-trivial problem. Writing it
  from scratch for a reference implementation is a worse use of the same
  effort than using the tool built for exactly this (mitmproxy is what this
  session's own outbound proxy — see the environment's own
  TLS-intercepting agent proxy — is functionally doing).

## Consequences

- **Real enforcement, not just visibility.** `policy_addon.py` calls the same
  `evaluate_egress()` every other enforcement point in this repo uses, so a
  request through this gateway is denied under the exact same rule that would
  deny it at the policy-engine layer — not a second, potentially-diverging
  implementation.
- **Agent identity via `X-Agent-Id` header, not mTLS.** The gateway is only
  reachable from agent-restricted/deploy-staging by NetworkPolicy, but within
  that boundary, nothing yet cryptographically proves which agent a request
  came from — a compromised agent could set another agent's header value.
  Because the check that matters (the destination allowlist) is evaluated
  against whatever agent_id is claimed, a false claim can at most narrow or
  match what that claimed identity could already reach — it does not grant
  access outside the union of every agent's allowlists. Still, per-agent
  mTLS client certificates (issued alongside the capability tokens
  `control/token_issuer.py` already generates) would close this properly.
  Not built in this pass — a named follow-up, not a hidden gap.
- **CA trust distribution is manual.** mitmproxy generates its own CA on
  first start into an `emptyDir`, so it is not persisted across pod restarts
  and there is no automation here that installs it into agent pods' trust
  stores. A real deployment needs either a persistent volume for
  `confdir` plus a one-time trust-distribution step, or a pre-provisioned
  fixed CA delivered via a Secret. This manifest set proves the proxy
  topology and real-policy enforcement; it does not automate CA lifecycle.
- Detection: `policy_addon.py` prints one JSON line per request in the same
  shape `detection.normalise.from_proxy_log()` expects as input, so a log
  shipper reading the gateway's stdout feeds the same pipeline as every other
  source, with no format translation needed.
