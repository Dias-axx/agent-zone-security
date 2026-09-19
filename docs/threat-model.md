# Threat model

Scope: an autonomous AI agent running inside a segmented enterprise network, holding
credentials and tool access, possibly compromised by prompt injection or a malicious
tool definition. The control model assumes the agent is already running with valid
credentials — it does not attempt to prevent the initial compromise.

Frameworks referenced: MITRE ATLAS (2026 mapping), OWASP Top 10 for Agentic
Applications (Dec 2025), STRIDE. References are dated because this field is moving
fast and the mapping is expected to age.

## Assets

| Asset | Description |
|---|---|
| Agent credentials | Short-lived capability tokens (`control/token_issuer.py`), scoped to `(agent_id, role, session_id, scope)` |
| Delegating user's IAM scope | The human an agent acts for; the AND gate depends on this being accurate |
| Internal document stores | RAG collections with per-collection sensitivity (`policy/examples/rag-agent.yaml`) |
| Egress path | The only route out of the agent's network zone |
| Audit trail | Append-only JSONL log of every policy evaluation |

## Threat actors

- **External attacker via prompt injection**: content the agent processes (a document,
  a web page, a tool response) contains instructions that redirect the agent's
  behaviour. This project's non-goal list explicitly excludes filtering injected
  content — the threat model assumes injection succeeds and focuses on containment.
- **Malicious or compromised tool/MCP server**: a tool definition or its output
  attempts to escalate the agent's effective permissions or exfiltrate data through
  a side channel (e.g. DNS).
- **Over-permissioned delegation**: an agent configured with a broader role scope
  than the human it is delegated from, either by misconfiguration or by a stale
  policy that was not updated when the human's own access changed.
- **Insider misuse of agent autonomy**: a legitimate operator scripts an agent to
  perform actions at a volume or scope beyond what a single human session would
  normally attempt (denial-of-wallet, bulk data access).

## Entry points

- Tool calls the agent issues (`kind: tool` requests to the policy engine)
- Outbound network connections (`kind: egress`)
- Attempts to operate outside the agent's assigned namespace/zone (`kind: zone`)
- The capability token itself, if leaked or replayed

## Trust boundaries

- Agent pod ↔ Tool Broker (policy enforcement point for tool calls)
- Agent pod ↔ Egress Gateway (policy enforcement point for network egress)
- Zone boundary enforced by the network fabric (Cilium NetworkPolicy, Phase 2)
- Delegating human's IAM scope ↔ the agent's own role scope (AND gate)

## Escalation paths

1. A delegated agent's role policy is broader than necessary, and the AND gate is
   implemented incorrectly (as OR) or omitted entirely — the single most severe
   design error this repo defends against.
2. A capability token is not properly bound to a session or is not checked for
   revocation on every evaluation, allowing a revoked agent to continue acting.
3. An egress allowlist entry uses an unconstrained wildcard, silently permitting
   exfiltration to any host.
4. DNS is used as an exfiltration channel that bypasses HTTP/TLS-layer egress
   controls (see CVE-2025-55284 in the README problem statement).

## Blast radius

- Contained by design to the agent's own zone and its own capability token's scope.
- A single compromised agent should not be able to reach another zone, another
  agent's credentials, or a tool outside its declared role — assuming the AND gate,
  zone enforcement and egress allowlist are all correctly configured.
- Blast radius is NOT contained if: the delegating user's own IAM scope is itself
  overprivileged (the AND gate only ever narrows, it cannot fix an overprivileged
  human), or if the egress gateway's remaining gaps (see Known limitations — CA
  trust distribution and header-based, non-cryptographic agent identity) are used
  to smuggle data to an allowlisted destination that also accepts attacker traffic.

## Monitoring gaps (documented, not hidden)

- The egress gateway (`deploy/mitmproxy/`) now terminates TLS and enforces the
  real egress allowlist, but agent identity there is an `X-Agent-Id` header, not
  a cryptographic credential, and the mitmproxy CA is not yet distributed to
  agent pods' trust stores automatically — see
  `docs/adr/0002-tls-terminating-egress-gateway.md`.
- Behavioural baselines are derived from deterministic mock agents; they are
  synthetic and do not transfer to real workloads without retraining.
- Tool-output scanning (`detection/output_scanner.py`) is heuristic pattern
  matching, not content sanitisation or a prompt-injection filter — a tool's
  response can still contain content that influences the next model call and
  evades every pattern this scanner knows about, even though the agent's own
  network/tool actions stay contained regardless.
- No multi-agent delegation chain modelling — the AND gate is evaluated one hop
  deep (agent → the human it is delegated from), not across a chain of agents
  delegating to other agents.

## Mitigations implemented in this repo

| Control | Maps to |
|---|---|
| Default-deny egress with exact/suffix allowlist | Prevention |
| Zone allow-list (home + reachable) | Prevention |
| AND-gate intersection for delegated identity | Prevention |
| Short-lived capability tokens with immediate revocation (shared store optional) | Prevention |
| TLS-terminating egress gateway with real-policy enforcement | Prevention |
| Append-only audit trail (allows and denies; local file + optional syslog) | Detection support |
| Declarative detection rules mapped to ATLAS/OWASP ASI | Detection |
| Tool-output heuristic anomaly scanning | Detection (best-effort) |
| Response chain: alert → isolate → revoke → preserve → terminate | Response |

See `docs/compliance-mapping.md` for how these controls map to external compliance
frameworks, and the README's "Known limitations" section for what is explicitly out
of scope.
