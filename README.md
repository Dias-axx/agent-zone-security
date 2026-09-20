# agent-zone-control

**Runtime containment and behavioural detection for AI agents in segmented enterprise networks.**

Most agent-security tooling stops at configuration scanning. This project starts where that ends:
it assumes an agent is already running, already has credentials, and may be doing something it was
never meant to do — reaching the internet, crossing into a network zone it has no business in, or
calling a tool outside its declared role.

The control model is borrowed from regulated enterprise network security (default-deny egress,
explicit per-zone firewall approvals, forced proxy egress, privileged access management) and applied
to autonomous agents as the subject instead of users and servers.

---

## Problem

| Observation | Source |
|---|---|
| Most organisations cannot trace agent actions back to an accountable human sponsor | CSA "Securing Autonomous AI Agents" survey, 2026 |
| The large majority of organisations would fail a compliance audit focused on agent behaviour or access controls | CSA / Strata Identity survey, 2026 |
| Agent frameworks (LangGraph, ADK, CrewAI, MCP) ship no secure defaults for identity, auditability or boundary enforcement | OWASP Top 10 for Agentic Applications, Dec 2025 |
| Real CVEs already exist for agent egress abuse (e.g. DNS exfiltration via a coding agent) | CVE-2025-55284 |

The gap this repo addresses: **there is no open reference implementation that combines zone
enforcement, egress control, per-agent identity and behavioural detection into one auditable loop.**

## Non-goals

- Not an MCP configuration scanner — that problem is covered (`mcp-scan`, `mcp-armor`). This repo
  assumes the agent is already deployed and running; it does not audit its configuration at rest.
- Not a prompt-injection filter. This project assumes injection succeeds and contains the blast radius.
- Not a production product. It is a reference implementation with reproducible proof-of-concepts.

---

## Architecture

```
                        ┌──────────────────────────────┐
                        │        Agent Registry        │
                        │ owner · role · autonomy · TTL│
                        └──────────────┬───────────────┘
                                       │ admission gate
┌─────────── zone: agent-restricted ───┼──────────────────────────────┐
│                                      ▼                              │
│   ┌─────────────┐        ┌────────────────────┐                     │
│   │ Agent Pod   │───────▶│  Egress Gateway    │──▶ allowlisted only │
│   │ (ephemeral) │        │  (forward proxy)   │                     │
│   └──────┬──────┘        └─────────┬──────────┘                     │
│          │ tool calls              │ proxy logs                     │
│          ▼                         │                                │
│   ┌─────────────┐                  │                                │
│   │ Tool Broker │ policy check ────┤                                │
│   └─────────────┘                  │                                │
└──────────────┬─────────────────────┼────────────────────────────────┘
               │ NetworkPolicy drops │ OTel traces
               ▼                     ▼
        ┌──────────────────────────────────┐
        │  Detection Engine (rules/)       │
        │  ATLAS + OWASP ASI mapped        │
        └──────────────┬───────────────────┘
                       ▼
           alert → isolate → revoke → terminate
```

The Tool Broker and Egress Gateway both call into the same policy decision point
(`control/policy_engine.py`) today. The Cilium `NetworkPolicy` zone enforcement
shown in the diagram is confirmed running on real infrastructure (see
[Phase status](#phase-status) and `docs/architecture.md`); the egress-gateway pod
itself is not yet exercised live (its image isn't built/pushed).

## Control layers

**Prevention**
- Default-deny egress per agent namespace (`deploy/k8s/10-default-deny.yaml`, Cilium-enforced `NetworkPolicy`)
- Namespace = zone; cross-zone traffic only via explicit, reviewed policy (`deploy/k8s/32-zone-deploy-staging.yaml`)
- All outbound traffic forced through an egress-gateway pod; direct connections dropped (`deploy/k8s/30-31-*.yaml`)
- Short-lived, task-scoped capability tokens — never long-lived API keys (`control/token_issuer.py`)
- AND-gate for delegated identity: a delegated agent's effective permission is the
  intersection of its role scope and the scope of the human it acts for, never a
  superset (`control/policy_engine.py`)

**Detection**
- Cilium/Hubble flow logs — every `DENIED` verdict is a high-fidelity signal (normaliser implemented, live ingestion not yet wired — see Known limitations)
- Egress proxy logs — non-allowlisted destinations, abnormal transfer volume (normaliser implemented, live ingestion not yet wired)
- OpenTelemetry tool-call traces — calls outside the declared role scope (normaliser implemented, live ingestion not yet wired)
- Declarative detection rules evaluated against normalised events (`detection/`)

A blocked attempt is worth more than a successful request: it proves the agent *wanted* something it
was not permitted to do. Those are the alerts this project optimises for.

**Response**

`alert → isolate (deny-all NetworkPolicy) → revoke token → preserve → terminate pod`
(`control/response.py`)

Escalation level is configured per agent role via `response.on_violation`, not globally.

## Framework mapping

| Control | OWASP Top 10 for Agentic Applications (Dec 2025) | MITRE ATLAS (2026 mapping) |
|---|---|---|
| Role-scoped tool allowlist | Excessive Agency | AML.T0053 LLM Plugin Compromise |
| Egress allowlist + proxy | Tool Misuse | AML.T0025 Exfiltration via Cyber Means |
| AND-gate delegated identity | Excessive Agency / Privilege Abuse | Lateral movement via agent tooling |
| Secret-store access control | Sensitive Information Disclosure | AML.T0024 Exfiltration via ML Inference API |
| Volume-based detection | Resource Exhaustion / Denial of Wallet | AML.T0034 Cost Harvesting |
| Tool-output anomaly scanning (heuristic, not preventive) | Prompt Injection Propagation | AML.T0051.001 Indirect Prompt Injection |
| TLS-terminating egress gateway with real-policy enforcement | Tool Misuse | AML.T0025 Exfiltration via Cyber Means |
| Immutable audit trail with `delegated_by` | Lack of auditability | — |

Framework references are dated deliberately — this field moved substantially during 2026 and the
mapping is expected to age.

---

## Repository layout

```
registry/      agent inventory: owner, role, autonomy level, review date
policy/        capability schema + example role policies (read-only, deploy, RAG)
control/       policy engine, registry validator, token issuer (+ optional Redis revocation
               backend), audit log (+ pluggable sinks), response chain
detection/     event normalisation, declarative rule engine, tool-output heuristic scanner,
               ATLAS/ASI-mapped rules
agents/        deterministic mock agents (log_reader, deploy_assistant) + optional LLM adapter
poc/           reproducible attack/containment scenarios, each returns a process exit code
tests/         pytest suite covering every deny path and the AND-gate
deploy/        k3d/Cilium cluster config, Kubernetes manifests (zones, default-deny, Kyverno),
               and the mitmproxy-based TLS-terminating egress gateway (deploy/mitmproxy/)
go/            flow consumer, response controller, admission webhook (Go, no external dependencies)
docs/          threat model, architecture notes, compliance mapping, ADRs
```

## Phase status

| Phase | Scope | State |
|---|---|---|
| 1 | Registry, policy schema + examples, policy engine, mock agents | done |
| 1.5 | Token issuer, audit log, response chain, pytest suite, CI | done |
| 2 | k3d + Cilium, zone isolation, egress gateway, admission control | **core acceptance criterion confirmed live** (Docker Desktop/Windows): cross-zone attempt → real `DROPPED` Hubble flow. Egress gateway and admission control not yet exercised live — see `docs/architecture.md` |
| 3 | Detection engine + Go flow-consumer: `AGT-ZONE-001` confirmed firing against a real captured Hubble flow through the actual Go→Python pipeline, not just synthetic JSON (`make poc-pipeline`); live OTel/Vault ingestion still not wired | partial |
| 4 | Compliance mapping (EU AI Act, DORA, ISO 42001, NIST AI RMF, BAIT/MaRisk) | documented, honestly marked partial/documented-only — see `docs/compliance-mapping.md` |
| 6 | Go: flow consumer, response controller, admission webhook — `flow-consumer`'s Hubble parsing confirmed against a real captured flow (one label-key bug found and fixed); `response-controller`/`admission-webhook` still only unit-tested against mocks, never run against a live API server | partial |

Demo agents are deterministic mocks so that proof-of-concepts run reproducibly in CI at zero cost.
Real model APIs (Claude, GPT) are an optional adapter (`agents/adapters/llm.py`), not a dependency.

## Quick start

```bash
pip install -r requirements-dev.txt
python -m control.validate            # validate registry + policies (fails closed)
make poc                              # run all five containment proof-of-concepts
pytest                                # unit tests
ruff check . && mypy                  # lint + strict type check
```

Each PoC prints the policy verdicts it produces and exits non-zero if the expected
containment behaviour did not occur:

```bash
python -m poc.scenario_egress            # default-deny egress + explicit allowlist
python -m poc.scenario_zone              # cross-zone traversal denied (AGT-ZONE-001)
python -m poc.scenario_and_gate          # delegated agent cannot exceed its human's scope
python -m poc.scenario_secret_harvest    # secret-store access + exfiltration contained and detected
python -m poc.scenario_denial_of_wallet  # high-volume tool calls flagged, response chain escalated
```

### Go components

```bash
make go-check      # gofmt, go vet, golangci-lint, go test, go build (go/)
make poc-pipeline   # Go flow-consumer piped into Python detection engine, synthetic Hubble JSON
```

`poc-pipeline` builds `go/cmd/flow-consumer` and pipes synthetic-but-realistic
`hubble observe -o json` lines through it into `detection/consume_stream.py`,
printing the real `AGT-ZONE-001` match it produces. This proves the Go->Python
boundary; it is not a live-cluster proof (see Cluster below).

### Cluster (Phase 2 — core containment confirmed live)

```bash
make cluster-up     # k3d cluster + Cilium/Hubble via Helm
make deploy          # apply deploy/k8s/ (zones, default-deny, egress gateway, test pods)
make poc-cluster     # poc/scenario_zone_cluster.sh: cross-zone attempt -> DROPPED Hubble flow
make cluster-down    # tear down
```

`cluster-up` + `deploy` + the core zone-containment assertion were run end to end on
real infrastructure (Docker Desktop, Windows, k3d v5.8.3, Cilium 1.16.5): every pod
reached `Running`, a cross-zone connection genuinely timed out, and `hubble observe`
showed the real `DROPPED` flow with `AGT-ZONE-001` firing against it — see
`docs/architecture.md` for the captured output. This repo's own build sandbox hit an
unrelated containerd/runc limitation blocking all pod scheduling (preserved in
`docs/architecture.md` for reference); it turned out to be specific to that sandbox,
not the k3d/Cilium configuration. Not yet exercised live: the `egress-gateway` pod
(its image isn't built/pushed, so it stays `ImagePullBackOff`) and the Kyverno
admission policies. See `docs/live-verification-runbook.md` for the full step-by-step
guide, including the Windows-specific `host.docker.internal` kubeconfig fix.

## Known limitations

- **TLS inspection: real gateway, built and run standalone, not yet run in-cluster.**
  `deploy/k8s/30-egress-gateway.yaml` deploys a mitmproxy-based TLS-terminating forward proxy
  (`deploy/mitmproxy/`) enforcing the same `evaluate_egress()` every other layer uses. The image was
  built and run as a standalone container in this repo's build session — real proxied requests through
  it produced real allow/deny decisions and an actual "Connection killed" for a denied destination (see
  `docs/adr/0002-tls-terminating-egress-gateway.md` for the captured output). What that run does **not**
  cover: deployment into the k3d/Cilium cluster from Phase 2 (still blocked, see `docs/architecture.md`),
  CA trust distribution to real agent pods, and agent identity is an `X-Agent-Id` header, not mTLS —
  both named as follow-ups in the ADR, not hidden.
- **Tool-output "sanitisation" is heuristic detection, not prevention.** `detection/output_scanner.py`
  flags known injection-marker patterns in tool output and feeds `AGT-INJECT-001` into the same
  detection pipeline as every other signal (`poc/scenario_tool_output_anomaly.py`). This does **not**
  reverse the threat model's core assumption that injection can succeed (see Non-goals) — it is a
  best-effort additional signal with real false-negative and false-positive rates, not a filter anyone
  should rely on to stop an injection from working. The containment controls (policy engine, egress
  allowlist, zone enforcement) remain the actual defense; this only helps notice sooner.
- **Synthetic behavioural baselines.** Detection thresholds (e.g. the denial-of-wallet call-count rule)
  are illustrative and derived from deterministic mock agents. They will not transfer to real
  workloads without retraining against real traffic.
- **No multi-agent delegation chains.** The AND gate is evaluated one hop deep (agent → the human it
  is delegated from). An agent delegating to another agent is not modelled.
- **`data_scope` (per-collection access) is declared but not enforced.** `policy/examples/rag-agent.yaml`
  declares `hr-confidential: access: none`, but `control/policy_engine.py`'s `evaluate_tool` only checks
  the tool name (`docstore.query`) against the role's scope — it never reads `data_scope`, so a role with
  `docstore.query` can query any collection regardless of what `data_scope` says. Enforcing this properly
  needs a resource/collection field threaded through `Request`, every call site, and the mock agents —
  a design decision, not a local fix, so it is named here rather than half-implemented. Found in review;
  left open deliberately.
- **Token revocation and audit log are pluggable now, but default to single-process/single-file.**
  `control/token_issuer.py`'s `TokenIssuer` accepts a `RevocationStore` (default:
  `InMemoryRevocationStore`, still single-process; optional `RedisRevocationStore` in
  `control/revocation_backends.py`, import-guarded, shares revocation state across processes/replicas —
  requires a Redis instance this repo does not provision) and a shared `secret` (default: still a fresh
  random secret per instance, so multiple processes can't verify each other's tokens unless a shared
  secret is explicitly passed in — secret distribution is a deployment concern this module deliberately
  does not solve). `control/audit.py`'s `AuditLog` now dispatches to multiple `AuditSink`s
  (`JSONLFileSink` always, plus optional `SyslogSink` for a SIEM). The Redis and syslog paths are
  unit-tested against fakes only, not a real Redis/syslog collector. A third sink,
  `control/coding_agent_monitor_sink.py`'s `CodingAgentMonitorSink`, forwards each record to a running
  [Coding-Agent-Monitor](https://github.com/Dias-axx/coding-agent-monitor) instance as a live log line
  (`allow`/`confirm` → stdout, `deny` → stderr) so its dashboard shows policy verdicts next to normal
  session logs — **this one was verified end to end**: a real monitor instance was started, records were
  written through the real sink, and `GET /api/agents/:id` showed both log lines with the correct
  streams. It is explicitly a best-effort, non-durable convenience view (matching the monitor's own
  stance and its lack of authentication) — never a replacement for `JSONLFileSink`/`SyslogSink`, and a
  forwarding failure is swallowed and logged to stderr, never raised into the policy-evaluation path.
- **The response chain's `isolate`/`terminate` actions are still dry-run only in every call site in
  this repo** — no code path has flipped `dry_run=False` against a live cluster. OTel/Vault ingestion
  into the detection engine is also not wired.
- **Cluster core containment confirmed live; egress gateway and admission control are not.**
  `deploy/k3d/cluster.yaml` and `deploy/k8s/*.yaml` were run end to end on real infrastructure (Docker
  Desktop, Windows): every pod including Cilium's DaemonSet reached `Running`, a cross-zone connection
  attempt genuinely timed out, and `hubble observe` showed the real `DROPPED` flow — see
  `docs/architecture.md` for the captured output. The `egress-gateway` pod itself stayed
  `ImagePullBackOff` in that same run (image never built/pushed, see the mitmproxy limitation above),
  so egress-gateway reachability and the Kyverno admission policies were not exercised live.
- **Go components: `flow-consumer`'s Hubble parsing is now confirmed against a real captured flow**
  (`TestParseHubbleLineRealCapturedFlow`) — one real bug found this way and fixed: `hubble.go` was
  matching on `agent_id=` while `internal/response/controller.go`'s `isolate()`/`terminate()` already
  used `agent-id=` (hyphen) to select pods; both now agree on `agent-id`. `go/cmd/response-controller`
  and `go/cmd/admission-webhook` are still tested against fakes only (`internal/response`,
  `internal/webhook`) — neither has run against a real API server yet.
- No customer, employer or production data is used anywhere in this repository. All scenarios are
  synthetic.

## License

MIT
