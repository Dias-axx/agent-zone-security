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
(`control/policy_engine.py`) today; the network-level enforcement (Cilium
NetworkPolicy, an egress-gateway pod) shown in the diagram is defined as code
under `deploy/` but not yet confirmed running end to end anywhere — see
[Phase status](#phase-status) and `docs/architecture.md`.

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
| Immutable audit trail with `delegated_by` | Lack of auditability | — |

Framework references are dated deliberately — this field moved substantially during 2026 and the
mapping is expected to age.

---

## Repository layout

```
registry/      agent inventory: owner, role, autonomy level, review date
policy/        capability schema + example role policies (read-only, deploy, RAG)
control/       policy engine, registry validator, token issuer, audit log, response chain
detection/     event normalisation + declarative rule engine, ATLAS/ASI-mapped rules
agents/        deterministic mock agents (log_reader, deploy_assistant) + optional LLM adapter
poc/           reproducible attack/containment scenarios, each returns a process exit code
tests/         pytest suite covering every deny path and the AND-gate
deploy/        k3d/Cilium cluster config and Kubernetes manifests (zones, default-deny, egress gateway, Kyverno)
go/            flow consumer, response controller, admission webhook (Go, no external dependencies)
docs/          threat model, architecture notes, compliance mapping, ADRs
```

## Phase status

| Phase | Scope | State |
|---|---|---|
| 1 | Registry, policy schema + examples, policy engine, mock agents | done |
| 1.5 | Token issuer, audit log, response chain, pytest suite, CI | done |
| 2 | k3d + Cilium, zone isolation, egress gateway, admission control | manifests written, cluster creation + Cilium install verified; pod scheduling/live Hubble flow **not yet verified anywhere** — see `docs/architecture.md` |
| 3 | Detection engine + Go flow-consumer: rule evaluation and the Go->Python pipeline verified against synthetic Hubble JSON (`make poc-pipeline`); live Hubble/OTel/Vault ingestion from a running cluster not yet wired (same gap as Phase 2) | partial |
| 4 | Compliance mapping (EU AI Act, DORA, ISO 42001, NIST AI RMF, BAIT/MaRisk) | documented, honestly marked partial/documented-only — see `docs/compliance-mapping.md` |
| 6 | Go: flow consumer, response controller, admission webhook — implemented, unit-tested (17 tests) against mocked `kubectl`/API calls and synthetic Hubble JSON; never run against a live cluster | partial |

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

### Cluster (Phase 2, unverified — read this before running)

```bash
make cluster-up     # k3d cluster + Cilium/Hubble via Helm
make deploy          # apply deploy/k8s/ (zones, default-deny, egress gateway, test pods)
make poc-cluster     # poc/scenario_zone_cluster.sh: cross-zone attempt -> DROPPED Hubble flow
make cluster-down    # tear down
```

These targets do what was actually run while building this repo, up to a point:
`cluster-up` succeeds (cluster creates, Cilium's Helm chart installs cleanly), but
in that build environment no pod — Cilium's own DaemonSet included — ever reached
`Running`, so `deploy` and `poc-cluster` were never confirmed. See
`docs/architecture.md` for the exact failure and the diagnosis performed. Run
these on real infrastructure (a VM, bare metal, or a CI runner with full
nested-container support) to get the actual proof.

## Known limitations

- **No TLS inspection.** The egress gateway design (Phase 2, not yet built) sees SNI and destination
  only, not payload. This is a deliberate scope decision, not an oversight — see
  `docs/adr/0001-cilium-over-calico.md`.
- **No tool-output sanitisation.** A tool's response can still influence the next model call even
  though the agent's own network and tool actions are contained. This project's threat model assumes
  injection succeeds; it does not filter it (see Non-goals).
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
- **Single-process token revocation and audit log.** `TokenIssuer` revocation state and the JSONL
  audit log both live in a single process/file in this reference implementation. A production
  deployment needs a shared revocation store and a real log pipeline.
- **No live cluster wiring yet.** The response chain's `isolate`/`terminate` actions are dry-run only;
  the detection engine evaluates rules against synthetic events, not a running Cilium/OTel/Vault
  pipeline. See [Phase status](#phase-status).
- **Cluster manifests are unverified end to end.** `deploy/k3d/cluster.yaml` and `deploy/k8s/*.yaml`
  were written and cluster creation + the Cilium Helm install were confirmed, but pod scheduling was
  blocked by a containerd/runc failure specific to the sandbox this repo was built in (see
  `docs/architecture.md`). Do not treat Phase 2 as proven until `make poc-cluster` has actually been
  run successfully and its `hubble observe` output captured.
- **Go components are unit-tested, not live-tested.** `go/cmd/response-controller` and
  `go/cmd/admission-webhook` shell out to `kubectl` / call the Kubernetes API respectively; both are
  tested against fakes only (`internal/response`, `internal/webhook`). Neither has been run against a
  real API server. `go/cmd/flow-consumer` is tested against synthetic Hubble JSON
  (`make poc-pipeline`), not a live `hubble observe` process — its JSON field mapping
  (`go/internal/flow/hubble.go`) is a best-effort guess at Hubble's schema and may need adjusting
  against a real Cilium version's actual output.
- No customer, employer or production data is used anywhere in this repository. All scenarios are
  synthetic.

## License

MIT
