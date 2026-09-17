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
NetworkPolicy, a real forward proxy) shown in the diagram is Phase 2 and not yet
implemented — see [Phase status](#phase-status).

## Control layers

**Prevention**
- Default-deny egress per agent namespace (Cilium `NetworkPolicy`, Phase 2)
- Namespace = zone; cross-zone traffic only via explicit, reviewed policy
- All outbound traffic forced through an egress gateway; direct connections dropped (Phase 2)
- Short-lived, task-scoped capability tokens — never long-lived API keys (`control/token_issuer.py`)
- AND-gate for delegated identity: a delegated agent's effective permission is the
  intersection of its role scope and the scope of the human it acts for, never a
  superset (`control/policy_engine.py`)

**Detection**
- Cilium/Hubble flow logs — every `DENIED` verdict is a high-fidelity signal (Phase 2/3)
- Egress proxy logs — non-allowlisted destinations, abnormal transfer volume (Phase 2/3)
- OpenTelemetry tool-call traces — calls outside the declared role scope (Phase 3)
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
deploy/        k3d/Cilium cluster and Kubernetes manifests (planned, Phase 2)
docs/          threat model, architecture notes, compliance mapping, ADRs
```

## Phase status

| Phase | Scope | State |
|---|---|---|
| 1 | Registry, policy schema + examples, policy engine, mock agents | done |
| 1.5 | Token issuer, audit log, response chain, pytest suite, CI | done |
| 2 | k3d + Cilium, zone isolation, egress gateway, admission control | planned |
| 3 | Detection engine: rule evaluation implemented against synthetic events; live Hubble/OTel/Vault ingestion not yet wired | partial |
| 4 | Compliance mapping (EU AI Act, DORA, ISO 42001, NIST AI RMF, BAIT/MaRisk) | documented, honestly marked partial/documented-only — see `docs/compliance-mapping.md` |

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
- **Single-process token revocation and audit log.** `TokenIssuer` revocation state and the JSONL
  audit log both live in a single process/file in this reference implementation. A production
  deployment needs a shared revocation store and a real log pipeline.
- **No live cluster wiring yet.** The response chain's `isolate`/`terminate` actions are dry-run only;
  the detection engine evaluates rules against synthetic events, not a running Cilium/OTel/Vault
  pipeline. See [Phase status](#phase-status).
- No customer, employer or production data is used anywhere in this repository. All scenarios are
  synthetic.

## License

MIT
