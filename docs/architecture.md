# Architecture

See the README for the top-level ASCII diagram. This document describes the
responsibilities of each component and the current implementation status.

## Components

### Agent Registry (`registry/agents.yaml`)

The admission gate input. Every agent must have an accountable `owner`, and every
delegated agent must have a `delegated_by`. `control/validate.py` fails closed if
either is missing or if the registry's declared `zone` does not match the
referenced policy's `zones.home`.

**Status**: implemented (Phase 1).

### Policy Engine (`control/policy_engine.py`)

The decision point for three request kinds: `tool`, `egress`, `zone`. Pure
functions, no I/O, no network — takes a policy document and a `Request`, returns a
`Verdict`. This is deliberately the smallest, most heavily tested surface in the
repo, because every other component depends on its correctness. See
`docs/threat-model.md` for why the AND gate (delegated identity) is the single
most important behaviour here.

**Status**: implemented (Phase 1).

### Token Issuer (`control/token_issuer.py`)

Issues short-lived, HMAC-signed capability tokens. TTL is bounded by a hard
ceiling (3600s) enforced both here and in the registry validator, so a policy
cannot request a longer-lived token than the system allows. Revocation is
in-memory per `TokenIssuer` instance in this reference implementation — a
production deployment would back this with a shared revocation store (e.g. Redis)
so revocation is visible across all enforcement points, not just the process that
issued the token.

**Status**: implemented (Phase 1), single-process only.

### Audit Log (`control/audit.py`)

Append-only JSONL. Every policy evaluation is recorded, including allows — this is
what makes "prove this agent's action history" possible after the fact. The record
schema is stable so a SIEM forwarder can be attached without a schema change.

**Status**: implemented (Phase 1), local file backend only.

### Response Chain (`control/response.py`)

`alert → isolate → revoke → preserve → terminate`, in that fixed order. All
actions are dry-run/simulated in Phase 1-2. Wiring `isolate` to a real
`NetworkPolicy` apply, `revoke` to the live token issuer, and `terminate` to a pod
delete is Phase 3 scope (the Go response controller).

**Status**: logic and ordering implemented (Phase 1-2); not wired to a live
cluster yet.

### Mock Agents (`agents/`)

Deterministic, scripted agents used so PoC scenarios are reproducible in CI with
no network access and no model API cost. `agents/adapters/llm.py` is an optional,
import-guarded adapter for a real model API — never a hard dependency.

**Status**: implemented (Phase 1).

### Detection (`detection/`)

`normalise.py` maps heterogeneous event sources (Hubble flow, egress proxy log,
OTel tool trace, Vault audit log) into one schema. `engine.py` evaluates
declarative YAML rules (`detection/rules/*.yaml`) against that schema using a
restricted AST-based expression evaluator — never Python's `eval`.

**Status**: rule evaluation against synthetic events is implemented and covered by
the PoCs and tests. Live ingestion from an actual Hubble/OTel/Vault pipeline is
Phase 3 scope — the normaliser functions exist and are unit-tested against
representative payload shapes, but nothing in this repo yet consumes a real
running cluster's event stream.

### Cluster (`deploy/`)

Not implemented in this pass. Per the build order, Phase 2 (k3d + Cilium, zone
NetworkPolicies, egress gateway, admission control) has to land before Phase 3
(a real Go response controller and live detection) makes sense, and both are
explicitly out of scope for this iteration to avoid partially-wired
infrastructure that cannot be exercised end to end. See `docs/adr/` for the
Cilium-over-Calico decision, recorded ahead of that implementation.

**Status**: planned.

## Data flow (steady state, once Phase 2/3 land)

1. Agent registry + policy define what an agent may do.
2. Every tool call, egress attempt and zone traversal goes through the policy
   engine before it is permitted.
3. The engine's verdict is recorded to the audit log, regardless of outcome.
4. Network-level enforcement (Cilium NetworkPolicy, egress gateway) independently
   enforces the same boundaries at the infrastructure layer — the policy engine's
   decision and the network's enforcement should agree; where they diverge, that
   divergence is itself a detection signal (a `DENIED` Hubble flow for a call the
   policy engine believed was in scope, or vice versa, points at a config drift
   bug worth investigating).
5. The detection engine normalises and evaluates events from all these sources.
6. A confirmed violation drives the response chain, whose depth is per-role
   (`response.on_violation`), not a global default.
