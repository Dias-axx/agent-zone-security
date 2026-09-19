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
the PoCs and tests. `go/cmd/flow-consumer` (Go, per the language split — see
"Go components" below) parses real `hubble observe -o json` line shape into the
same normalised schema and pipes it into `detection/consume_stream.py`, which
evaluates it against the same rules. `poc/scenario_hubble_pipeline.sh` runs this
whole path — Go binary piped into the Python module — for real, against
synthetic-but-realistic Hubble JSON, and its `AGT-ZONE-001` output is real
command output, not a fabricated example. What is still missing is the other
end of that pipe: nothing in this repo has yet piped in a real, running
cluster's actual `hubble observe` process — that gap is the same one blocking
Phase 2's cluster verification (see "Cluster" below), not a separate problem.

### Go components (`go/`)

Three Go binaries, per the language split (Go 1.22+, `golangci-lint`, `go test`
— no external dependencies, so no `go.sum`/module cache is needed):

- `cmd/flow-consumer`: parses `hubble observe -o json` lines into the common
  normalised event schema (`internal/flow`) and writes them as NDJSON to
  stdout, to be piped into `detection/consume_stream.py`. Unit-tested against
  representative Hubble JSON shapes, including malformed lines.
- `cmd/response-controller`: a CLI running the same
  `alert -> isolate -> revoke -> preserve -> terminate` chain as
  `control/response.py` (`internal/response`), shelling out to `kubectl`
  rather than importing `client-go`, kept dependency-free and testable via a
  fake `Runner` in tests. Dry-run by default; only `--dry-run=false` reaches
  `kubectl`.
- `cmd/admission-webhook`: a `ValidatingAdmissionWebhook` (`internal/webhook`)
  checking a pod's `agent-zone-control/zone` annotation against its
  namespace's `zone` label — the runtime mirror of the registry/policy zone
  check `control/validate.py` does at authoring time. Complements, not
  replaces, `deploy/k8s/50-kyverno-pod-hardening.yaml`.

**Status**: all three build, vet clean, and pass `golangci-lint` and their own
`go test` suites (17 tests) against mocked `kubectl`/Kubernetes API calls and
synthetic Hubble JSON — none of that required a live cluster. What has NOT been
done: running `response-controller` or `admission-webhook` against a real
Kubernetes API server, and running `flow-consumer` against a real `hubble`
process's output rather than a synthetic fixture. Both depend on the same live
cluster gap Phase 2 hit (see below).

### Egress gateway (`deploy/mitmproxy/`)

A mitmproxy-based TLS-terminating forward proxy replacing the earlier nginx
placeholder. `deploy/mitmproxy/policy_addon.py` imports
`control.policy_engine.evaluate_egress` directly — the same egress-allowlist
code every other enforcement point uses, not a second implementation — keyed
by an `X-Agent-Id` request header. See
`docs/adr/0002-tls-terminating-egress-gateway.md` for why mitmproxy over
Envoy and the named follow-ups (mTLS agent identity, CA trust distribution).

**Status**: `evaluate_request()` is unit-tested directly
(`tests/test_mitmproxy_addon.py`). The image (`deploy/mitmproxy/Dockerfile`)
was built and run as a standalone container in this repo's build session —
real proxied HTTP requests through the running mitmproxy process produced
real allow/deny decisions (captured in the ADR), including a fail-closed
deny for an unrecognised agent id and an actual killed connection for a
denied destination. Building it caught a real bug (PyYAML isn't bundled in
the mitmproxy base image), fixed in the Dockerfile. Not yet done: deploying
it into the k3d/Cilium cluster from Phase 2 (still blocked — see below) to
confirm the NetworkPolicy-restricted reachability and Hubble/audit-log
integration end to end.

### Cluster (`deploy/`)

`deploy/k3d/cluster.yaml` defines a k3d cluster with the default CNI (flannel)
and k3s's built-in NetworkPolicy controller disabled, so Cilium is installed
separately (`make cluster-up`, via Helm) as the sole owner of the dataplane and
policy enforcement. `deploy/k8s/` defines the zones as namespaces
(`agent-restricted`, `deploy-staging`, `corp-prod`, `egress-gateway`), a
default-deny `NetworkPolicy` per zone, an explicit DNS allow, an egress-gateway
placeholder pod that is the only non-DNS destination agent zones may reach, the
`deploy-staging` cross-zone allow mirroring `policy/examples/deploy-agent.yaml`'s
`zones.reachable`, and two Kyverno `ClusterPolicy` resources for pod-hardening
checks the Pod Security Standard alone does not cover (owner/role label
provenance).

**Verification status, stated plainly**: in the sandbox this repository was
built in, `k3d cluster create` succeeds and `helm install cilium` deploys
without error, but no pod — Cilium's own DaemonSet included — ever reaches
`Running`. The container runtime fails every CRI pod-sandbox creation with:

```
failed to create containerd task: failed to create shim task: OCI runtime
create failed: runc create failed: unable to start container process:
can't get final child's PID from pipe: EOF: unknown
```

Diagnosis performed in that session: image pulls initially failed on
certificate verification (the nested node containers did not trust the
sandbox's TLS-intercepting proxy CA — fixed by installing the CA bundle into
each node container and restarting it). After that fix, a bare `runc run`
invoked directly inside the k3d node container succeeds end to end (including
a fresh network namespace), but the same node's containerd, going through the
full CRI pod-sandbox path, fails consistently and immediately on every pod,
including a plain `pause` container. That gap — bare `runc` works, CRI-driven
`runc` does not — points at something specific to the OCI spec containerd
generates (cgroup path assignment or a seccomp/security profile difference)
colliding with a restriction imposed above Docker in that sandbox, not at a
mistake in the k3d/Cilium configuration itself. This was not chased further
within the session's time budget once the failure reproduced identically
across a clean pod recreation.

**What this means for the manifests in this repo**: `deploy/k3d/cluster.yaml`
and `deploy/k8s/*.yaml` are believed correct against the acceptance criterion
(a cross-zone connection attempt should produce a `DROPPED` Hubble flow and
`AGT-ZONE-001` should fire against it — see `poc/scenario_zone_cluster.sh`),
but that belief has NOT been confirmed by actually running them successfully.
Run `make cluster-up && make deploy && make poc-cluster` on real infrastructure
(a VM, bare metal, or a CI runner with full nested-container support, e.g. a
GitHub Actions Ubuntu runner) to get the actual proof. Treat any claim that
Phase 2 "works" as unverified until that command has produced real
`hubble observe` output — this file will be updated with that output once it
exists.

**Status**: manifests and cluster config written; cluster creation and Cilium
Helm install verified; pod scheduling / live Hubble flow verification blocked
in the build environment and not yet done anywhere else.

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
