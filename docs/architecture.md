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
`AuditLog` dispatches each record to a `JSONLFileSink` (always) plus any configured
`extra_sinks`: `SyslogSink` (stdlib-only, for a syslog-speaking SIEM) and
`control/coding_agent_monitor_sink.py`'s `CodingAgentMonitorSink`, which forwards to
a running [Coding-Agent-Monitor](https://github.com/Dias-axx/coding-agent-monitor)
instance as a live per-agent log line.

**Status**: `JSONLFileSink` implemented and always on (Phase 1).
`CodingAgentMonitorSink` verified end to end in this repo's build session — a real
monitor instance was started, records were written through the real sink over HTTP,
and `GET /api/agents/:id` showed the expected log lines with `allow`→stdout,
`deny`→stderr classification. `SyslogSink` and `RedisRevocationStore` (see Token
Issuer below) are unit-tested against fakes only, not a real collector/Redis. All
three extra sinks/stores are explicitly secondary: `JSONLFileSink` (or a real SIEM
pipeline) stays the source of truth, since Coding-Agent-Monitor is itself
best-effort, in-memory and unauthenticated by its own design.

### Activity dashboard / API (`control/activity_api.py`, `control/activity_reader.py`)

A local, read-only view over the same `JSONLFileSink` file `AuditLog` already
writes: `control/activity_reader.py` holds pure read/filter/aggregate
functions (no I/O beyond reading the file), and `control/activity_api.py`
wraps them in a stdlib `http.server` (no framework dependency, matching
`control/policy_engine.py`'s zero-dependency stance) that serves `GET
/api/agents` (per-agent decision counts and last-seen), `GET /api/activity`
(filterable by `agent_id`, `decision`, `kind`, `since`, `limit`), and a single
embedded HTML dashboard at `/` (auto-refreshing table, no CDN or external
script). It is a second, independent path to the same audit data
`CodingAgentMonitorSink` above forwards live to an external monitor — this
one reads the local file directly and needs no other service running.

**Status**: verified end to end. `tests/test_activity_reader.py` covers the
pure functions (malformed-line tolerance, filtering, aggregation) directly.
`tests/test_activity_api.py` starts a real server on an ephemeral localhost
port, writes real records through an actual `AuditLog`, and asserts the
HTTP responses (`/`, `/api/agents`, `/api/activity`, unfiltered and
filtered, plus a 404 for an unknown path) match what was actually written —
not mocked. A manual run (`python -m control.activity_api --audit-log
...`) against a real audit file confirmed the same via `curl` and produced
correctly aggregated JSON. No authentication; binds to `127.0.0.1` by
default — a local operator tool, not a hardened service (see README's Known
limitations).

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

**Status: confirmed live in-cluster.** `evaluate_request()` is unit-tested
directly (`tests/test_mitmproxy_addon.py`), and beyond the earlier
standalone-container run (real allow/deny decisions, a fail-closed deny for
an unrecognised agent id, a real bug caught — PyYAML not bundled in the base
image, fixed in the Dockerfile — full detail in the ADR), the built image was
loaded into the live k3d/Cilium cluster with `k3d image import` (no registry
needed) and deployed via `deploy/k8s/30-egress-gateway.yaml`, reachable only
from `agent-restricted`/`deploy-staging` by `NetworkPolicy` as designed. A
real proxied request from the actual `agent-probe` pod through the in-cluster
gateway produced the exact same allow/deny/fail-closed decisions as the
standalone run — see `docs/adr/0002-tls-terminating-egress-gateway.md` for
the captured output. Not yet done: TLS interception of an actual HTTPS
request end to end, and automated CA trust distribution to agent pods (both
named follow-ups in the ADR).

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

**Verification status: confirmed live**, on a second machine (Windows 11,
Docker Desktop, k3d v5.8.3, Cilium 1.16.5, Go 1.27.1) after this repo's own
build sandbox hit the containerd/runc limitation described below. Every pod
reached `Running`, including Cilium's own DaemonSet:

```
NAME                                      READY   STATUS    RESTARTS   AGE
cilium-5hzxb                              1/1     Running   0          2m54s
cilium-9jqfx                              1/1     Running   0          2m54s
cilium-envoy-2sb2b                        1/1     Running   0          2m54s
cilium-envoy-7wg59                        1/1     Running   0          2m54s
cilium-operator-6c4fb78954-x68pr          1/1     Running   0          2m54s
coredns-ccb96694c-xms9k                   1/1     Running   0          9m13s
hubble-relay-7b5c9d5cbb-7nwsf             1/1     Running   0          2m54s
local-path-provisioner-5cf85fd84d-rk9b7   1/1     Running   0          9m13s
metrics-server-5985cbc9d7-qsvhr           1/1     Running   0          9m13s
```

`agent-probe` (agent-restricted) attempting to reach `corp-prod-target`
(corp-prod) timed out as expected:

```
curl: (28) Connection timed out after 5002 milliseconds
```

and `hubble observe --namespace corp-prod --verdict DROPPED` showed the real
flow — this is genuine captured output, trimmed to the fields that matter:

```json
{"flow":{"verdict":"DROPPED","drop_reason_desc":"POLICY_DENIED",
 "source":{"namespace":"agent-restricted","pod_name":"agent-probe",
   "labels":["k8s:app=agent-probe","k8s:role=read-only-agent"]},
 "destination":{"namespace":"corp-prod","pod_name":"corp-prod-target"},
 "traffic_direction":"EGRESS","Summary":"TCP Flags: SYN"}}
```

This satisfies the Phase 2 acceptance criterion exactly as written: a
cross-zone connection attempt produces a `DROPPED` Hubble flow. Piping this
real flow shape through the actual `go/cmd/flow-consumer` binary and
`detection/consume_stream.py` confirmed the second half of the criterion —
`AGT-ZONE-001` fires against the real flow, not a synthetic fixture:

```
[AGT-ZONE-001] Cross-zone traversal denied (agent=unknown target=corp-prod verdict=deny)
```

Two real bugs surfaced by this run, both fixed:

1. `host.docker.internal` (the address k3d writes into kubeconfig on Windows)
   resolved to the machine's LAN IP rather than loopback and timed out —
   fixed locally with `kubectl config set-cluster ... --server=https://127.0.0.1:6550`.
   This is an environment quirk, not a repo bug; no manifest change needed.
2. **`agent_id=unknown` above is real and was a genuine bug**:
   `deploy/k8s/40-test-pods.yaml`'s `agent-probe` pod never carried an
   `agent-id` label, and separately, `go/internal/flow/hubble.go`'s
   `agentIDFromLabels` was looking for `agent_id=` (underscore) while
   `go/internal/response/controller.go`'s `isolate()`/`terminate()` already
   used `agent-id` (hyphen) to select pods — two different conventions that
   never agreed with each other. Both fixed: the test pod now carries
   `agent-id: agt-log-reader-001`, and `hubble.go` now matches on `agent-id=`
   throughout, verified with a new test built from this exact captured flow
   shape (`TestParseHubbleLineRealCapturedFlow`).

**What was NOT exercised in this run**: the `egress-gateway` pod stayed
`ImagePullBackOff` at the time (its image had not yet been built/imported),
so only the core zone-containment assertion ran. That gap has since been
closed in a follow-up session on the same cluster — see the "Egress gateway"
section above and the ADR for the real in-cluster allow/deny output. The Go
`response-controller`/`admission-webhook` were still not run against this
live API server either — see "Go components" above.

**Status**: Phase 2's core acceptance criterion (cross-zone attempt → real
`DROPPED` Hubble flow → `AGT-ZONE-001` fires) is confirmed on real
infrastructure. The build sandbox's own containerd/runc limitation
(preserved below for anyone who hits the same wall) turned out to be
sandbox-specific, not a defect in the k3d/Cilium configuration — exactly as
suspected.

<details>
<summary>Original build-sandbox diagnosis (containerd/runc failure, since resolved elsewhere)</summary>

In the sandbox this repository was originally built in, `k3d cluster create`
succeeded and `helm install cilium` deployed without error, but no pod —
Cilium's own DaemonSet included — ever reached `Running`. The container
runtime failed every CRI pod-sandbox creation with:

```
failed to create containerd task: failed to create shim task: OCI runtime
create failed: runc create failed: unable to start container process:
can't get final child's PID from pipe: EOF: unknown
```

Diagnosis performed in that session: image pulls initially failed on
certificate verification (the nested node containers did not trust the
sandbox's TLS-intercepting proxy CA — fixed by installing the CA bundle into
each node container and restarting it). After that fix, a bare `runc run`
invoked directly inside the k3d node container succeeded end to end
(including a fresh network namespace), but the same node's containerd, going
through the full CRI pod-sandbox path, failed consistently and immediately on
every pod, including a plain `pause` container. That gap — bare `runc` works,
CRI-driven `runc` does not — pointed at something specific to the OCI spec
containerd generates (cgroup path assignment or a seccomp/security profile
difference) colliding with a restriction imposed above Docker in that
sandbox. Confirmed by the successful run above: the k3d/Cilium configuration
itself was never the problem.

</details>

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
