# Live verification runbook: Phase 2/3 on real infrastructure

This repo's Phase 2 (k3d + Cilium cluster) and Phase 3 (Go flow-consumer /
response-controller / admission-webhook against a live cluster) were written
and unit-tested but never confirmed running end to end — the sandbox this
repo was built in fails every CRI pod-sandbox creation (`runc create failed:
... can't get final child's PID from pipe: EOF`) once containerd, not a bare
`runc run`, drives it. See `docs/architecture.md` for the full diagnosis.

This runbook is what to run on infrastructure that does not have that
limitation, to get the actual proof the README and ADR currently mark as
missing.

---

## 1. Prerequisites

| Requirement | Why | How to check |
|---|---|---|
| Linux x86_64 or arm64, kernel 5.8+ | k3d/Cilium baseline | `uname -a` |
| **cgroup v2 unified hierarchy** | The build sandbox had cgroup v1 hybrid; that is the leading suspect for the pod-sandbox failure. A real VM or a GitHub Actions `ubuntu-latest` runner both default to cgroup v2 today | `cat /sys/fs/cgroup/cgroup.controllers` — must print a list, not "No such file or directory" |
| Docker Engine, running, **not** already nested inside another container without `--privileged` | k3d creates its nodes as Docker containers | `docker info` succeeds |
| 2 vCPU / 4 GB RAM free, minimum | k3d server+agent node, Cilium agent+operator+envoy, Hubble relay, egress-gateway, test pods | — |
| Outbound access to `docker.io`, `ghcr.io`, `quay.io` (or a configured mirror) | k3s, Cilium, and test pod images | `docker pull rancher/k3s:v1.31.5-k3s1` |
| `kubectl`, `helm`, `k3d` (v5.8+), Go 1.24+, Python 3.12+ | tooling this repo's Makefile shells out to | `kubectl version --client`, `helm version`, `k3d version`, `go version`, `python3 --version` |

If you're behind a corporate TLS-intercepting proxy, install its CA into
Docker's and the k3d node containers' trust stores **before** `cluster-up` —
this repo's build session lost significant time to exactly that (see
`docs/architecture.md`), and it's a one-time fix, not a per-run one.

## 2. Get the code

```bash
git clone https://github.com/Dias-axx/agent-zone-security.git
cd agent-zone-security
git checkout claude/agent-zone-control-tkmxlw   # or the merged main, once PR #2 lands
```

## 3. Sanity check the parts that don't need a cluster (fast, ~10s)

Do this first — if these fail, a cluster won't help and the problem is
environment-specific to your machine, not the cluster.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

ruff check . && mypy && pytest -q && python -m control.validate && make poc
make go-check          # gofmt, go vet, golangci-lint, go test, go build
make poc-pipeline       # Go flow-consumer -> Python detection engine, synthetic input
```

Expected: `44 passed` (Python) or more if tests were added since, all 5 PoCs
print `PASS`, `make poc-pipeline` prints `AGT-ZONE-001` firing and `PASS`.

## 4. Bring up the cluster

```bash
make cluster-up
```

This runs `k3d cluster create --config deploy/k3d/cluster.yaml` (default CNI
disabled) then installs Cilium 1.16.5 with Hubble via Helm, and waits on
`kubectl -n kube-system rollout status daemonset/cilium --timeout=300s`.

**Checkpoint — this is exactly where the build sandbox failed:**

```bash
kubectl get pods -n kube-system
```

Every pod should reach `Running` within a few minutes. If any pod is stuck in
`ContainerCreating` past ~2 minutes, check:

```bash
kubectl get events -n kube-system --sort-by=.lastTimestamp | tail -20
```

- `x509: certificate signed by unknown authority` → a TLS-intercepting proxy
  is in the path and its CA isn't trusted inside the k3d node containers. Fix
  per the note in §1, then `docker restart` the `k3d-agent-zone-control-*`
  containers (cert trust is cached per-process, a running k3s/containerd
  won't pick up a newly-appended CA without a restart).
- `runc create failed: ... can't get final child's PID from pipe: EOF` → the
  same nested-container limitation this repo's build session hit. If this
  reproduces on infra you expected to support nested containers, that is
  itself a useful, reportable finding — please open an issue with `uname -a`,
  `docker info`, and cgroup mode, so `docs/architecture.md` can be corrected
  with a real root cause instead of a suspicion.

## 5. Deploy the zones and test fixtures

```bash
make deploy
kubectl get pods -n agent-restricted -n corp-prod -n egress-gateway
```

Expected: `agent-probe` (agent-restricted), `corp-prod-target`
(corp-prod), and the `egress-gateway` deployment's pod all `Running`.

Kyverno policies (`deploy/k8s/50-kyverno-pod-hardening.yaml`) need the
Kyverno controller installed separately — not required for the containment
PoC below:

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
kubectl apply -f deploy/k8s/50-kyverno-pod-hardening.yaml
```

## 6. Run the acceptance PoC

```bash
make poc-cluster
```

This is `poc/scenario_zone_cluster.sh`: confirms `agent-probe` can still
reach the egress gateway (home-zone egress works), confirms a direct
connection into `corp-prod` fails, then checks `hubble observe` for a
`DROPPED` flow toward `corp-prod` and prints it.

**Expected real output** (this is the artifact to capture and paste into
`docs/architecture.md`'s "Cluster" section, replacing the "not yet done"
language — do not paraphrase it, use kubectl/hubble's actual output):

- The `curl` into the egress gateway: an HTTP status line, connection
  succeeds.
- The `curl` into `corp-prod-target`: a timeout/connection-refused (the
  script treats this as expected and does not fail on it).
- `hubble observe --namespace corp-prod --verdict DROPPED --last 20 --output
  json`: at least one JSON flow object with `"verdict":"DROPPED"` and
  `"destination":{"namespace":"corp-prod", ...}`.

If it prints `PASS: cross-zone attempt blocked by NetworkPolicy and visible
as a DROPPED Hubble flow`, Phase 2's acceptance criterion (per the handover
spec, §7) is met for real, for the first time.

## 7. Optional: exercise the Go components against the live cluster

None of these were run against a real API server or a real `hubble` process
during this repo's build — that gap is what this section closes.

```bash
# Point kubectl (and therefore response-controller, which shells out to it)
# at this cluster — already done by `k3d cluster create`, confirm with:
kubectl config current-context   # should be k3d-agent-zone-control

# Real Hubble JSON through the real Go binary (not the synthetic fixture
# poc/scenario_hubble_pipeline.sh uses):
go build -o /tmp/flow-consumer ./go/cmd/flow-consumer
kubectl -n kube-system exec deploy/hubble-relay -- hubble observe -o json --follow \
  | /tmp/flow-consumer \
  | python -m detection.consume_stream
```

Leave this running, then in another terminal repeat the cross-zone `curl`
from §6's `agent-probe` pod — you should see `AGT-ZONE-001` printed live,
sourced from the actual Hubble Relay this time. **This is the single most
valuable artifact to capture**: it proves `go/internal/flow/hubble.go`'s
JSON field mapping (written against documented shape, never validated
live — see its own doc comment) actually matches a real Cilium version's
output, or tells you exactly which field to fix if it doesn't.

For `response-controller` and `admission-webhook`, both need real RBAC to
act against the cluster (a `NetworkPolicy` apply / pod delete, and a
webhook TLS cert + `ValidatingWebhookConfiguration` registration
respectively) that this runbook does not provision — treat wiring those up
as its own follow-up, not a five-minute check.

## 8. Tear down

```bash
make cluster-down
```

Deletes the k3d cluster and its network/volumes. Nothing outside Docker's
own state is touched — no changes are made to the host beyond what `docker`
itself tracks.

## 9. What to update afterward

Whichever of the above actually ran, update — with the real output, not a
paraphrase:

- `docs/architecture.md`'s "Cluster" and "Go components" verification-status
  paragraphs
- `docs/adr/0001-cilium-over-calico.md`'s status line
- `README.md`'s Phase status table and the "Cluster (Phase 2, unverified)"
  quick-start section
- If `go/internal/flow/hubble.go`'s JSON shape needed correcting: its own
  doc comment, which explicitly asks for this
