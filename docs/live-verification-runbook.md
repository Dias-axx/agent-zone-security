# Live verification runbook: Phase 2/3 on real infrastructure

**Update: the core Phase 2 acceptance criterion has been confirmed** — this
runbook was followed end to end on a Windows machine with Docker Desktop
(k3d v5.8.3, Cilium 1.16.5, Go 1.27.1). Every pod reached `Running`, a
cross-zone connection attempt timed out, and `hubble observe` showed the real
`DROPPED` flow with `AGT-ZONE-001` firing against it — see
`docs/architecture.md`'s "Cluster" section for the captured output. This
repo's own build sandbox fails every CRI pod-sandbox creation (`runc create
failed: ... can't get final child's PID from pipe: EOF`) once containerd,
not a bare `runc run`, drives it — that turned out to be specific to that
sandbox, not the k3d/Cilium configuration.

**Update 2: the egress gateway is also confirmed** — built with
`make egress-gateway-image-import` (`k3d image import`, no registry needed)
and deployed via `deploy/k8s/30-egress-gateway.yaml` into the same cluster.
A real request from `agent-probe` through the in-cluster gateway with a
valid `X-Agent-Id` header produced `verdict: allow` for its allowed
destination and `verdict: deny` for a disallowed one, plus a fail-closed
`deny` with no header at all — see
`docs/adr/0002-tls-terminating-egress-gateway.md` for the captured output.

Not yet exercised live: the Kyverno admission policies, and the Go
`response-controller`/`admission-webhook` against a real API server. This
runbook remains the reference for doing those, and for reproducing the
confirmed parts yourself.

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
- **On Windows with Docker Desktop specifically**: `kubectl`/`helm` may time
  out reaching `https://host.docker.internal:6550` even though the cluster is
  up and the port is genuinely published (`docker ps` shows
  `0.0.0.0:6550->6443/tcp` on the `*-serverlb` container) — `host.docker.internal`
  can resolve to the host's LAN IP instead of loopback and then time out
  reaching itself. Fix by pointing the kubeconfig at loopback directly
  (confirmed working, k3d's generated cert covers it):
  ```powershell
  kubectl config set-cluster k3d-agent-zone-control --server=https://127.0.0.1:6550
  ```
  This is a local environment quirk, not a cluster or repo problem — nothing
  else needs to change.

## 5. Deploy the zones and test fixtures

Build the egress-gateway image and load it into the k3d cluster's nodes
first — there's no registry, so `k3d image import` replaces a push (the
manifest already points at this local tag with `imagePullPolicy:
IfNotPresent`):

```bash
make egress-gateway-image-import   # requires k3d and docker; runs the docker build then k3d image import
make deploy
kubectl get pods -n agent-restricted -n corp-prod -n egress-gateway
```

Expected: `agent-probe` (agent-restricted), `corp-prod-target`
(corp-prod), and the `egress-gateway` deployment's pod all `Running`. If
`egress-gateway` still shows `ImagePullBackOff`/`ErrImagePull` after this,
confirm the image import actually targeted the right cluster name
(`k3d cluster list`) and that `K3D_CLUSTER_NAME` in the Makefile matches
it.

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

**The `hubble` CLI is not bundled in the `hubble-relay` image** —
`kubectl -n kube-system exec deploy/hubble-relay -- hubble observe ...`
fails with `exec: "hubble": executable file not found in $PATH`. The
verified working method is to port-forward Hubble Relay and run a
separately-installed `hubble` CLI against it:

```bash
kubectl -n kube-system port-forward deploy/hubble-relay 4245:4245 &

# Download the matching CLI release (adjust for your OS/arch — this is the
# real, verified-working release used during the confirmed run):
#   Linux:   https://github.com/cilium/hubble/releases/download/v1.19.4/hubble-linux-amd64.tar.gz
#   Windows: https://github.com/cilium/hubble/releases/download/v1.19.4/hubble-windows-amd64.tar.gz
tar -xzf hubble-<os>-<arch>.tar.gz

./hubble observe --server localhost:4245 --namespace corp-prod \
  --verdict DROPPED --last 20 --output json
```

**Confirmed real output** — this has already been captured and is in
`docs/architecture.md`'s "Cluster" section: `DROPPED` flows with
`"drop_reason_desc":"POLICY_DENIED"`, source `agent-restricted/agent-probe`,
destination `corp-prod/corp-prod-target`, `"traffic_direction":"EGRESS"`.
If you reproduce this, you should see the same shape (verdict, drop reason,
namespaces) even if UUIDs/timestamps/ports differ — no need to re-paste it
into `docs/architecture.md` unless the shape itself differs from what's
documented there, which would indicate a Cilium version-specific change
worth noting.

If it prints `PASS: cross-zone attempt blocked by NetworkPolicy and visible
as a DROPPED Hubble flow`, Phase 2's acceptance criterion (per the handover
spec, §7) is met for real — already confirmed once; this section is now for
reproducing it, not proving it for the first time.

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
sourced from the actual Hubble Relay this time. This has already been done
once (see `docs/architecture.md`'s "Cluster" section and
`go/internal/flow/hubble_test.go`'s `TestParseHubbleLineRealCapturedFlow`),
which confirmed `go/internal/flow/hubble.go`'s JSON field mapping matches
real Cilium 1.16.5 output and also surfaced a real `agent-id`/`agent_id`
label-key mismatch (since fixed). Re-running this is still useful to catch
a field-shape change in a different Cilium version.

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

The core Phase 2 criterion (§4-§6) has already been confirmed and
documented (see the update note at the top of this file). If you exercise
something **not yet covered** — the egress-gateway image, Kyverno
admission policies, or `response-controller`/`admission-webhook` against a
real API server — update, with the real output, not a paraphrase:

- `docs/architecture.md`'s "Cluster" and "Go components" verification-status
  paragraphs
- `docs/adr/0001-cilium-over-calico.md`'s status line
- `README.md`'s Phase status table and the "Cluster" quick-start section
- If `go/internal/flow/hubble.go`'s JSON shape needed correcting: its own
  doc comment, which explicitly asks for this
