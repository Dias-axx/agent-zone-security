#!/usr/bin/env bash
# PoC (cluster): cross-zone containment on a real Cilium dataplane.
#
# Companion to poc/scenario_zone.py, which proves AGT-ZONE-001 against the policy
# engine's own synthetic Verdict. This script proves the same boundary at the
# network layer: agent-probe (agent-restricted) has no NetworkPolicy allowing it
# into corp-prod (see deploy/k8s/10-default-deny.yaml), so the connection attempt
# must fail, and `hubble observe` must show a DROPPED flow for it.
#
# Requires: make cluster-up && make deploy (see Makefile).
#
# NOTE ON VERIFICATION STATUS: this script was authored and is believed correct
# against the manifests in deploy/k8s/, but has NOT been exercised end-to-end in
# the environment this repo was built in — that sandbox's nested containerd/runc
# stack fails to start ANY CRI pod sandbox (see docs/architecture.md, "Known
# limitations" in README), so no cilium/hubble pod ever reached Running there.
# Run it yourself on real infra (a VM, bare metal, or a CI runner with full nested
# container support) and treat its output as the actual proof, not this comment.

set -euo pipefail

NAMESPACE_SRC="agent-restricted"
POD_SRC="agent-probe"
TARGET_URL="http://corp-prod-target.corp-prod.svc.cluster.local:8080"

echo "==> Waiting for agent-probe to be Ready"
kubectl -n "$NAMESPACE_SRC" wait --for=condition=Ready pod/"$POD_SRC" --timeout=120s

echo "==> Confirming home-zone egress still works (egress gateway reachable)"
if kubectl -n "$NAMESPACE_SRC" exec "$POD_SRC" -- curl -sS -m 5 -o /dev/null -w "%{http_code}\n" \
    http://egress-gateway.egress-gateway.svc.cluster.local:8080; then
  echo "PASS: egress gateway reachable from home zone"
else
  echo "FAIL: expected egress gateway to be reachable from home zone" >&2
  exit 1
fi

echo "==> Attempting cross-zone connection into corp-prod (expected to fail)"
if kubectl -n "$NAMESPACE_SRC" exec "$POD_SRC" -- curl -sS -m 5 -o /dev/null -w "%{http_code}\n" "$TARGET_URL"; then
  echo "FAIL: expected cross-zone connection into corp-prod to be blocked, but it succeeded" >&2
  exit 1
else
  echo "Cross-zone connection failed as expected (connection blocked by NetworkPolicy)"
fi

echo "==> Checking hubble observe for a DROPPED flow toward corp-prod"
DROPPED_FLOW=$(kubectl -n kube-system exec deploy/hubble-relay -- hubble observe \
  --namespace corp-prod --verdict DROPPED --last 20 --output json 2>/dev/null || true)

if [ -z "$DROPPED_FLOW" ]; then
  echo "FAIL: expected at least one DROPPED flow toward corp-prod in hubble observe" >&2
  exit 1
fi

echo "$DROPPED_FLOW"
echo "PASS: cross-zone attempt blocked by NetworkPolicy and visible as a DROPPED Hubble flow"
echo "This is where detection/normalise.py:from_hubble_flow() would classify the event and"
echo "detection/rules/zone-cross.yaml (AGT-ZONE-001) would fire against it in a live pipeline."
