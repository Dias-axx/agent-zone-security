# ADR 0001: Cilium over Calico for the Phase 2 cluster CNI

**Status**: Proposed (Phase 2 — k3d/Cilium cluster — is not implemented yet; this
decision is recorded ahead of that work so the choice and its cost are on record
before the cluster manifests are written).

## Context

Phase 2 of the build order requires a k3d cluster with a CNI that enforces
per-namespace (per-zone) `NetworkPolicy` and produces flow-level visibility for
the detection engine to consume. Both Cilium and Calico support standard
Kubernetes `NetworkPolicy` and can enforce default-deny egress per namespace.

## Decision

Use Cilium, with Hubble enabled for flow observability.

## Rationale

- Hubble gives per-flow `ALLOWED`/`DROPPED` verdicts with pod/namespace identity
  attached, which is exactly the "blocked attempt" signal the README's detection
  philosophy is built on ("a blocked attempt is worth more than a successful
  request"). Calico's flow logging (Felix/Typha) exists but is not as directly
  positioned for this use case out of the box.
- Cilium's eBPF datapath is the natural next step for the deferred TLS/SNI-aware
  egress control mentioned in the README's known limitations — Calico would need
  a different extension path to get there.
- Both projects are CNCF graduated and comparably mature for the default-deny
  NetworkPolicy behaviour this project actually depends on today; the deciding
  factor is the flow-visibility and future eBPF path, not baseline policy
  enforcement, which either would provide.

## Cost / trade-off

- Cilium has a steeper initial setup than Calico in a k3d context (disabling the
  default CNI, installing via Helm, enabling Hubble as a separate step).
- This is a single-cluster reference implementation, not a fleet — Cilium's
  operational complexity at scale (cluster mesh, multi-cluster Hubble relay) is
  not exercised here and should not be read as validated by this repo.

## Consequences

- `deploy/k3d/cluster.yaml` (Phase 2, not yet written) must disable the default
  k3d CNI (`--disable-network-policy` / flannel) before installing Cilium.
- Detection rule `AGT-ZONE-001` is expected to fire against real Hubble
  `DROPPED` flows once Phase 2 lands (see `docs/architecture.md`), not only
  against the policy engine's own synthetic verdicts as it does today.
