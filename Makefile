.PHONY: validate lint typecheck test poc poc-pipeline cluster-up cluster-down deploy \
	poc-cluster egress-gateway-image egress-gateway-image-import activity-api \
	go-fmt go-vet go-lint go-test go-build go-check

validate:
	python -m control.validate

lint:
	ruff check .

typecheck:
	mypy

test:
	pytest

# Local read-only GUI/API over the audit log (control/audit.py). Point
# AUDIT_LOG at the same path your AuditLog(path) instance writes to (defaults
# to audit.jsonl in the repo root, matching no real default — set it
# explicitly for anything beyond a quick local look).
AUDIT_LOG ?= audit.jsonl

activity-api:
	python -m control.activity_api --audit-log $(AUDIT_LOG)

poc:
	python -m poc.scenario_egress
	python -m poc.scenario_zone
	python -m poc.scenario_and_gate
	python -m poc.scenario_secret_harvest
	python -m poc.scenario_denial_of_wallet
	python -m poc.scenario_tool_output_anomaly

# Go->Python pipeline PoC (Phase 3): builds go/cmd/flow-consumer and pipes
# synthetic Hubble-shaped JSON through it into detection.consume_stream.
# Verified against synthetic input only — see poc-cluster for the live-cluster
# gap and docs/architecture.md.
poc-pipeline:
	./poc/scenario_hubble_pipeline.sh

# Go component checks (go/). No external dependencies, so no go.sum/module
# cache is needed.
go-fmt:
	cd go && test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

go-vet:
	cd go && go vet ./...

go-lint:
	cd go && golangci-lint run ./...

go-test:
	cd go && go test ./...

go-build:
	cd go && go build ./...

go-check: go-fmt go-vet go-lint go-test go-build

# Phase 2: k3d + Cilium cluster. Verified up through cluster creation and Cilium's
# control-plane images installing via Helm; pod-sandbox scheduling (Cilium's own
# DaemonSet included) has NOT been verified end to end in every environment — see
# docs/architecture.md "Known limitations" before relying on cluster-up/deploy in a
# constrained or nested-container sandbox.
CILIUM_VERSION := 1.16.5
K3S_IMAGE := rancher/k3s:v1.31.5-k3s1

cluster-up:
	k3d cluster create --config deploy/k3d/cluster.yaml
	helm repo add cilium https://helm.cilium.io/ --force-update
	helm repo update cilium
	helm install cilium cilium/cilium --version $(CILIUM_VERSION) \
		--namespace kube-system \
		--set hubble.enabled=true \
		--set hubble.relay.enabled=true \
		--set hubble.ui.enabled=false \
		--set operator.replicas=1
	@echo "Waiting for Cilium to report Ready (kubectl -n kube-system rollout status daemonset/cilium)..."
	kubectl -n kube-system rollout status daemonset/cilium --timeout=300s

cluster-down:
	k3d cluster delete agent-zone-control

deploy:
	kubectl apply -f deploy/k8s/00-namespaces.yaml
	kubectl apply -f deploy/k8s/10-default-deny.yaml
	kubectl apply -f deploy/k8s/20-allow-dns.yaml
	kubectl apply -f deploy/k8s/30-egress-gateway.yaml
	kubectl apply -f deploy/k8s/31-allow-egress-gateway.yaml
	kubectl apply -f deploy/k8s/32-zone-deploy-staging.yaml
	kubectl apply -f deploy/k8s/40-test-pods.yaml
	@echo "Kyverno policies (deploy/k8s/50-kyverno-pod-hardening.yaml) require the Kyverno"
	@echo "controller installed separately — see the comment header in that file."

poc-cluster:
	./poc/scenario_zone_cluster.sh

# Builds the TLS-terminating egress gateway image (mitmproxy + this repo's own
# policy engine, see deploy/mitmproxy/). deploy/k8s/30-egress-gateway.yaml
# already points at this exact local tag with imagePullPolicy: IfNotPresent,
# so for a k3d cluster `make egress-gateway-image-import` (below) is enough —
# no registry push needed. Built and run standalone (not yet in-cluster) in
# this repo's build session with real allow/deny output captured — see
# docs/adr/0002-tls-terminating-egress-gateway.md.
EGRESS_GATEWAY_IMAGE := agent-zone-control-egress-gateway:latest
K3D_CLUSTER_NAME := agent-zone-control

egress-gateway-image:
	docker build -f deploy/mitmproxy/Dockerfile -t $(EGRESS_GATEWAY_IMAGE) .

# Loads the built image directly into the k3d cluster's node containers, so
# `make deploy` can run it without a registry.
egress-gateway-image-import: egress-gateway-image
	k3d image import $(EGRESS_GATEWAY_IMAGE) -c $(K3D_CLUSTER_NAME)
