.PHONY: validate lint typecheck test poc cluster-up cluster-down deploy poc-cluster

validate:
	python -m control.validate

lint:
	ruff check .

typecheck:
	mypy

test:
	pytest

poc:
	python -m poc.scenario_egress
	python -m poc.scenario_zone
	python -m poc.scenario_and_gate
	python -m poc.scenario_secret_harvest
	python -m poc.scenario_denial_of_wallet

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
