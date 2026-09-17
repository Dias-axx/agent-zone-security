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

# Phase 2 (planned): k3d + Cilium cluster. Not implemented yet — see docs/architecture.md.
cluster-up:
	@echo "Phase 2 not implemented yet: k3d/Cilium cluster bring-up is planned, see docs/architecture.md" >&2
	@exit 1

cluster-down:
	@echo "Phase 2 not implemented yet" >&2
	@exit 1

deploy:
	@echo "Phase 2 not implemented yet" >&2
	@exit 1

poc-cluster:
	@echo "Phase 2 not implemented yet" >&2
	@exit 1
