#!/usr/bin/env bash
# PoC (pipeline): the real Go flow-consumer piped into the real Python detection
# engine, fed synthetic-but-realistic `hubble observe -o json` lines. This is
# NOT a live-cluster proof (see poc/scenario_zone_cluster.sh and
# docs/architecture.md for that gap) — it is the actual, runnable proof that
# the Go->Python boundary described in go/cmd/flow-consumer/main.go's header
# comment works: a DROPPED cross-zone flow, in Hubble's own JSON shape, ends up
# firing AGT-ZONE-001 in detection/rules/zone-cross.yaml.
#
# Requires: Go toolchain (go build) and the project's Python venv active.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$(mktemp -d)/flow-consumer"

echo "==> Building flow-consumer"
(cd "$REPO_ROOT/go" && go build -o "$BIN" ./cmd/flow-consumer)

echo "==> Feeding synthetic Hubble JSON through flow-consumer | detection.consume_stream"
OUTPUT=$(printf '%s\n%s\n%s\n' \
  '{"flow":{"verdict":"DROPPED","source":{"namespace":"agent-restricted","pod_name":"agent-probe","labels":["k8s:agent_id=agt-log-reader-001"]},"destination":{"namespace":"corp-prod","pod_name":"corp-prod-target"}}}' \
  'garbage line that is not valid hubble json' \
  '{"flow":{"verdict":"FORWARDED","source":{"namespace":"agent-restricted","labels":[]},"destination":{"namespace":"agent-restricted"}}}' \
  | "$BIN" 2>/tmp/flow-consumer-stderr.log \
  | (cd "$REPO_ROOT" && python -m detection.consume_stream))

echo "$OUTPUT"

if ! echo "$OUTPUT" | grep -q "AGT-ZONE-001"; then
  echo "FAIL: expected AGT-ZONE-001 to fire on the synthetic DROPPED cross-zone flow" >&2
  exit 1
fi

echo "PASS: Go flow-consumer -> Python detection engine pipeline fires AGT-ZONE-001 on synthetic Hubble input"
