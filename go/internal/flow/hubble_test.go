package flow

import (
	"strings"
	"testing"
)

func TestParseHubbleLineDroppedCrossZone(t *testing.T) {
	line := []byte(`{"flow":{"verdict":"DROPPED","source":{"namespace":"agent-restricted","pod_name":"agent-probe","labels":["k8s:agent-id=agt-log-reader-001"]},"destination":{"namespace":"corp-prod","pod_name":"corp-prod-target"}}}`)

	event, err := ParseHubbleLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Kind != "zone" {
		t.Errorf("kind = %q, want zone", event.Kind)
	}
	if event.Verdict != "deny" {
		t.Errorf("verdict = %q, want deny", event.Verdict)
	}
	if event.Target != "corp-prod" {
		t.Errorf("target = %q, want corp-prod", event.Target)
	}
	if event.AgentID != "agt-log-reader-001" {
		t.Errorf("agent_id = %q, want agt-log-reader-001", event.AgentID)
	}
	if event.Source != "hubble" {
		t.Errorf("source = %q, want hubble", event.Source)
	}
}

func TestParseHubbleLineForwardedAllowed(t *testing.T) {
	line := []byte(`{"flow":{"verdict":"FORWARDED","source":{"namespace":"agent-restricted","labels":[]},"destination":{"namespace":"agent-restricted"}}}`)

	event, err := ParseHubbleLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Verdict != "allow" {
		t.Errorf("verdict = %q, want allow", event.Verdict)
	}
	if event.AgentID != "unknown" {
		t.Errorf("agent_id = %q, want unknown (no agent-id label present)", event.AgentID)
	}
}

func TestParseHubbleLineDoesNotMatchDifferentlyKeyedLabel(t *testing.T) {
	// "parent-agent-id=" contains "agent-id=" as a substring; agentIDFromLabels
	// must not treat that as a match for the "agent-id" key.
	line := []byte(`{"flow":{"verdict":"DROPPED","source":{"namespace":"agent-restricted","labels":["k8s:parent-agent-id=decoy","k8s:agent-id=agt-real-001"]},"destination":{"namespace":"corp-prod"}}}`)

	event, err := ParseHubbleLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.AgentID != "agt-real-001" {
		t.Errorf("agent_id = %q, want agt-real-001 (must not match the parent-agent-id decoy label)", event.AgentID)
	}
}

// TestParseHubbleLineRealCapturedFlow uses an actual `hubble observe -o json`
// line captured from a live k3d + Cilium 1.16.5 cluster (Docker Desktop,
// Windows) running this repo's deploy/k8s/ manifests: agent-probe
// (agent-restricted) attempting to reach corp-prod-target (corp-prod),
// correctly dropped by NetworkPolicy. This is the first real proof this
// parsing logic was ever exercised against a live cluster rather than a
// hand-written fixture — see docs/architecture.md's "Cluster" section for
// the full captured output and context.
func TestParseHubbleLineRealCapturedFlow(t *testing.T) {
	line := []byte(`{"flow":{"time":"2026-09-20T14:56:45.779111730Z","uuid":"2848b6b6-59c0-4be2-8bdc-3a5861de4c68","verdict":"DROPPED","drop_reason":133,"IP":{"source":"10.0.1.116","destination":"10.0.1.117","ipVersion":"IPv4"},"l4":{"TCP":{"source_port":38160,"destination_port":8080,"flags":{"SYN":true}}},"source":{"ID":4070,"identity":60176,"namespace":"agent-restricted","labels":["k8s:app=agent-probe","k8s:agent-id=agt-log-reader-001","k8s:role=read-only-agent"],"pod_name":"agent-probe"},"destination":{"ID":2376,"identity":10337,"namespace":"corp-prod","labels":["k8s:app=corp-prod-target"],"pod_name":"corp-prod-target"},"Type":"L3_L4","node_name":"k3d-agent-zone-control-agent-0","traffic_direction":"EGRESS","drop_reason_desc":"POLICY_DENIED","Summary":"TCP Flags: SYN"},"node_name":"k3d-agent-zone-control-agent-0","time":"2026-09-20T14:56:45.779111730Z"}`)

	event, err := ParseHubbleLine(line)
	if err != nil {
		t.Fatalf("unexpected error parsing a real captured flow: %v", err)
	}
	if event.Kind != "zone" || event.Verdict != "deny" || event.Target != "corp-prod" {
		t.Errorf("event = %+v, want kind=zone verdict=deny target=corp-prod", event)
	}
	if event.AgentID != "agt-log-reader-001" {
		t.Errorf("agent_id = %q, want agt-log-reader-001 (with the agent-id label present)", event.AgentID)
	}
}

func TestParseHubbleLineMalformedJSON(t *testing.T) {
	if _, err := ParseHubbleLine([]byte("not json")); err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}

func TestParseHubbleLineMissingEndpoints(t *testing.T) {
	if _, err := ParseHubbleLine([]byte(`{"flow":{"verdict":"DROPPED"}}`)); err == nil {
		t.Fatal("expected an error for a flow missing source/destination, got nil")
	}
}

func TestStreamHubbleLinesSkipsBadLinesAndEmitsGoodOnes(t *testing.T) {
	input := strings.Join([]string{
		`{"flow":{"verdict":"DROPPED","source":{"namespace":"agent-restricted","labels":[]},"destination":{"namespace":"corp-prod"}}}`,
		`not json at all`,
		`{"flow":{"verdict":"FORWARDED","source":{"namespace":"agent-restricted","labels":[]},"destination":{"namespace":"agent-restricted"}}}`,
	}, "\n")

	var badLines int
	events := StreamHubbleLines(strings.NewReader(input), func(_ []byte, _ error) {
		badLines++
	})

	var received []Normalized
	for event := range events {
		received = append(received, event)
	}

	if badLines != 1 {
		t.Errorf("badLines = %d, want 1", badLines)
	}
	if len(received) != 2 {
		t.Fatalf("received %d events, want 2", len(received))
	}
	if received[0].Verdict != "deny" || received[1].Verdict != "allow" {
		t.Errorf("unexpected verdicts: %+v", received)
	}
}
