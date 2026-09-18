package flow

import (
	"strings"
	"testing"
)

func TestParseHubbleLineDroppedCrossZone(t *testing.T) {
	line := []byte(`{"flow":{"verdict":"DROPPED","source":{"namespace":"agent-restricted","pod_name":"agent-probe","labels":["k8s:agent_id=agt-log-reader-001"]},"destination":{"namespace":"corp-prod","pod_name":"corp-prod-target"}}}`)

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
		t.Errorf("agent_id = %q, want unknown (no agent_id label present)", event.AgentID)
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
