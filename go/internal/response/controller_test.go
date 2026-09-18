package response

import (
	"context"
	"errors"
	"testing"
)

type fakeRunner struct {
	calls [][]string
	stdin []string
	err   error
}

func (f *fakeRunner) Run(_ context.Context, stdin string, args ...string) (string, error) {
	f.calls = append(f.calls, args)
	f.stdin = append(f.stdin, stdin)
	return "", f.err
}

func TestEscalateAlertOnlyChain(t *testing.T) {
	c := NewController(&fakeRunner{}, "agent-restricted")
	events, err := c.Escalate(context.Background(), "agt-1", "tok-1", "alert", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 || events[0].Action != ActionAlert {
		t.Fatalf("events = %+v, want single alert", events)
	}
}

func TestEscalateTerminateChainOrderingPreservesBeforeTerminate(t *testing.T) {
	c := NewController(&fakeRunner{}, "agent-restricted")
	events, err := c.Escalate(context.Background(), "agt-1", "tok-1", "terminate", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantOrder := []Action{ActionAlert, ActionIsolate, ActionRevoke, ActionPreserve, ActionTerminate}
	if len(events) != len(wantOrder) {
		t.Fatalf("got %d events, want %d", len(events), len(wantOrder))
	}
	for i, want := range wantOrder {
		if events[i].Action != want {
			t.Errorf("events[%d].Action = %q, want %q", i, events[i].Action, want)
		}
	}
}

func TestEscalateUnknownOnViolationErrors(t *testing.T) {
	c := NewController(&fakeRunner{}, "agent-restricted")
	if _, err := c.Escalate(context.Background(), "agt-1", "tok-1", "nonsense", true); err == nil {
		t.Fatal("expected an error for an unknown on_violation value, got nil")
	}
}

func TestEscalateDryRunNeverCallsRunner(t *testing.T) {
	runner := &fakeRunner{}
	c := NewController(runner, "agent-restricted")
	if _, err := c.Escalate(context.Background(), "agt-1", "tok-1", "terminate", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("dry_run=true called the runner %d times, want 0", len(runner.calls))
	}
}

func TestEscalateLiveCallsIsolateAndTerminate(t *testing.T) {
	runner := &fakeRunner{}
	c := NewController(runner, "agent-restricted")
	events, err := c.Escalate(context.Background(), "agt-1", "tok-1", "terminate", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, e := range events {
		if e.DryRun {
			t.Errorf("event %+v has DryRun=true, want false for a live escalation", e)
		}
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner called %d times, want 2 (isolate apply + terminate delete)", len(runner.calls))
	}
	if runner.calls[0][0] != "apply" {
		t.Errorf("first call = %v, want apply (isolate)", runner.calls[0])
	}
	if runner.stdin[0] == "" {
		t.Error("isolate's apply call carried no manifest on stdin")
	}
	if runner.calls[1][0] != "delete" {
		t.Errorf("second call = %v, want delete (terminate)", runner.calls[1])
	}
}

func TestEscalateLiveIsolateFailureIsReportedNotPanicked(t *testing.T) {
	runner := &fakeRunner{err: errors.New("boom")}
	c := NewController(runner, "agent-restricted")
	events, err := c.Escalate(context.Background(), "agt-1", "tok-1", "isolate", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	isolateEvent := events[1]
	if isolateEvent.Action != ActionIsolate {
		t.Fatalf("events[1].Action = %q, want isolate", isolateEvent.Action)
	}
	if isolateEvent.Detail == "" {
		t.Error("expected a non-empty failure detail")
	}
}
