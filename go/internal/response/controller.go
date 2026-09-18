// Package response implements the Go side of the response chain:
// alert -> isolate -> revoke -> preserve -> terminate.
//
// It mirrors control/response.py's ordering and dry-run-by-default stance
// exactly (isolate before terminate, so a forensic snapshot can be taken before
// the pod that would carry it is deleted). This package is the one meant to run
// against a live cluster in Phase 3+, driving kubectl rather than the Python
// side's simulated actions — but it shells out to the kubectl binary rather
// than importing client-go, to keep this module dependency-free and to keep
// "isolate"/"terminate" testable by substituting a fake kubectl in tests
// without needing a real API server.
package response

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// Action mirrors control.response.ResponseAction's five values.
type Action string

const (
	ActionAlert     Action = "alert"
	ActionIsolate   Action = "isolate"
	ActionRevoke    Action = "revoke"
	ActionPreserve  Action = "preserve"
	ActionTerminate Action = "terminate"
)

// Chain mirrors control.response.ESCALATION_CHAIN. Keyed by the role policy's
// response.on_violation value — there is no global default on either side.
var Chain = map[string][]Action{
	"alert":     {ActionAlert},
	"isolate":   {ActionAlert, ActionIsolate},
	"revoke":    {ActionAlert, ActionIsolate, ActionRevoke},
	"terminate": {ActionAlert, ActionIsolate, ActionRevoke, ActionPreserve, ActionTerminate},
}

// Event mirrors control.response.ResponseEvent.
type Event struct {
	AgentID string
	Action  Action
	DryRun  bool
	Detail  string
}

// Runner executes the actual kubectl invocations. Production code uses
// KubectlRunner; tests substitute a fake to assert on the exact command and
// stdin sent, without a live cluster. stdin may be empty for commands that
// don't pipe a manifest in (e.g. delete).
type Runner interface {
	Run(ctx context.Context, stdin string, args ...string) (stdout string, err error)
}

// KubectlRunner shells out to the kubectl binary on PATH.
type KubectlRunner struct{}

func (KubectlRunner) Run(ctx context.Context, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	if stdin != "" {
		cmd.Stdin = bytes.NewBufferString(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("kubectl %v: %w: %s", args, err, stderr.String())
	}
	return stdout.String(), nil
}

// Controller runs the escalation chain for one agent/namespace.
type Controller struct {
	Runner    Runner
	Namespace string
}

func NewController(runner Runner, namespace string) *Controller {
	return &Controller{Runner: runner, Namespace: namespace}
}

func (c *Controller) alert(_ context.Context, agentID string, dryRun bool) Event {
	return Event{AgentID: agentID, Action: ActionAlert, DryRun: dryRun, Detail: "policy violation detected"}
}

// isolate applies a deny-all NetworkPolicy scoped to the offending agent's pod
// label, the same shape as deploy/k8s/10-default-deny.yaml but targeted with a
// podSelector instead of {} so only that agent is cut off, not the whole zone.
func (c *Controller) isolate(ctx context.Context, agentID string, dryRun bool) Event {
	manifest := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-%s
  namespace: %s
spec:
  podSelector:
    matchLabels:
      agent-id: %s
  policyTypes: [Ingress, Egress]
`, agentID, c.Namespace, agentID)

	if dryRun {
		return Event{AgentID: agentID, Action: ActionIsolate, DryRun: true, Detail: "[dry-run] would apply deny-all NetworkPolicy isolate-" + agentID}
	}
	if _, err := c.Runner.Run(ctx, manifest, "apply", "-f", "-"); err != nil {
		return Event{AgentID: agentID, Action: ActionIsolate, DryRun: false, Detail: "FAILED to apply isolate NetworkPolicy: " + err.Error()}
	}
	return Event{AgentID: agentID, Action: ActionIsolate, DryRun: false, Detail: "applied deny-all NetworkPolicy isolate-" + agentID}
}

func (c *Controller) revoke(_ context.Context, agentID, tokenID string, dryRun bool) Event {
	detail := fmt.Sprintf("revoke token %s", tokenID)
	if dryRun {
		detail = "[dry-run] would " + detail
	}
	return Event{AgentID: agentID, Action: ActionRevoke, DryRun: dryRun, Detail: detail}
}

func (c *Controller) preserve(_ context.Context, agentID string, dryRun bool) Event {
	detail := "preserve forensic snapshot"
	if dryRun {
		detail = "[dry-run] would " + detail
	}
	return Event{AgentID: agentID, Action: ActionPreserve, DryRun: dryRun, Detail: detail}
}

// terminate deletes the agent's pod by label selector.
func (c *Controller) terminate(ctx context.Context, agentID string, dryRun bool) Event {
	if dryRun {
		return Event{AgentID: agentID, Action: ActionTerminate, DryRun: true, Detail: "[dry-run] would delete pod(s) matching agent-id=" + agentID}
	}
	if _, err := c.Runner.Run(ctx, "", "delete", "pod", "-l", "agent-id="+agentID, "-n", c.Namespace); err != nil {
		return Event{AgentID: agentID, Action: ActionTerminate, DryRun: false, Detail: "FAILED to delete pod: " + err.Error()}
	}
	return Event{AgentID: agentID, Action: ActionTerminate, DryRun: false, Detail: "deleted pod(s) matching agent-id=" + agentID}
}

// Escalate runs the chain selected by onViolation, in the fixed order defined
// by Chain, exactly mirroring control.response.escalate. dryRun defaults to
// true at every call site in this repository; only an explicit false wires a
// call to actually reach kubectl.
func (c *Controller) Escalate(ctx context.Context, agentID, tokenID, onViolation string, dryRun bool) ([]Event, error) {
	actions, ok := Chain[onViolation]
	if !ok {
		return nil, fmt.Errorf("unknown response.on_violation value %q", onViolation)
	}

	events := make([]Event, 0, len(actions))
	for _, action := range actions {
		switch action {
		case ActionAlert:
			events = append(events, c.alert(ctx, agentID, dryRun))
		case ActionIsolate:
			events = append(events, c.isolate(ctx, agentID, dryRun))
		case ActionRevoke:
			events = append(events, c.revoke(ctx, agentID, tokenID, dryRun))
		case ActionPreserve:
			events = append(events, c.preserve(ctx, agentID, dryRun))
		case ActionTerminate:
			events = append(events, c.terminate(ctx, agentID, dryRun))
		}
	}
	return events, nil
}
