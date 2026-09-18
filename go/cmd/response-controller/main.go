// response-controller runs the alert->isolate->revoke->preserve->terminate
// chain (internal/response) for one agent. It is meant to be invoked by
// whatever confirms a detection rule fired (in Phase 3+, the Python detection
// engine, via a subprocess call or a small queue) — it does not itself decide
// that a violation occurred, it only carries out the response once told to.
//
// Defaults to --dry-run=true. Only an explicit --dry-run=false reaches
// kubectl, matching control/response.py's stance that every call site in this
// repository is dry-run unless a caller deliberately opts in to live actions.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/dias-axx/agent-zone-control/go/internal/response"
)

func main() {
	agentID := flag.String("agent-id", "", "agent identifier to act on (required)")
	tokenID := flag.String("token-id", "unknown", "capability token id to revoke, if the chain includes revoke")
	onViolation := flag.String("on-violation", "alert", "response.on_violation value: alert|isolate|revoke|terminate")
	namespace := flag.String("namespace", "agent-restricted", "namespace the agent's pod runs in")
	dryRun := flag.Bool("dry-run", true, "simulate actions instead of calling kubectl")
	flag.Parse()

	if *agentID == "" {
		fmt.Fprintln(os.Stderr, "response-controller: --agent-id is required")
		os.Exit(2)
	}

	controller := response.NewController(response.KubectlRunner{}, *namespace)
	events, err := controller.Escalate(context.Background(), *agentID, *tokenID, *onViolation, *dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "response-controller: %v\n", err)
		os.Exit(1)
	}

	for _, event := range events {
		fmt.Printf("[RESPONSE:%s] dry_run=%t agent=%s %s\n", event.Action, event.DryRun, event.AgentID, event.Detail)
	}
}
