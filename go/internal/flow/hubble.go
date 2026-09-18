package flow

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// hubbleEnvelope models the subset of `hubble observe -o json` output this
// package reads. Hubble wraps each flow in a top-level "flow" object alongside
// node metadata; this struct covers only the fields the zone-crossing detection
// rule (AGT-ZONE-001, detection/rules/zone-cross.yaml) needs.
//
// This shape was written against Hubble's documented JSON flow format and has
// NOT been validated against a live Hubble process's actual output in this
// repository's build environment (see docs/architecture.md's "Cluster" section
// for why) — the exact field names/nesting can differ across Cilium versions.
// Treat ParseHubbleLine as a best-effort mapping to be confirmed and adjusted
// against a real `hubble observe -o json` sample the first time this runs
// against a live cluster.
type hubbleEnvelope struct {
	Flow *hubbleFlow `json:"flow"`
}

type hubbleFlow struct {
	Verdict     string          `json:"verdict"`
	Source      *hubbleEndpoint `json:"source"`
	Destination *hubbleEndpoint `json:"destination"`
}

type hubbleEndpoint struct {
	Namespace string   `json:"namespace"`
	PodName   string   `json:"pod_name"`
	Labels    []string `json:"labels"`
}

const agentIDLabelKey = "agent_id="

// agentIDFromLabels looks for an "agent_id=<value>" label, matching how Cilium
// surfaces Kubernetes pod labels as strings in a flow's endpoint — typically
// prefixed with their source, e.g. "k8s:agent_id=agt-log-reader-001", so this
// matches on the "agent_id=" key appearing anywhere in the label rather than
// requiring it at position zero.
func agentIDFromLabels(labels []string) string {
	for _, label := range labels {
		if idx := strings.Index(label, agentIDLabelKey); idx != -1 {
			return label[idx+len(agentIDLabelKey):]
		}
	}
	return "unknown"
}

// verdictToNormalized maps Hubble's DROPPED/FORWARDED verdicts onto the
// deny/allow vocabulary detection/rules/*.yaml rules are written against.
func verdictToNormalized(hubbleVerdict string) string {
	if hubbleVerdict == "DROPPED" {
		return "deny"
	}
	return "allow"
}

// ParseHubbleLine parses one line of `hubble observe -o json` output into the
// common Normalized event schema. It returns an error for malformed JSON or a
// flow missing the fields needed to classify it — callers should skip and log
// such lines rather than abort the stream, matching detection/engine.py's
// "a rule that does not match an event's fields is not a system error" stance.
func ParseHubbleLine(line []byte) (Normalized, error) {
	var envelope hubbleEnvelope
	if err := json.Unmarshal(line, &envelope); err != nil {
		return Normalized{}, fmt.Errorf("parse hubble json line: %w", err)
	}
	if envelope.Flow == nil || envelope.Flow.Source == nil || envelope.Flow.Destination == nil {
		return Normalized{}, fmt.Errorf("hubble flow line missing source/destination")
	}

	return Normalized{
		Source:  "hubble",
		AgentID: agentIDFromLabels(envelope.Flow.Source.Labels),
		Kind:    "zone",
		Target:  envelope.Flow.Destination.Namespace,
		Verdict: verdictToNormalized(envelope.Flow.Verdict),
		Raw:     json.RawMessage(line),
	}, nil
}

// StreamHubbleLines reads newline-delimited `hubble observe -o json` output
// from r, parses each line, and sends successfully parsed events on the
// returned channel. Parse failures are sent to onError rather than aborting the
// stream. Both channels close when r is exhausted or ctx-independent EOF/error
// occurs; callers drain both until the events channel closes.
func StreamHubbleLines(r io.Reader, onError func(line []byte, err error)) <-chan Normalized {
	out := make(chan Normalized)
	go func() {
		defer close(out)
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			lineCopy := append([]byte(nil), line...)
			event, err := ParseHubbleLine(lineCopy)
			if err != nil {
				if onError != nil {
					onError(lineCopy, err)
				}
				continue
			}
			out <- event
		}
	}()
	return out
}
