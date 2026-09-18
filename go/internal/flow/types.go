// Package flow defines the normalised event schema this consumer produces, and
// the source-side parsing that turns Hubble's own JSON output into it.
//
// This mirrors detection/normalise.py's NormalisedEvent on the Python side: the
// two must stay in the same shape, because a normalised event produced here is
// meant to be piped, as one JSON object per line, into a Python-side consumer
// that evaluates it against detection/rules/*.yaml (see cmd/flow-consumer).
package flow

import "encoding/json"

// Normalized is the common event shape, one JSON object per line on the wire.
// Field names and values intentionally match detection.normalise.NormalisedEvent
// in the Python package (source/agent_id/kind/target/verdict/raw).
type Normalized struct {
	Source  string          `json:"source"`
	AgentID string          `json:"agent_id"`
	Kind    string          `json:"kind"`
	Target  string          `json:"target"`
	Verdict string          `json:"verdict"`
	Raw     json.RawMessage `json:"raw"`
}
