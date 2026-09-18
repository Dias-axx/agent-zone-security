// flow-consumer reads `hubble observe -o json` output from stdin, normalises
// each flow into the common event schema (internal/flow), and writes one JSON
// object per line to stdout. It does not evaluate detection rules itself —
// per the project's language split, rule evaluation stays in Python
// (detection/engine.py) — so the intended pipeline is:
//
//	hubble observe -o json | flow-consumer | python -m detection.consume_stream
//
// This has not been run against a live `hubble observe` process in this
// repository's build environment (see docs/architecture.md); it is exercised
// by internal/flow's unit tests against representative JSON lines instead.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/dias-axx/agent-zone-control/go/internal/flow"
)

func main() {
	writer := bufio.NewWriter(os.Stdout)
	defer flushOrWarn(writer)

	events := flow.StreamHubbleLines(os.Stdin, func(line []byte, err error) {
		fmt.Fprintf(os.Stderr, "flow-consumer: skipping unparsable line: %v (%q)\n", err, string(line))
	})

	encoder := json.NewEncoder(writer)
	for event := range events {
		if err := encoder.Encode(event); err != nil {
			fmt.Fprintf(os.Stderr, "flow-consumer: failed to encode event: %v\n", err)
			continue
		}
		flushOrWarn(writer)
	}
}

func flushOrWarn(writer *bufio.Writer) {
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "flow-consumer: failed to flush stdout: %v\n", err)
	}
}
