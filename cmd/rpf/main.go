package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/adilalperenciftci/agent-boundary/internal/rpf"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: rpf <assemble|create-local-provenance|graph-events|validate-events|verify-fixture> [options]")
	}
	switch os.Args[1] {
	case "assemble":
		assemble(os.Args[2:])
	case "verify-fixture":
		verify(os.Args[2:])
	case "validate-events":
		validateEvents(os.Args[2:])
	case "graph-events":
		graphEvents(os.Args[2:])
	case "create-local-provenance":
		createLocalProvenance(os.Args[2:])
	default:
		fail("unknown command %q", os.Args[1])
	}
}

func createLocalProvenance(arguments []string) {
	set := flag.NewFlagSet("create-local-provenance", flag.ContinueOnError)
	artifactPath := set.String("artifact", "", "artifact file")
	eventPath := set.String("events", "", "canonical event JSONL")
	repository := set.String("repository", "", "source repository URI")
	revision := set.String("revision", "", "source revision")
	outputPath := set.String("output", "", "new unsigned local provenance statement")
	if err := set.Parse(arguments); err != nil {
		fail("%v", err)
	}
	if *artifactPath == "" || *eventPath == "" || *repository == "" || *revision == "" || *outputPath == "" {
		fail("all create-local-provenance options are required")
	}
	artifact, err := os.ReadFile(*artifactPath)
	if err != nil {
		fail("read artifact: %v", err)
	}
	raw, err := os.ReadFile(*eventPath)
	if err != nil {
		fail("read events: %v", err)
	}
	events, err := rpf.ParseEventStream(raw)
	if err != nil {
		fail("validate events: %v", err)
	}
	statement, err := rpf.CreateLocalFixtureProvenance(filepath.Base(*artifactPath), artifact, events, *repository, *revision)
	if err != nil {
		fail("create local provenance: %v", err)
	}
	if err := rpf.WriteCanonicalExclusive(*outputPath, statement); err != nil {
		fail("write local provenance: %v", err)
	}
	printJSON(map[string]any{"written": true, "output": *outputPath, "assurance": "unsigned-local-fixture"})
}

func graphEvents(arguments []string) {
	set := flag.NewFlagSet("graph-events", flag.ContinueOnError)
	eventPath := set.String("events", "", "canonical event JSONL")
	outputPath := set.String("output", "", "new canonical execution graph file")
	if err := set.Parse(arguments); err != nil {
		fail("%v", err)
	}
	if *eventPath == "" || *outputPath == "" {
		fail("--events and --output are required")
	}
	raw, err := os.ReadFile(*eventPath)
	if err != nil {
		fail("read events: %v", err)
	}
	graph, err := rpf.BuildGraphFromStream(raw)
	if err != nil {
		fail("build graph: %v", err)
	}
	if err := rpf.WriteCanonicalExclusive(*outputPath, graph); err != nil {
		fail("write graph: %v", err)
	}
	printJSON(map[string]any{"written": true, "output": *outputPath, "nodes": len(graph.Nodes), "edges": len(graph.Edges)})
}

func validateEvents(arguments []string) {
	set := flag.NewFlagSet("validate-events", flag.ContinueOnError)
	eventPath := set.String("events", "", "canonical event JSONL")
	if err := set.Parse(arguments); err != nil {
		fail("%v", err)
	}
	if *eventPath == "" {
		fail("--events is required")
	}
	raw, err := os.ReadFile(*eventPath)
	if err != nil {
		fail("read events: %v", err)
	}
	events, err := rpf.ParseEventStream(raw)
	if err != nil {
		fail("validate events: %v", err)
	}
	printJSON(map[string]any{
		"valid": true, "event_count": len(events), "build_id": events[0].Build.BuildID,
		"first_sequence": events[0].Sequence, "last_sequence": events[len(events)-1].Sequence,
	})
}

func assemble(arguments []string) {
	set := flag.NewFlagSet("assemble", flag.ContinueOnError)
	artifact := set.String("artifact", "", "artifact file")
	events := set.String("events", "", "canonical event JSONL")
	provenance := set.String("provenance", "", "SLSA provenance statement")
	policy := set.String("policy", "", "behavior policy")
	output := set.String("output", "", "output evidence directory")
	if err := set.Parse(arguments); err != nil {
		fail("%v", err)
	}
	if *artifact == "" || *events == "" || *provenance == "" || *policy == "" || *output == "" {
		fail("all assemble options are required")
	}
	inputs, err := rpf.ReadInputs(*artifact, *events, *provenance, *policy)
	if err != nil {
		fail("read inputs: %v", err)
	}
	bundle, err := rpf.Assemble(inputs)
	if err != nil {
		fail("assemble: %v", err)
	}
	if err := rpf.WriteBundle(*output, bundle); err != nil {
		fail("write bundle: %v", err)
	}
	printJSON(map[string]any{"assembled": true, "output": *output, "completeness": bundle.RuntimeTrace.Predicate[rpf.CorrelationKey].(map[string]any)["completeness"]})
}

func verify(arguments []string) {
	set := flag.NewFlagSet("verify-fixture", flag.ContinueOnError)
	artifact := set.String("artifact", "", "artifact file")
	events := set.String("events", "", "canonical event JSONL")
	provenance := set.String("provenance", "", "SLSA provenance statement")
	policy := set.String("policy", "", "behavior policy")
	bundlePath := set.String("bundle", "", "evidence bundle directory")
	if err := set.Parse(arguments); err != nil {
		fail("%v", err)
	}
	if *artifact == "" || *events == "" || *provenance == "" || *policy == "" || *bundlePath == "" {
		fail("all verify-fixture options are required")
	}
	inputs, err := rpf.ReadInputs(*artifact, *events, *provenance, *policy)
	if err != nil {
		fail("read inputs: %v", err)
	}
	bundle, err := rpf.LoadBundle(*bundlePath)
	if err != nil {
		fail("load bundle: %v", err)
	}
	decision, err := rpf.Verify(inputs, bundle)
	if err != nil {
		fail("verify: %v", err)
	}
	printJSON(decision)
	if decision.Decision == "REVIEW" {
		os.Exit(2)
	}
	if decision.Decision == "REJECT" {
		os.Exit(3)
	}
}

func printJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fail("encode output: %v", err)
	}
}

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(4)
}
