package rpf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"sort"
)

var allowedOperations = map[string]struct{}{
	"sensor_started": {}, "process_exec": {}, "process_exit": {},
	"file_open_sensitive": {}, "file_open_output": {}, "file_rename_output": {},
	"network_connect": {}, "privilege_change": {}, "artifact_finalized": {},
	"sensor_finalized": {},
}

func ParseEventStream(raw []byte) ([]Event, error) {
	if len(raw) == 0 || len(raw) > maxDocumentBytes {
		return nil, fmt.Errorf("event stream size %d outside accepted range", len(raw))
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), maxEventBytes)
	events := make([]Event, 0)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			return nil, errors.New("blank event lines are forbidden")
		}
		var event Event
		if err := decodeStrict(line, &event, maxEventBytes); err != nil {
			return nil, fmt.Errorf("event line %d: %w", len(events)+1, err)
		}
		if err := validateEvent(event); err != nil {
			return nil, fmt.Errorf("event line %d: %w", len(events)+1, err)
		}
		canonicalLine, err := canonical(event)
		if err != nil || !bytes.Equal(line, canonicalLine) {
			return nil, fmt.Errorf("event line %d is not canonical JSON", len(events)+1)
		}
		events = append(events, event)
		if len(events) > maxEvents {
			return nil, errors.New("event count exceeds limit")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan event stream: %w", err)
	}
	if len(events) == 0 {
		return nil, errors.New("event stream is empty")
	}
	if err := verifyChain(events); err != nil {
		return nil, err
	}
	return events, nil
}

func validateEvent(event Event) error {
	if event.SchemaVersion != EventSchema {
		return fmt.Errorf("unsupported event schema %q", event.SchemaVersion)
	}
	if event.EventID == "" || event.Build.BuildID == "" || event.Build.RunID == "" {
		return errors.New("event/build identity is missing")
	}
	if event.Build.BootID == "" || event.Build.CgroupID == 0 || event.Build.CgroupPathHash == "" {
		return errors.New("build kernel scope is incomplete")
	}
	if event.Build.Source.Repository == "" || event.Build.Source.Revision == "" {
		return errors.New("build source identity is missing")
	}
	if event.Sequence == 0 || event.MonotonicNS == 0 {
		return errors.New("event sequence and monotonic time must be positive")
	}
	if _, ok := allowedOperations[event.Operation]; !ok {
		return fmt.Errorf("unsupported operation %q", event.Operation)
	}
	if event.Sensor.Name == "" || event.Sensor.Version == "" || event.Sensor.ConfigDigest == "" {
		return errors.New("sensor identity is incomplete")
	}
	if event.Operation == "process_exec" && event.Process == nil {
		return errors.New("process_exec requires process identity")
	}
	if event.Process != nil && (event.Process.ProcessKey == "" || event.Process.TGID == 0 || event.Process.StartTimeNS == 0 || event.Process.PIDNamespace == 0 || event.Process.MountNamespace == 0 || event.Process.Executable.Path == "" || event.Process.Executable.IdentityKind == "" || (event.Process.Executable.IdentityKind != "path_only" && event.Process.Executable.Identity == "")) {
		return errors.New("composite process identity is incomplete")
	}
	return nil
}

func eventDigest(event Event) (string, error) {
	raw, err := canonical(event)
	if err != nil {
		return "", err
	}
	var body map[string]any
	if err := decodeStrict(raw, &body, maxEventBytes); err != nil {
		return "", err
	}
	integrity, ok := body["integrity"].(map[string]any)
	if !ok {
		return "", errors.New("event integrity object is missing")
	}
	delete(integrity, "event_hash")
	canonicalBody, err := canonical(body)
	if err != nil {
		return "", err
	}
	return "sha256:" + Digest(canonicalBody), nil
}

func verifyChain(events []Event) error {
	previous := zeroHash
	buildID := events[0].Build.BuildID
	runID := events[0].Build.RunID
	buildScope := events[0].Build
	sensor := events[0].Sensor
	var previousMonotonic uint64
	for index, event := range events {
		wantSequence := uint64(index + 1)
		if event.Sequence != wantSequence {
			return fmt.Errorf("event sequence %d, expected %d", event.Sequence, wantSequence)
		}
		if event.Build.BuildID != buildID || event.Build.RunID != runID || event.Build != buildScope {
			return fmt.Errorf("event %d crosses build identity", event.Sequence)
		}
		if event.Sensor != sensor {
			return fmt.Errorf("event %d changes sensor identity", event.Sequence)
		}
		if event.MonotonicNS < previousMonotonic {
			return fmt.Errorf("event %d reverses monotonic order", event.Sequence)
		}
		if event.Integrity.PreviousEventHash != previous {
			return fmt.Errorf("event %d previous hash mismatch", event.Sequence)
		}
		actual, err := eventDigest(event)
		if err != nil {
			return err
		}
		if event.Integrity.EventHash != actual {
			return fmt.Errorf("event %d hash mismatch", event.Sequence)
		}
		previous = actual
		previousMonotonic = event.MonotonicNS
	}
	return nil
}

func BuildGraph(events []Event) (ExecutionGraph, error) {
	if len(events) == 0 {
		return ExecutionGraph{}, errors.New("cannot graph empty event stream")
	}
	nodeMap := make(map[string]GraphNode)
	edges := make([]GraphEdge, 0)
	for _, event := range events {
		if event.Process == nil {
			continue
		}
		process := event.Process
		if process.ProcessKey == "" || process.Executable.Path == "" {
			return ExecutionGraph{}, fmt.Errorf("event %d has incomplete process identity", event.Sequence)
		}
		node := GraphNode{ProcessKey: process.ProcessKey, ParentKey: process.ParentKey, Executable: process.Executable.Path}
		if old, exists := nodeMap[process.ProcessKey]; exists && old != node {
			return ExecutionGraph{}, fmt.Errorf("process key %q has conflicting identity", process.ProcessKey)
		}
		nodeMap[process.ProcessKey] = node
		switch event.Operation {
		case "process_exec":
			if process.ParentKey != "" {
				edges = append(edges, GraphEdge{Sequence: event.Sequence, From: process.ParentKey, To: process.ProcessKey, Kind: "observed_exec_parent"})
			}
		case "file_open_sensitive", "file_open_output", "file_rename_output", "network_connect", "artifact_finalized":
			edges = append(edges, GraphEdge{Sequence: event.Sequence, From: process.ProcessKey, To: resourceIdentity(event), Kind: event.Operation, Evidence: event.Resource})
		}
	}
	nodes := make([]GraphNode, 0, len(nodeMap))
	for key, node := range nodeMap {
		switch {
		case node.ParentKey == "":
			node.ParentObservation = "none"
		case nodeMap[node.ParentKey].ProcessKey != "":
			node.ParentObservation = "observed"
		default:
			node.ParentObservation = "unobserved"
		}
		nodeMap[key] = node
		nodes = append(nodes, node)
	}
	for index := range edges {
		if edges[index].Kind != "observed_exec_parent" {
			continue
		}
		if _, observed := nodeMap[edges[index].From]; !observed {
			edges[index].Kind = "unobserved_exec_parent"
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ProcessKey < nodes[j].ProcessKey })
	sort.Slice(edges, func(i, j int) bool { return edges[i].Sequence < edges[j].Sequence })
	return ExecutionGraph{SchemaVersion: "0.2", BuildID: events[0].Build.BuildID, Nodes: nodes, Edges: edges}, nil
}

func BuildGraphFromStream(raw []byte) (ExecutionGraph, error) {
	events, err := ParseEventStream(raw)
	if err != nil {
		return ExecutionGraph{}, err
	}
	return BuildGraph(events)
}

func resourceIdentity(event Event) string {
	if value, ok := event.Resource["category"].(string); ok {
		return "category:" + value
	}
	if value, ok := event.Resource["destination"].(string); ok {
		return "network:" + value
	}
	digest, _ := canonicalDigest(event.Resource)
	return "resource:sha256:" + digest
}

func completeness(manifest Manifest) string {
	if !manifest.Lifecycle.Started || !manifest.Lifecycle.Finalized || manifest.Loss.CounterReadError {
		return "unknown"
	}
	if manifest.Loss.KernelReserve+manifest.Loss.KernelCorrelation+manifest.Loss.Decode+manifest.Loss.Queue+manifest.Loss.Persistence > 0 {
		return "incomplete"
	}
	return "complete"
}
