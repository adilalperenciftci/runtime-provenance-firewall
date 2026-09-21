package rpf

import (
	"bytes"
	"strings"
	"testing"
)

func fixtureInputs(t testing.TB, mutate func(*[]Event)) Inputs {
	t.Helper()
	artifact := []byte("deterministic fixture artifact\n")
	build := BuildScope{BuildID: "bld_fixture_001", RunID: "local-run-001", Source: SourceIdentity{Repository: "https://example.test/repo", Revision: "1111111111111111111111111111111111111111"}, BootID: "4f25a5e2-3a0d-4bb0-99dd-a4e4b6c2a100", CgroupID: 99122, CgroupPathHash: "sha256:cgroup"}
	sensor := Sensor{Name: "rpf-fixture-sensor", Version: "0.1.0", ConfigDigest: "sha256:sensor-config"}
	parent := Process{ProcessKey: "sha256:parent", PID: 100, TGID: 100, PPID: 1, StartTimeNS: 1000, PIDNamespace: 42, MountNamespace: 43, UID: 1000, GID: 1000, Executable: Executable{Path: "/bin/sh", Identity: "sha256:sh", IdentityKind: "content_sha256"}}
	compiler := Process{ProcessKey: "sha256:compiler", ParentKey: parent.ProcessKey, PID: 101, TGID: 101, PPID: 100, StartTimeNS: 2000, PIDNamespace: 42, MountNamespace: 43, UID: 1000, GID: 1000, Executable: Executable{Path: "/usr/bin/cc", Identity: "sha256:cc", IdentityKind: "content_sha256"}}
	events := []Event{
		{SchemaVersion: EventSchema, EventID: "00000000-0000-7000-8000-000000000001", Sequence: 1, ObservedAt: "2026-09-11T12:00:00Z", MonotonicNS: 1, Build: build, Operation: "sensor_started", Outcome: Outcome{Status: "success"}, Sensor: sensor, Resource: map[string]any{}},
		{SchemaVersion: EventSchema, EventID: "00000000-0000-7000-8000-000000000002", Sequence: 2, ObservedAt: "2026-09-11T12:00:01Z", MonotonicNS: 2, Build: build, Process: &parent, Operation: "process_exec", Outcome: Outcome{Status: "success"}, Sensor: sensor, Resource: map[string]any{}},
		{SchemaVersion: EventSchema, EventID: "00000000-0000-7000-8000-000000000003", Sequence: 3, ObservedAt: "2026-09-11T12:00:02Z", MonotonicNS: 3, Build: build, Process: &compiler, Operation: "process_exec", Outcome: Outcome{Status: "success"}, Sensor: sensor, Resource: map[string]any{}},
		{SchemaVersion: EventSchema, EventID: "00000000-0000-7000-8000-000000000004", Sequence: 4, ObservedAt: "2026-09-11T12:00:03Z", MonotonicNS: 4, Build: build, Process: &compiler, Operation: "artifact_finalized", Outcome: Outcome{Status: "success"}, Sensor: sensor, Resource: map[string]any{"category": "artifact", "sha256": Digest(artifact)}},
		{SchemaVersion: EventSchema, EventID: "00000000-0000-7000-8000-000000000005", Sequence: 5, ObservedAt: "2026-09-11T12:00:04Z", MonotonicNS: 5, Build: build, Operation: "sensor_finalized", Outcome: Outcome{Status: "success"}, Sensor: sensor, Resource: map[string]any{"kernel_reserve": 0, "kernel_correlation": 0, "decode": 0, "queue": 0, "persistence": 0, "counter_read_error": false}},
	}
	if mutate != nil {
		mutate(&events)
	}
	previous := zeroHash
	var stream bytes.Buffer
	for index := range events {
		events[index].Sequence = uint64(index + 1)
		events[index].Integrity.PreviousEventHash = previous
		hash, err := eventDigest(events[index])
		if err != nil {
			t.Fatal(err)
		}
		events[index].Integrity.EventHash = hash
		previous = hash
		raw, err := canonical(events[index])
		if err != nil {
			t.Fatal(err)
		}
		stream.Write(raw)
		stream.WriteByte('\n')
	}
	provenance, err := CreateLocalFixtureProvenance("artifact", artifact, events, events[0].Build.Source.Repository, events[0].Build.Source.Revision)
	if err != nil {
		t.Fatal(err)
	}
	provenanceBytes, err := canonical(provenance)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{SchemaVersion: "0.1", AllowedBuilderIDs: []string{LocalBuilderID}, AllowedArtifactProducers: []string{"/usr/bin/cc"}, AllowedRepositories: []string{"https://example.test/repo"}, AllowedExecutables: []string{"/bin/sh", "/usr/bin/cc"}, AllowedNetworkDestinations: []string{"127.0.0.1:8080"}, ForbiddenSensitiveCategories: []string{"synthetic_credential"}, ExpectedProvider: "local", IncompleteDecision: "REJECT"}
	policyBytes, err := canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	return Inputs{ArtifactBytes: artifact, ArtifactName: "artifact", EventBytes: stream.Bytes(), ProvenanceBytes: provenanceBytes, PolicyBytes: policyBytes}
}

func BenchmarkParseEventStream(b *testing.B) {
	inputs := fixtureInputs(b, nil)
	b.ReportAllocs()
	b.SetBytes(int64(len(inputs.EventBytes)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseEventStream(inputs.EventBytes); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(5, "events")
	b.ReportMetric(float64(len(inputs.EventBytes)), "event_bytes")
}

func BenchmarkAssemble(b *testing.B) {
	inputs := fixtureInputs(b, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Assemble(inputs); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(5, "events")
	b.ReportMetric(float64(len(inputs.EventBytes)), "event_bytes")
}

func BenchmarkVerify(b *testing.B) {
	inputs := fixtureInputs(b, nil)
	bundle, err := Assemble(inputs)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Verify(inputs, bundle); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(5, "events")
	b.ReportMetric(float64(len(inputs.EventBytes)), "event_bytes")
}

func TestBaselineAssemblesAndAllows(t *testing.T) {
	inputs := fixtureInputs(t, nil)
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Verify(inputs, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "ALLOW" || decision.Completeness != "complete" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if len(bundle.Graph.Nodes) != 2 || len(bundle.Graph.Edges) != 2 {
		t.Fatalf("unexpected graph: %#v", bundle.Graph)
	}
	for _, node := range bundle.Graph.Nodes {
		if node.ProcessKey == "sha256:parent" && node.ParentObservation != "none" {
			t.Fatalf("root parent observation is ambiguous: %#v", node)
		}
		if node.ProcessKey == "sha256:compiler" && node.ParentObservation != "observed" {
			t.Fatalf("observed ancestry was not labelled: %#v", node)
		}
	}
	if bundle.Graph.Edges[0].Kind != "observed_exec_parent" {
		t.Fatalf("observed parent edge was not labelled: %#v", bundle.Graph.Edges[0])
	}
}

func TestEventSchemaV01IsRejected(t *testing.T) {
	inputs := fixtureInputs(t, nil)
	legacy := bytes.Replace(inputs.EventBytes, []byte(`"schema_version":"0.2"`), []byte(`"schema_version":"0.1"`), 1)
	if _, err := ParseEventStream(legacy); err == nil || !strings.Contains(err.Error(), "unsupported event schema") {
		t.Fatalf("legacy event schema was accepted: %v", err)
	}
}

func TestGraphLabelsUnobservedParent(t *testing.T) {
	inputs := fixtureInputs(t, func(events *[]Event) {
		(*events)[2].Process.ParentKey = "sha256:not-in-stream"
	})
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range bundle.Graph.Nodes {
		if node.ProcessKey == "sha256:compiler" {
			if node.ParentObservation != "unobserved" {
				t.Fatalf("unobserved parent was not explicit: %#v", node)
			}
			if bundle.Graph.Edges[0].Kind != "unobserved_exec_parent" {
				t.Fatalf("unobserved parent edge was not labelled: %#v", bundle.Graph.Edges[0])
			}
			return
		}
	}
	t.Fatal("compiler node missing")
}

func TestBundleDiskRoundTrip(t *testing.T) {
	inputs := fixtureInputs(t, nil)
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := WriteBundle(directory, bundle); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBundle(directory)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Verify(inputs, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "ALLOW" {
		t.Fatalf("disk bundle failed verification: %#v", decision)
	}
}

func TestEventLossCannotAllow(t *testing.T) {
	inputs := fixtureInputs(t, func(events *[]Event) { (*events)[len(*events)-1].Resource["kernel_reserve"] = 1 })
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Verify(inputs, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "REJECT" || decision.Completeness != "incomplete" {
		t.Fatalf("loss was accepted: %#v", decision)
	}
}

func TestMissingCorrelationLossCounterCannotAllow(t *testing.T) {
	inputs := fixtureInputs(t, func(events *[]Event) {
		delete((*events)[len(*events)-1].Resource, "kernel_correlation")
	})
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Verify(inputs, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "REJECT" || decision.Completeness != "incomplete" {
		t.Fatalf("missing loss counter was accepted: %#v", decision)
	}
}

func TestMissingFinalLifecycleCannotAllow(t *testing.T) {
	inputs := fixtureInputs(t, func(events *[]Event) {
		*events = (*events)[:len(*events)-1]
	})
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Verify(inputs, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "REJECT" || decision.Completeness != "unknown" {
		t.Fatalf("tail-truncated lifecycle was accepted: %#v", decision)
	}
	if len(decision.Reasons) != 1 || decision.Reasons[0].Code != "RPF-EVIDENCE-001" {
		t.Fatalf("tail truncation lacked explicit evidence reason: %#v", decision)
	}
}

func TestProvenanceInternalAndExternalRevisionConflictFails(t *testing.T) {
	inputs := fixtureInputs(t, nil)
	statement, err := decodeStatement(inputs.ProvenanceBytes)
	if err != nil {
		t.Fatal(err)
	}
	definition := statement.Predicate["buildDefinition"].(map[string]any)
	definition["externalParameters"].(map[string]any)["revision"] = "2222222222222222222222222222222222222222"
	inputs.ProvenanceBytes, err = canonical(statement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Assemble(inputs); err == nil {
		t.Fatal("conflicting source revisions were accepted")
	}
}

func TestUnauthorizedBuilderRejects(t *testing.T) {
	inputs := fixtureInputs(t, nil)
	statement, err := decodeStatement(inputs.ProvenanceBytes)
	if err != nil {
		t.Fatal(err)
	}
	definition := statement.Predicate["buildDefinition"].(map[string]any)
	identity := definition["internalParameters"].(map[string]any)[BuildIdentityKey].(map[string]any)
	identity["builderId"] = "https://attacker.example/builder"
	statement.Predicate["runDetails"].(map[string]any)["builder"].(map[string]any)["id"] = identity["builderId"]
	inputs.ProvenanceBytes, err = canonical(statement)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Verify(inputs, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "REJECT" || !hasReason(decision, "RPF-BUILDER-001") {
		t.Fatalf("unauthorized builder was accepted: %#v", decision)
	}
}

func TestUnauthorizedRepositoryRejects(t *testing.T) {
	inputs := fixtureInputs(t, func(events *[]Event) {
		for index := range *events {
			(*events)[index].Build.Source.Repository = "https://attacker.example/repo"
		}
	})
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Verify(inputs, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "REJECT" || !hasReason(decision, "RPF-SOURCE-001") {
		t.Fatalf("unauthorized repository was accepted: %#v", decision)
	}
}

func TestRuntimeAndProvenanceSourceMismatchFails(t *testing.T) {
	inputs := fixtureInputs(t, nil)
	statement, err := decodeStatement(inputs.ProvenanceBytes)
	if err != nil {
		t.Fatal(err)
	}
	definition := statement.Predicate["buildDefinition"].(map[string]any)
	identity := definition["internalParameters"].(map[string]any)[BuildIdentityKey].(map[string]any)
	source := identity["sourceRevision"].(map[string]any)
	source["revision"] = "2222222222222222222222222222222222222222"
	definition["externalParameters"].(map[string]any)["revision"] = source["revision"]
	definition["resolvedDependencies"].([]any)[0].(map[string]any)["digest"].(map[string]any)["gitCommit"] = source["revision"]
	inputs.ProvenanceBytes, err = canonical(statement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Assemble(inputs); err == nil || !strings.Contains(err.Error(), "runtime source identity mismatch") {
		t.Fatalf("runtime/provenance source mismatch was accepted: %v", err)
	}
}

func hasReason(decision Decision, code string) bool {
	for _, reason := range decision.Reasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}

func TestRuntimeEvidenceAndProvenanceBuildReplayFails(t *testing.T) {
	inputs := fixtureInputs(t, nil)
	replayed := fixtureInputs(t, func(events *[]Event) {
		for index := range *events {
			(*events)[index].Build.BuildID = "replayed-build"
			(*events)[index].Build.RunID = "replayed-run"
		}
	})
	inputs.ProvenanceBytes = replayed.ProvenanceBytes
	if _, err := Assemble(inputs); err == nil {
		t.Fatal("provenance from another build was accepted")
	}
}

func TestSensitiveAccessAndUnexpectedEgressReject(t *testing.T) {
	for _, operation := range []string{"file_open_sensitive", "network_connect"} {
		caseInputs := fixtureInputs(t, func(events *[]Event) {
			base := *events
			behavior := base[3]
			behavior.EventID = "00000000-0000-7000-8000-000000000006"
			behavior.Operation = operation
			if operation == "file_open_sensitive" {
				behavior.Resource = map[string]any{"category": "synthetic_credential"}
			} else {
				behavior.Resource = map[string]any{"destination": "127.0.0.1:9090"}
			}
			*events = append(base[:4], append([]Event{behavior}, base[4:]...)...)
		})
		bundle, err := Assemble(caseInputs)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := Verify(caseInputs, bundle)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Decision != "REJECT" {
			t.Fatalf("%s was accepted: %#v", operation, decision)
		}
	}
}

func TestExpectedNetworkAccessAllows(t *testing.T) {
	inputs := fixtureInputs(t, func(events *[]Event) {
		base := *events
		network := base[2]
		network.EventID = "00000000-0000-7000-8000-000000000006"
		network.Operation = "network_connect"
		network.Resource = map[string]any{"destination": "127.0.0.1:8080", "protocol": 6}
		network.Outcome = Outcome{Status: "attempted"}
		*events = append(base[:3], append([]Event{network}, base[3:]...)...)
	})
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Verify(inputs, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "ALLOW" || len(decision.Reasons) != 0 {
		t.Fatalf("expected network access produced a finding: %#v", decision)
	}
}

func TestUnauthorizedArtifactProducerRejects(t *testing.T) {
	inputs := fixtureInputs(t, func(events *[]Event) {
		for index := range *events {
			if (*events)[index].Process != nil && (*events)[index].Process.ProcessKey == "sha256:compiler" {
				(*events)[index].Process.Executable.Path = "/tmp/renamed-cc"
			}
		}
	})
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Verify(inputs, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "REJECT" || !hasReason(decision, "RPF-ARTIFACT-PRODUCER-001") {
		t.Fatalf("unauthorized artifact producer was accepted: %#v", decision)
	}
}

func TestArtifactSubstitutionFails(t *testing.T) {
	inputs := fixtureInputs(t, nil)
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	inputs.ArtifactBytes = []byte("substituted\n")
	decision, err := Verify(inputs, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "REJECT" {
		t.Fatalf("substitution was accepted: %#v", decision)
	}
}

func TestManifestTamperFails(t *testing.T) {
	inputs := fixtureInputs(t, nil)
	bundle, err := Assemble(inputs)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Manifest.BuildID = "other-build"
	decision, err := Verify(inputs, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != "REJECT" {
		t.Fatalf("tamper was accepted: %#v", decision)
	}
}

func TestDuplicateJSONKeyRejected(t *testing.T) {
	var policy Policy
	err := decodeStrict([]byte(`{"schema_version":"0.1","schema_version":"0.1"}`), &policy, maxDocumentBytes)
	if err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestOversizedJSONStringRejected(t *testing.T) {
	raw := []byte(`{"value":"` + strings.Repeat("x", maxStringBytes+1) + `"}`)
	var value map[string]any
	if err := decodeStrict(raw, &value, maxDocumentBytes); err == nil {
		t.Fatal("oversized JSON string accepted")
	}
}

func TestEmptyExecutableIdentityRejected(t *testing.T) {
	proc := Process{
		ProcessKey:     "sha256:proc",
		PID:            100,
		TGID:           100,
		PPID:           1,
		StartTimeNS:    1000,
		PIDNamespace:   42,
		MountNamespace: 43,
		UID:            1000,
		GID:            1000,
		Executable:     Executable{Path: "/bin/sh", Identity: "", IdentityKind: "content_sha256"},
	}
	event := Event{
		SchemaVersion: EventSchema,
		EventID:       "00000000-0000-7000-8000-000000000002",
		Sequence:      2,
		MonotonicNS:   2,
		Build:         BuildScope{BuildID: "b", RunID: "r", Source: SourceIdentity{Repository: "repo", Revision: "rev"}, BootID: "boot", CgroupID: 1, CgroupPathHash: "hash"},
		Sensor:        Sensor{Name: "sensor", Version: "0.1", ConfigDigest: "cfg"},
		Operation:     "process_exec",
		Process:       &proc,
	}
	if err := validateEvent(event); err == nil {
		t.Fatal("empty executable identity was accepted for content_sha256")
	}
}

