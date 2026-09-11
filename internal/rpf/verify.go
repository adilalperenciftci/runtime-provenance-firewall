package rpf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

type Inputs struct {
	ArtifactBytes   []byte
	ArtifactName    string
	EventBytes      []byte
	ProvenanceBytes []byte
	PolicyBytes     []byte
}

type Bundle struct {
	Graph        ExecutionGraph
	Manifest     Manifest
	RuntimeTrace Statement
}

func Assemble(inputs Inputs) (Bundle, error) {
	events, err := ParseEventStream(inputs.EventBytes)
	if err != nil {
		return Bundle{}, err
	}
	policy, err := decodePolicy(inputs.PolicyBytes)
	if err != nil {
		return Bundle{}, fmt.Errorf("policy: %w", err)
	}
	provenance, err := decodeStatement(inputs.ProvenanceBytes)
	if err != nil {
		return Bundle{}, fmt.Errorf("provenance: %w", err)
	}
	if provenance.PredicateType != SLSAPredicate {
		return Bundle{}, fmt.Errorf("unexpected provenance predicate %q", provenance.PredicateType)
	}
	identity, err := provenanceIdentity(provenance)
	if err != nil {
		return Bundle{}, err
	}
	if identity.BuildID != events[0].Build.BuildID || identity.RunIdentity.RunID != events[0].Build.RunID {
		return Bundle{}, errors.New("provenance and runtime build identity mismatch")
	}
	if identity.Source != events[0].Build.Source {
		return Bundle{}, errors.New("provenance and runtime source identity mismatch")
	}
	artifactHash := Digest(inputs.ArtifactBytes)
	if !subjectMatches(provenance.Subject, inputs.ArtifactName, artifactHash) {
		return Bundle{}, errors.New("SLSA provenance subject does not match artifact")
	}
	if err := verifyArtifactObservation(events, artifactHash); err != nil {
		return Bundle{}, err
	}
	graph, err := BuildGraph(events)
	if err != nil {
		return Bundle{}, err
	}
	graphHash, err := canonicalDigest(graph)
	if err != nil {
		return Bundle{}, err
	}
	policyHash := Digest(inputs.PolicyBytes)
	provenanceHash := Digest(inputs.ProvenanceBytes)
	manifest := Manifest{
		SchemaVersion: ManifestSchema,
		BuildID:       identity.BuildID,
		RunIdentity:   identity.RunIdentity,
		Source:        identity.Source,
		EventStream: StreamCommitment{
			SHA256: Digest(inputs.EventBytes), FirstSequence: events[0].Sequence,
			LastSequence: events[len(events)-1].Sequence, EventCount: uint64(len(events)),
		},
		Loss:                 lossFromFinalEvent(events[len(events)-1]),
		Lifecycle:            Lifecycle{Started: events[0].Operation == "sensor_started", Finalized: events[len(events)-1].Operation == "sensor_finalized"},
		ExecutionGraphSHA256: graphHash,
		Artifact:             Artifact{Name: inputs.ArtifactName, SHA256: artifactHash},
		PolicySHA256:         policyHash,
		SensorConfigSHA256:   events[0].Sensor.ConfigDigest,
	}
	manifestHash, err := canonicalDigest(manifest)
	if err != nil {
		return Bundle{}, err
	}
	correlation := Correlation{
		BuildID: identity.BuildID, RunIdentity: identity.RunIdentity, Source: identity.Source,
		EvidenceManifestHash: manifestHash, ExecutionGraphHash: graphHash,
		SLSAProvenanceHash: provenanceHash, PolicyHash: policyHash,
		Completeness: completeness(manifest),
	}
	correlationMap, err := toMap(correlation)
	if err != nil {
		return Bundle{}, err
	}
	runtime := Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: inputs.ArtifactName, Digest: map[string]string{"sha256": artifactHash}}},
		PredicateType: RuntimePredicate,
		Predicate: map[string]any{
			"monitor":          map[string]any{"type": "https://github.com/adilalperenciftci/agent-boundary/sensor/v0.1"},
			"monitoredProcess": map[string]any{"hostID": "urn:uuid:" + events[0].Build.BootID, "type": "https://slsa.dev/build/v1", "event": identity.RunIdentity.RunID},
			"monitorLog":       map[string]any{"process": graph.Nodes},
			CorrelationKey:     correlationMap,
		},
	}
	_ = policy
	return Bundle{Graph: graph, Manifest: manifest, RuntimeTrace: runtime}, nil
}

func verifyArtifactObservation(events []Event, artifactHash string) error {
	for _, event := range events {
		if event.Operation != "artifact_finalized" {
			continue
		}
		observed, _ := event.Resource["sha256"].(string)
		if observed != artifactHash {
			return errors.New("artifact finalization digest differs from supplied artifact")
		}
		if event.Process == nil {
			return errors.New("artifact finalization lacks producing process identity")
		}
		return nil
	}
	return errors.New("artifact finalization was not observed")
}

func subjectMatches(subjects []Subject, name, digest string) bool {
	for _, subject := range subjects {
		if subject.Name == name && subject.Digest["sha256"] == digest {
			return true
		}
	}
	return false
}

func Verify(inputs Inputs, bundle Bundle) (Decision, error) {
	events, err := ParseEventStream(inputs.EventBytes)
	if err != nil {
		return Decision{}, err
	}
	policy, err := decodePolicy(inputs.PolicyBytes)
	if err != nil {
		return Decision{}, err
	}
	provenance, err := decodeStatement(inputs.ProvenanceBytes)
	if err != nil {
		return Decision{}, err
	}
	identity, err := provenanceIdentity(provenance)
	if err != nil {
		return Decision{}, err
	}
	if bundle.Manifest.Artifact.SHA256 != Digest(inputs.ArtifactBytes) {
		return Decision{Decision: "REJECT", Completeness: completeness(bundle.Manifest), Reasons: []Reason{{Code: "RPF-ARTIFACT-001", Effect: "REJECT", Message: "artifact digest does not match evidence manifest"}}}, nil
	}
	recomputed, err := Assemble(inputs)
	if err != nil {
		return Decision{}, err
	}
	reasons := make([]Reason, 0)
	addReject := func(code, message string) {
		reasons = append(reasons, Reason{Code: code, Effect: "REJECT", Message: message})
	}
	if !canonicalEqual(bundle.Graph, recomputed.Graph) {
		addReject("RPF-INTEGRITY-001", "execution graph differs from event-derived graph")
	}
	if !canonicalEqual(bundle.Manifest, recomputed.Manifest) {
		addReject("RPF-INTEGRITY-002", "evidence manifest differs from recomputed commitments")
	}
	if !canonicalEqual(bundle.RuntimeTrace, recomputed.RuntimeTrace) {
		addReject("RPF-INTEGRITY-003", "runtime trace differs from artifact/evidence/provenance binding")
	}
	if bundle.Manifest.Artifact.SHA256 != Digest(inputs.ArtifactBytes) {
		addReject("RPF-ARTIFACT-001", "artifact digest does not match evidence manifest")
	}
	if identity.BuildID != bundle.Manifest.BuildID || identity.RunIdentity != bundle.Manifest.RunIdentity {
		addReject("RPF-IDENTITY-001", "SLSA provenance identity differs from runtime evidence")
	}
	state := completeness(bundle.Manifest)
	if state != "complete" {
		reasons = append(reasons, Reason{Code: "RPF-EVIDENCE-001", Effect: policy.IncompleteDecision, Message: "runtime evidence is " + state})
	}
	if identity.RunIdentity.Provider != policy.ExpectedProvider {
		addReject("RPF-CI-001", "CI provider is not authorized by policy")
	}
	if !slices.Contains(policy.AllowedBuilderIDs, identity.BuilderID) {
		addReject("RPF-BUILDER-001", "provenance builder identity is not authorized by policy")
	}
	if !slices.Contains(policy.AllowedRepositories, identity.Source.Repository) {
		addReject("RPF-SOURCE-001", "source repository identity is not authorized by policy")
	}
	reasons = append(reasons, behaviorReasons(events, policy)...)
	decision := "ALLOW"
	for _, reason := range reasons {
		if reason.Effect == "REJECT" {
			decision = "REJECT"
			break
		}
		if reason.Effect == "REVIEW" {
			decision = "REVIEW"
		}
	}
	return Decision{Decision: decision, Completeness: state, Reasons: reasons}, nil
}

func provenanceIdentity(statement Statement) (Correlation, error) {
	rawDefinition, ok := statement.Predicate["buildDefinition"].(map[string]any)
	if !ok {
		return Correlation{}, errors.New("SLSA buildDefinition is missing")
	}
	rawInternal, ok := rawDefinition["internalParameters"].(map[string]any)
	if !ok {
		return Correlation{}, errors.New("SLSA internalParameters are missing")
	}
	rawIdentity, ok := rawInternal[BuildIdentityKey]
	if !ok {
		return Correlation{}, errors.New("SLSA build identity extension is missing")
	}
	raw, err := canonical(rawIdentity)
	if err != nil {
		return Correlation{}, err
	}
	var identity Correlation
	if err := decodeStrict(raw, &identity, maxDocumentBytes); err != nil {
		return Correlation{}, fmt.Errorf("SLSA build identity: %w", err)
	}
	if identity.BuildID == "" || identity.BuilderID == "" || identity.RunIdentity.RunID == "" || identity.Source.Revision == "" {
		return Correlation{}, errors.New("SLSA build identity is incomplete")
	}
	buildType, _ := rawDefinition["buildType"].(string)
	external, externalOK := rawDefinition["externalParameters"].(map[string]any)
	resolved, resolvedOK := rawDefinition["resolvedDependencies"].([]any)
	runDetails, runOK := statement.Predicate["runDetails"].(map[string]any)
	if buildType == "" || !externalOK || !resolvedOK || !runOK {
		return Correlation{}, errors.New("SLSA provenance v1 structure is incomplete")
	}
	if external["repository"] != identity.Source.Repository || external["revision"] != identity.Source.Revision {
		return Correlation{}, errors.New("SLSA external parameters conflict with build identity")
	}
	if !resolvedSourceMatches(resolved, identity.Source) {
		return Correlation{}, errors.New("SLSA resolved dependencies omit the correlated source revision")
	}
	builder, builderOK := runDetails["builder"].(map[string]any)
	metadata, metadataOK := runDetails["metadata"].(map[string]any)
	builderID, _ := builder["id"].(string)
	invocationID, _ := metadata["invocationId"].(string)
	startedOn, _ := metadata["startedOn"].(string)
	finishedOn, _ := metadata["finishedOn"].(string)
	if !builderOK || !metadataOK || builderID != identity.BuilderID || invocationID != identity.RunIdentity.RunID || startedOn == "" || finishedOn == "" {
		return Correlation{}, errors.New("SLSA run details conflict with build identity")
	}
	return identity, nil
}

func resolvedSourceMatches(dependencies []any, source SourceIdentity) bool {
	for _, raw := range dependencies {
		dependency, ok := raw.(map[string]any)
		if !ok || dependency["uri"] != source.Repository {
			continue
		}
		digest, ok := dependency["digest"].(map[string]any)
		if ok && digest["gitCommit"] == source.Revision {
			return true
		}
	}
	return false
}

func lossFromFinalEvent(event Event) Loss {
	if event.Operation != "sensor_finalized" {
		return Loss{CounterReadError: true}
	}
	return Loss{
		KernelReserve:     uintResource(event.Resource, "kernel_reserve"),
		KernelCorrelation: uintResource(event.Resource, "kernel_correlation"),
		Decode:            uintResource(event.Resource, "decode"),
		Queue:             uintResource(event.Resource, "queue"),
		Persistence:       uintResource(event.Resource, "persistence"),
		CounterReadError:  boolResource(event.Resource, "counter_read_error"),
	}
}

func uintResource(resource map[string]any, key string) uint64 {
	value, ok := resource[key]
	if !ok {
		return 1
	}
	switch number := value.(type) {
	case jsonNumber:
		parsed, err := number.Int64()
		if err == nil && parsed >= 0 {
			return uint64(parsed)
		}
	case float64:
		if number >= 0 && number == float64(uint64(number)) {
			return uint64(number)
		}
	}
	return 1
}

type jsonNumber interface{ Int64() (int64, error) }

func boolResource(resource map[string]any, key string) bool {
	value, ok := resource[key].(bool)
	return !ok || value
}

func behaviorReasons(events []Event, policy Policy) []Reason {
	reasons := make([]Reason, 0)
	for _, event := range events {
		switch event.Operation {
		case "process_exec":
			if event.Process != nil && !slices.Contains(policy.AllowedExecutables, event.Process.Executable.Path) {
				reasons = append(reasons, Reason{Code: "RPF-PROCESS-001", Effect: "REVIEW", Message: "executable is not declared by policy", Sequence: event.Sequence})
			}
		case "network_connect":
			destination, _ := event.Resource["destination"].(string)
			if destination == "" || !slices.Contains(policy.AllowedNetworkDestinations, destination) {
				reasons = append(reasons, Reason{Code: "RPF-EGRESS-001", Effect: "REJECT", Message: "network destination is not declared by policy", Sequence: event.Sequence})
			}
		case "file_open_sensitive":
			category, _ := event.Resource["category"].(string)
			if category == "" || slices.Contains(policy.ForbiddenSensitiveCategories, category) {
				reasons = append(reasons, Reason{Code: "RPF-SENSITIVE-001", Effect: "REJECT", Message: "forbidden sensitive-path category was accessed", Sequence: event.Sequence})
			}
		case "artifact_finalized":
			if event.Process == nil || !slices.Contains(policy.AllowedArtifactProducers, event.Process.Executable.Path) {
				reasons = append(reasons, Reason{Code: "RPF-ARTIFACT-PRODUCER-001", Effect: "REJECT", Message: "artifact-producing executable is not authorized by policy", Sequence: event.Sequence})
			}
		}
	}
	return reasons
}

func toMap(value any) (map[string]any, error) {
	raw, err := canonical(value)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := decodeStrict(raw, &result, maxDocumentBytes); err != nil {
		return nil, err
	}
	return result, nil
}

func canonicalEqual(left, right any) bool {
	a, errA := canonical(left)
	b, errB := canonical(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func ReadInputs(artifactPath, eventPath, provenancePath, policyPath string) (Inputs, error) {
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		return Inputs{}, err
	}
	events, err := os.ReadFile(eventPath)
	if err != nil {
		return Inputs{}, err
	}
	provenance, err := os.ReadFile(provenancePath)
	if err != nil {
		return Inputs{}, err
	}
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		return Inputs{}, err
	}
	return Inputs{ArtifactBytes: artifact, ArtifactName: filepath.Base(artifactPath), EventBytes: events, ProvenanceBytes: provenance, PolicyBytes: policy}, nil
}

func WriteBundle(directory string, bundle Bundle) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	files := map[string]any{
		"execution-graph.json":   bundle.Graph,
		"evidence-manifest.json": bundle.Manifest,
		"runtime-trace.json":     bundle.RuntimeTrace,
	}
	for name, value := range files {
		raw, err := canonical(value)
		if err != nil {
			return err
		}
		raw = append(raw, '\n')
		path := filepath.Join(directory, name)
		temporary := path + ".tmp"
		if err := os.WriteFile(temporary, raw, 0o600); err != nil {
			return err
		}
		if err := os.Rename(temporary, path); err != nil {
			return err
		}
	}
	return nil
}

func WriteCanonicalExclusive(path string, value any) error {
	raw, err := canonical(value)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = output.Close()
		_ = os.Remove(path)
	}
	if _, err := output.Write(raw); err != nil {
		cleanup()
		return err
	}
	if err := output.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func LoadBundle(directory string) (Bundle, error) {
	read := func(name string, target any) error {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		return decodeStrict(raw, target, maxDocumentBytes)
	}
	var bundle Bundle
	if err := read("execution-graph.json", &bundle.Graph); err != nil {
		return Bundle{}, err
	}
	if err := read("evidence-manifest.json", &bundle.Manifest); err != nil {
		return Bundle{}, err
	}
	if err := read("runtime-trace.json", &bundle.RuntimeTrace); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}
