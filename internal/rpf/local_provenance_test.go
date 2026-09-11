package rpf

import "testing"

func TestCreateLocalFixtureProvenanceRoundTrip(t *testing.T) {
	inputs := fixtureInputs(t, nil)
	events, err := ParseEventStream(inputs.EventBytes)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := CreateLocalFixtureProvenance("artifact", inputs.ArtifactBytes, events, "https://example.test/repo", "1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonical(statement)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeStatement(raw)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provenanceIdentity(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if identity.BuildID != events[0].Build.BuildID || identity.Source.Repository != "https://example.test/repo" {
		t.Fatalf("unexpected provenance identity: %+v", identity)
	}
}
