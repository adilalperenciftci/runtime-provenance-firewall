package rpf

import "testing"

func FuzzParseEventStream(f *testing.F) {
	f.Add(fixtureInputs(f, nil).EventBytes)
	f.Add([]byte("{}\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseEventStream(raw)
	})
}

func FuzzDecodePolicy(f *testing.F) {
	f.Add(fixtureInputs(f, nil).PolicyBytes)
	f.Add([]byte(`{"schema_version":"0.1"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = decodePolicy(raw)
	})
}

func FuzzDecodeStatement(f *testing.F) {
	f.Add(fixtureInputs(f, nil).ProvenanceBytes)
	f.Add([]byte(`{"_type":"https://in-toto.io/Statement/v1"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = decodeStatement(raw)
	})
}
