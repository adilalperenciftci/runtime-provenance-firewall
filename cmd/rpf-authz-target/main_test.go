package main

import "testing"

func TestVulnerableAndPatchedAuthorizationBoundary(t *testing.T) {
	input := request{TargetIdentity: targetIdentity, SessionRole: "builder-reader", AdapterRole: "builder-admin"}
	if got := authorize("intentionally-vulnerable", input); !got.Granted || got.Marker == "" {
		t.Fatalf("vulnerability not reproducible: %+v", got)
	}
	if got := authorize("patched", input); got.Granted || got.Marker != "" {
		t.Fatalf("patched mode crossed boundary: %+v", got)
	}
}

func TestWrongTargetIdentityAlwaysDenied(t *testing.T) {
	input := request{TargetIdentity: "other", SessionRole: "builder-admin", AdapterRole: "builder-admin"}
	for _, mode := range []string{"intentionally-vulnerable", "patched"} {
		if got := authorize(mode, input); got.Granted {
			t.Fatalf("%s accepted wrong fixture identity", mode)
		}
	}
}

func TestPatchedModePreservesAuthorizedAdmin(t *testing.T) {
	input := request{TargetIdentity: targetIdentity, SessionRole: "builder-admin", AdapterRole: "builder-reader"}
	if got := authorize("patched", input); !got.Granted || got.Marker != "RPF_SYNTHETIC_ADMIN_MARKER" {
		t.Fatalf("patched mode broke authorized behavior: %+v", got)
	}
}
