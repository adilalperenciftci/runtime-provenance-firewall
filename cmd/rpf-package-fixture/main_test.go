//go:build linux

package main

import "testing"

func TestManifestPathIsFixed(t *testing.T) {
	t.Parallel()
	if labManifest != "/src/lab/fixtures/synthetic-package-lock.json" {
		t.Fatalf("unexpected manifest path: %q", labManifest)
	}
}
