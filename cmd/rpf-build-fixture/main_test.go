//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsLabOutput(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		"/src/build/out/sensor-test-artifact.txt":        true,
		"/src/build/out/sensor-replay-artifact.txt":      true,
		"/src/build/out/other":                           false,
		"/src/build/out/nested/sensor-test-artifact.txt": false,
		"/tmp/sensor-test-artifact.txt":                  false,
		"sensor-test-artifact.txt":                       false,
	}
	for path, want := range tests {
		if got := isLabOutput(path); got != want {
			t.Errorf("isLabOutput(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestWriteArtifactRejectsSymlink(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeArtifact(link); err == nil {
		t.Fatal("writeArtifact accepted a symbolic link")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "unchanged" {
		t.Fatalf("symlink target changed to %q", content)
	}
}
