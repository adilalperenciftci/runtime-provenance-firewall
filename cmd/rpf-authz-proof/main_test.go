package main

import "testing"

func TestProofRejectsExternalTarget(t *testing.T) {
	if err := prove("192.0.2.1:18081", "grant"); err == nil {
		t.Fatal("external target accepted")
	}
}
