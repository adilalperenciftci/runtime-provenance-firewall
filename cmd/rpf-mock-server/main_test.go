package main

import "testing"

func TestRejectsNonLoopbackListener(t *testing.T) {
	if err := serve("0.0.0.0:18080", "unused"); err == nil {
		t.Fatal("non-loopback listener accepted")
	}
}
