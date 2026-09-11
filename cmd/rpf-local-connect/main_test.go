package main

import "testing"

func TestRejectsNonLoopbackBeforeConnecting(t *testing.T) {
	if err := run("192.0.2.1:18080"); err == nil {
		t.Fatal("non-loopback callback target accepted")
	}
}
