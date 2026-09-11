//go:build linux

package main

import "testing"

func TestIPv4Destination(t *testing.T) {
	if got := ipv4Destination(0x0100007f, 18080); got != "127.0.0.1:18080" {
		t.Fatalf("got %q", got)
	}
}

func TestSensorConfigurationDigestHasUnambiguousFields(t *testing.T) {
	left, err := digestSensorConfiguration(sensorConfiguration{Repository: "repo\nrevision=other", Revision: "revision"})
	if err != nil {
		t.Fatal(err)
	}
	right, err := digestSensorConfiguration(sensorConfiguration{Repository: "repo", Revision: "other\nrevision=revision"})
	if err != nil {
		t.Fatal(err)
	}
	if left == right {
		t.Fatal("distinct registration fields produced the same configuration commitment")
	}
}
