//go:build linux

package main

import "testing"

func TestIsDisposableLabCgroup(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		"/sys/fs/cgroup/rpf-build":              true,
		"/sys/fs/cgroup/rpf-":                   true,
		"/sys/fs/cgroup/build":                  false,
		"/sys/fs/cgroup/rpf-build/nested":       false,
		"/sys/fs/cgroup-other/rpf-build":        false,
		"/sys/fs/cgroup/rpf-build/cgroup.procs": false,
	}
	for path, want := range tests {
		if got := isDisposableLabCgroup(path); got != want {
			t.Errorf("isDisposableLabCgroup(%q) = %v, want %v", path, got, want)
		}
	}
}
