//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const labUID = 65534

func main() {
	// Linux credentials are per-thread. Keep the cgroup move, credential changes,
	// and exec on one OS thread so the Go scheduler cannot restore a privileged
	// thread between those operations.
	runtime.LockOSThread()
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) < 4 || arguments[0] != "--cgroup" || arguments[2] != "--" {
		return errors.New("usage: rpf-cgroup-enter --cgroup /sys/fs/cgroup/rpf-* -- PROGRAM [ARG...]")
	}
	if os.Geteuid() != 0 {
		return errors.New("cgroup entry and credential drop require root")
	}
	cgroup, err := filepath.EvalSymlinks(arguments[1])
	if err != nil {
		return fmt.Errorf("resolve cgroup: %w", err)
	}
	if !isDisposableLabCgroup(cgroup) {
		return errors.New("refusing cgroup outside the disposable rpf lab prefix")
	}
	target, err := filepath.Abs(arguments[3])
	if err != nil || target != arguments[3] {
		return errors.New("target executable must be an absolute path")
	}
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return fmt.Errorf("enter cgroup: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if err := unix.Setgroups([]int{}); err != nil {
		return fmt.Errorf("clear supplementary groups: %w", err)
	}
	if err := unix.Setgid(labUID); err != nil {
		return fmt.Errorf("drop gid: %w", err)
	}
	if err := unix.Setuid(labUID); err != nil {
		return fmt.Errorf("drop uid: %w", err)
	}
	environment := []string{"HOME=/nonexistent", "LANG=C", "PATH=/usr/bin:/bin", "RPF_DISPOSABLE_LAB=1"}
	return unix.Exec(target, arguments[3:], environment)
}

func isDisposableLabCgroup(path string) bool {
	return filepath.Dir(path) == "/sys/fs/cgroup" && strings.HasPrefix(filepath.Base(path), "rpf-")
}
