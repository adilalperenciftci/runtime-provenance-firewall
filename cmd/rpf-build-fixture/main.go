//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const labOutputRoot = "/src/build/out"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	set := flag.NewFlagSet("rpf-build-fixture", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	artifact := set.String("artifact", "", "pre-created synthetic artifact path")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if set.NArg() != 0 || !isLabOutput(*artifact) {
		return errors.New("--artifact must be an absolute file directly under /src/build/out")
	}
	if os.Getenv("RPF_DISPOSABLE_LAB") != "1" {
		return errors.New("refusing to run outside the disposable repository lab")
	}
	if err := writeArtifact(*artifact); err != nil {
		return fmt.Errorf("write synthetic artifact: %w", err)
	}
	fmt.Println("rpf-synthetic-build")
	return nil
}

func writeArtifact(path string) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("synthetic artifact must be a pre-created regular file")
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.WriteString("rpf-artifact-v1"); err != nil {
		return err
	}
	return file.Sync()
}

func isLabOutput(path string) bool {
	clean := filepath.Clean(path)
	return filepath.IsAbs(path) && filepath.Dir(clean) == labOutputRoot &&
		strings.HasPrefix(filepath.Base(clean), "sensor-") && strings.HasSuffix(filepath.Base(clean), "-artifact.txt")
}
