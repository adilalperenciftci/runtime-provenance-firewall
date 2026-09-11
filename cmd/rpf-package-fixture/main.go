//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

const labManifest = "/src/lab/fixtures/synthetic-package-lock.json"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	set := flag.NewFlagSet("rpf-package-fixture", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	manifest := set.String("manifest", "", "repository-owned synthetic package manifest")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if set.NArg() != 0 || *manifest != labManifest {
		return errors.New("--manifest must be the repository-owned synthetic package manifest")
	}
	if os.Getenv("RPF_DISPOSABLE_LAB") != "1" {
		return errors.New("refusing to run outside the disposable repository lab")
	}
	data, err := os.ReadFile(*manifest)
	if err != nil {
		return fmt.Errorf("read synthetic package manifest: %w", err)
	}
	if !json.Valid(data) {
		return errors.New("synthetic package manifest is not valid JSON")
	}
	fmt.Println("rpf-credential-independent-package-install")
	return nil
}
