package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"
)

const targetIdentity = "rpf-authz-fixture-v1"

type request struct {
	TargetIdentity string `json:"target_identity"`
	SessionRole    string `json:"session_role"`
	AdapterRole    string `json:"adapter_role"`
}

type response struct {
	Granted bool   `json:"granted"`
	Marker  string `json:"marker,omitempty"`
	Reason  string `json:"reason"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18081", "fixed loopback lab address")
	mode := flag.String("mode", "", "intentionally-vulnerable or patched")
	ready := flag.String("ready-file", "", "new readiness marker")
	flag.Parse()
	if err := serve(*listen, *mode, *ready); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func authorize(mode string, input request) response {
	if input.TargetIdentity != targetIdentity {
		return response{Reason: "target_identity_mismatch"}
	}
	role := input.SessionRole
	if mode == "intentionally-vulnerable" {
		role = input.AdapterRole // Deliberate local fixture flaw: trusts request metadata.
	}
	if role != "builder-admin" {
		return response{Reason: "authorization_denied"}
	}
	return response{Granted: true, Marker: "RPF_SYNTHETIC_ADMIN_MARKER", Reason: "authorized"}
}

func serve(address, mode, readyPath string) error {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || !endpoint.Addr().IsLoopback() || readyPath == "" {
		return errors.New("target requires numeric loopback address and readiness path")
	}
	if mode != "intentionally-vulnerable" && mode != "patched" {
		return errors.New("target mode must be intentionally-vulnerable or patched")
	}
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(endpoint))
	if err != nil {
		return err
	}
	defer listener.Close()
	ready, err := os.OpenFile(readyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := ready.Close(); err != nil {
		return err
	}
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	connection, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	decoder := json.NewDecoder(bufio.NewReaderSize(connection, 4096))
	decoder.DisallowUnknownFields()
	var input request
	if err := decoder.Decode(&input); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	return json.NewEncoder(connection).Encode(authorize(mode, input))
}
