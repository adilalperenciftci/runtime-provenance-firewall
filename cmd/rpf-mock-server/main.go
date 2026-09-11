package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"
)

func main() {
	address := flag.String("listen", "127.0.0.1:18080", "fixed lab listen address")
	readyPath := flag.String("ready-file", "", "new readiness marker path")
	flag.Parse()
	if err := serve(*address, *readyPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(address, readyPath string) error {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || !endpoint.Addr().IsLoopback() || readyPath == "" {
		return errors.New("mock server requires numeric loopback listen address and ready file")
	}
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(endpoint))
	if err != nil {
		return fmt.Errorf("listen on local mock: %w", err)
	}
	defer listener.Close()
	ready, err := os.OpenFile(readyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create readiness marker: %w", err)
	}
	if err := ready.Close(); err != nil {
		return fmt.Errorf("close readiness marker: %w", err)
	}
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	connection, err := listener.AcceptTCP()
	if err != nil {
		return fmt.Errorf("accept local callback: %w", err)
	}
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	var marker [1]byte
	if _, err := connection.Read(marker[:]); err != nil {
		return fmt.Errorf("read local marker: %w", err)
	}
	if marker[0] != 0x52 {
		return errors.New("unexpected local marker")
	}
	return nil
}
