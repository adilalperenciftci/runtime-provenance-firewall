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
	address := flag.String("address", "127.0.0.1:18080", "fixed lab callback address")
	flag.Parse()
	if err := run(*address); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(address string) error {
	target, err := netip.ParseAddrPort(address)
	if err != nil || !target.Addr().IsLoopback() {
		return errors.New("lab callback target must be a numeric loopback address")
	}
	connection, err := net.DialTimeout("tcp4", target.String(), 2*time.Second)
	if err != nil {
		return fmt.Errorf("connect to local mock: %w", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte{0x52}); err != nil {
		return fmt.Errorf("write marker byte: %w", err)
	}
	return nil
}
