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

type request struct {
	TargetIdentity string `json:"target_identity"`
	SessionRole    string `json:"session_role"`
	AdapterRole    string `json:"adapter_role"`
}

type response struct {
	Granted bool   `json:"granted"`
	Marker  string `json:"marker"`
	Reason  string `json:"reason"`
}

func main() {
	address := flag.String("address", "127.0.0.1:18081", "fixed lab target")
	expect := flag.String("expect", "", "grant or deny")
	flag.Parse()
	if err := prove(*address, *expect); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func prove(address, expect string) error {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || !endpoint.Addr().IsLoopback() || (expect != "grant" && expect != "deny") {
		return errors.New("proof requires numeric loopback target and grant/deny expectation")
	}
	connection, err := net.DialTimeout("tcp4", endpoint.String(), 2*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	input := request{TargetIdentity: "rpf-authz-fixture-v1", SessionRole: "builder-reader", AdapterRole: "builder-admin"}
	if err := json.NewEncoder(connection).Encode(input); err != nil {
		return err
	}
	var output response
	decoder := json.NewDecoder(bufio.NewReaderSize(connection, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return err
	}
	if expect == "grant" && (!output.Granted || output.Marker != "RPF_SYNTHETIC_ADMIN_MARKER") {
		return errors.New("vulnerable proof did not obtain synthetic marker")
	}
	if expect == "deny" && (output.Granted || output.Marker != "") {
		return errors.New("patched target did not deny proof")
	}
	fmt.Printf("granted=%t reason=%s\n", output.Granted, output.Reason)
	return nil
}
