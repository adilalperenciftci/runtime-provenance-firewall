//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/adilalperenciftci/runtime-provenance-firewall/internal/rpf"
	"github.com/adilalperenciftci/runtime-provenance-firewall/internal/sensor"
	"golang.org/x/sys/unix"
)

const maxTrackedProcesses = 65_536

type sensorConfiguration struct {
	ObjectSHA256        string `json:"object_sha256"`
	CgroupID            uint64 `json:"cgroup_id"`
	CgroupPathSHA256    string `json:"cgroup_path_sha256"`
	Repository          string `json:"repository"`
	Revision            string `json:"revision"`
	SensitivePathSHA256 string `json:"sensitive_path_sha256"`
	SensitiveCategory   string `json:"sensitive_category"`
}

func main() {
	objectPath := flag.String("object", "", "compiled CO-RE BPF object")
	cgroupID := flag.Uint64("cgroup-id", 0, "target cgroup v2 ID")
	cgroupPath := flag.String("cgroup-path", "", "target cgroup v2 filesystem path")
	buildID := flag.String("build-id", "", "unique build execution ID")
	runID := flag.String("run-id", "", "CI or local run ID")
	repository := flag.String("repository", "", "source repository identity asserted by build registration")
	revision := flag.String("revision", "", "source revision asserted by build registration")
	bootID := flag.String("boot-id", "", "host boot ID")
	cgroupPathHash := flag.String("cgroup-path-hash", "", "SHA-256 commitment to registered cgroup path")
	outputPath := flag.String("output", "", "new canonical evidence JSONL file")
	artifactPath := flag.String("artifact", "", "absolute artifact path to finalize after monitoring")
	sensitivePath := flag.String("sensitive-path", "", "optional exact absolute synthetic-sensitive path")
	sensitiveCategory := flag.String("sensitive-category", "", "category emitted for the configured sensitive path")
	flag.Parse()
	if *objectPath == "" || *cgroupID == 0 || *cgroupPath == "" || *buildID == "" || *runID == "" ||
		*repository == "" || *revision == "" || *bootID == "" || *cgroupPathHash == "" || *outputPath == "" || *artifactPath == "" {
		fatal("--object, --output, --artifact, --build-id, --run-id, --repository, --revision, --boot-id, --cgroup-path, --cgroup-path-hash, and non-zero --cgroup-id are required")
	}
	if !filepath.IsAbs(*artifactPath) {
		fatal("--artifact must be an absolute path")
	}
	if (*sensitivePath == "") != (*sensitiveCategory == "") {
		fatal("--sensitive-path and --sensitive-category must be supplied together")
	}
	if *sensitivePath != "" && !filepath.IsAbs(*sensitivePath) {
		fatal("--sensitive-path must be absolute")
	}
	if expected := "sha256:" + rpf.Digest([]byte(*cgroupPath)); *cgroupPathHash != expected {
		fatal("--cgroup-path-hash does not match --cgroup-path")
	}
	object, err := os.ReadFile(*objectPath)
	if err != nil {
		fatal("read BPF object: %v", err)
	}
	configDigest, err := digestSensorConfiguration(sensorConfiguration{
		ObjectSHA256: rpf.Digest(object), CgroupID: *cgroupID,
		CgroupPathSHA256: rpf.Digest([]byte(*cgroupPath)), Repository: *repository, Revision: *revision,
		SensitivePathSHA256: rpf.Digest([]byte(*sensitivePath)), SensitiveCategory: *sensitiveCategory,
	})
	if err != nil {
		fatal("encode sensor configuration: %v", err)
	}
	source := rpf.Sensor{Name: "rpf-sensor", Version: "0.2.0", ConfigDigest: configDigest}
	build := rpf.BuildScope{BuildID: *buildID, RunID: *runID, Source: rpf.SourceIdentity{Repository: *repository, Revision: *revision}, BootID: *bootID, CgroupID: *cgroupID, CgroupPathHash: *cgroupPathHash}
	chain, err := rpf.NewEventChain(build, source)
	if err != nil {
		fatal("initialize event chain: %v", err)
	}
	monitor, err := sensor.Open(*objectPath, sensor.Config{CgroupID: *cgroupID, CgroupPath: *cgroupPath, SensitivePath: *sensitivePath})
	if err != nil {
		fatal("open sensor: %v", err)
	}
	defer monitor.Close()
	evidence, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		fatal("create evidence stream: %v", err)
	}
	defer evidence.Close()
	writeEvent(evidence, chain, rpf.Event{
		ObservedAt: now(), MonotonicNS: boottimeNS(), Operation: "sensor_started",
		Resource: map[string]any{"target_cgroup_id": *cgroupID}, Outcome: rpf.Outcome{Status: "success"},
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	processes := make(map[string]rpf.Process)
	var artifactProducer *rpf.Process
	var decodeLoss uint64
	for {
		event, err := monitor.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			fatal("read sensor: %v", err)
		}
		process := processFromKernel(event, *bootID)
		switch event.Kind {
		case sensor.EventExec:
			process.Executable = rpf.Executable{Path: event.Filename, Identity: event.Filename, IdentityKind: "path_only"}
			if _, exists := processes[process.ProcessKey]; exists || len(processes) < maxTrackedProcesses {
				processes[process.ProcessKey] = process
			} else {
				decodeLoss++
			}
			writeEvent(evidence, chain, rpf.Event{
				ObservedAt: now(), MonotonicNS: event.MonotonicNS, Process: &process,
				Operation: "process_exec", Resource: map[string]any{}, Outcome: rpf.Outcome{Status: "success"},
			})
		case sensor.EventOpen:
			observed, ok := processes[process.ProcessKey]
			if !ok {
				decodeLoss++
				continue
			}
			writeEvent(evidence, chain, rpf.Event{
				ObservedAt: now(), MonotonicNS: event.MonotonicNS, Process: &observed,
				Operation: "file_open_output", Resource: map[string]any{"path": event.Filename, "flags": event.Flags},
				Outcome: rpf.Outcome{Status: "success"},
			})
			if event.Filename == *artifactPath {
				producer := observed
				artifactProducer = &producer
			}
		case sensor.EventSensitive:
			observed, ok := processes[process.ProcessKey]
			if !ok {
				decodeLoss++
				continue
			}
			writeEvent(evidence, chain, rpf.Event{
				ObservedAt: now(), MonotonicNS: event.MonotonicNS, Process: &observed,
				Operation: "file_open_sensitive", Resource: map[string]any{"category": *sensitiveCategory},
				Outcome: rpf.Outcome{Status: "success"},
			})
		case sensor.EventConnect4:
			observed, ok := processes[process.ProcessKey]
			if !ok || event.DestinationPort > 65535 {
				decodeLoss++
				continue
			}
			writeEvent(evidence, chain, rpf.Event{
				ObservedAt: now(), MonotonicNS: event.MonotonicNS, Process: &observed,
				Operation: "network_connect",
				Resource:  map[string]any{"destination": ipv4Destination(event.DestinationIPv4, uint16(event.DestinationPort)), "protocol": event.Protocol},
				Outcome:   rpf.Outcome{Status: "attempted"},
			})
		}
	}
	if artifactProducer == nil {
		fatal("artifact path had no attributable successful write-open: %s", *artifactPath)
	}
	artifactHash, err := digestFile(*artifactPath)
	if err != nil {
		fatal("hash artifact: %v", err)
	}
	writeEvent(evidence, chain, rpf.Event{
		ObservedAt: now(), MonotonicNS: boottimeNS(), Process: artifactProducer,
		Operation: "artifact_finalized", Resource: map[string]any{"path": *artifactPath, "sha256": artifactHash},
		Outcome: rpf.Outcome{Status: "success"},
	})
	loss, err := monitor.Loss()
	counterReadError := err != nil
	writeEvent(evidence, chain, rpf.Event{
		ObservedAt: now(), MonotonicNS: boottimeNS(), Operation: "sensor_finalized",
		Resource: map[string]any{
			"kernel_reserve": loss.RingBuffer, "kernel_correlation": loss.Correlation,
			"kernel_path_read": loss.PathRead, "kernel_map_update": loss.MapUpdate,
			"kernel_cgroup_mismatch": loss.CgroupMismatch,
			"decode":                 decodeLoss, "queue": 0, "persistence": 0,
			"counter_read_error": counterReadError,
		},
		Outcome: rpf.Outcome{Status: "success"},
	})
	if counterReadError {
		fatal("read loss counter: %v", err)
	}
}

func digestSensorConfiguration(config sensorConfiguration) (string, error) {
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return "sha256:" + rpf.Digest(encoded), nil
}

func ipv4Destination(address uint32, port uint16) string {
	var octets [4]byte
	binary.LittleEndian.PutUint32(octets[:], address)
	return netip.AddrPortFrom(netip.AddrFrom4(octets), port).String()
}

func processFromKernel(event sensor.KernelEvent, bootID string) rpf.Process {
	parentKey := rpf.ProcessKey(bootID, uint64(event.ParentPIDNamespace), event.PPID, event.ParentStartTimeNS)
	return rpf.Process{
		ProcessKey: rpf.ProcessKey(bootID, uint64(event.PIDNamespace), event.TGID, event.StartTimeNS),
		ParentKey:  parentKey, PID: event.PID, TGID: event.TGID, PPID: event.PPID,
		StartTimeNS: event.StartTimeNS, PIDNamespace: uint64(event.PIDNamespace),
		MountNamespace: uint64(event.MountNamespace), UID: event.UID, GID: event.GID,
		Executable: rpf.Executable{Path: event.Filename, Identity: event.Filename, IdentityKind: "path_only"},
	}
}

func digestFile(path string) (string, error) {
	artifact, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer artifact.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, artifact); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func writeEvent(output *os.File, chain *rpf.EventChain, event rpf.Event) {
	raw, err := chain.Append(event)
	if err != nil {
		fatal("chain event: %v", err)
	}
	if _, err := output.Write(raw); err != nil {
		fatal("persist event: %v", err)
	}
	if err := output.Sync(); err != nil {
		fatal("sync event: %v", err)
	}
}

func boottimeNS() uint64 {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &value); err != nil {
		fatal("read monotonic boot clock: %v", err)
	}
	return uint64(value.Sec)*1_000_000_000 + uint64(value.Nsec)
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func fatal(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(4)
}
