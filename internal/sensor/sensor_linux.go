//go:build linux

package sensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	commLength     = 16
	pathLength     = 256
	EventExec      = 1
	EventOpen      = 2
	EventSensitive = 3
	EventConnect4  = 4
)

type KernelEvent struct {
	MonotonicNS        uint64 `json:"monotonic_ns"`
	CgroupID           uint64 `json:"cgroup_id"`
	StartTimeNS        uint64 `json:"start_time_ns"`
	ParentStartTimeNS  uint64 `json:"parent_start_time_ns"`
	PID                uint32 `json:"pid"`
	TGID               uint32 `json:"tgid"`
	PPID               uint32 `json:"ppid"`
	UID                uint32 `json:"uid"`
	GID                uint32 `json:"gid"`
	PIDNamespace       uint32 `json:"pid_namespace"`
	MountNamespace     uint32 `json:"mount_namespace"`
	ParentPIDNamespace uint32 `json:"parent_pid_namespace"`
	Kind               uint32 `json:"kind"`
	Flags              uint32 `json:"flags"`
	DestinationIPv4    uint32 `json:"destination_ipv4"`
	DestinationPort    uint32 `json:"destination_port"`
	Protocol           uint32 `json:"protocol"`
	Command            string `json:"command"`
	Filename           string `json:"filename"`
}

type wireExecEvent struct {
	MonotonicNS        uint64
	CgroupID           uint64
	StartTimeNS        uint64
	ParentStartTimeNS  uint64
	PID                uint32
	TGID               uint32
	PPID               uint32
	UID                uint32
	GID                uint32
	PIDNamespace       uint32
	MountNamespace     uint32
	ParentPIDNamespace uint32
	Kind               uint32
	Flags              uint32
	DestinationIPv4    uint32
	DestinationPort    uint32
	Protocol           uint32
	Command            [commLength]byte
	Filename           [pathLength]byte
	Padding            [4]byte
}

type Sensor struct {
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
}

type LossCounters struct {
	RingBuffer     uint64
	Correlation    uint64
	PathRead       uint64
	MapUpdate      uint64
	CgroupMismatch uint64
}

type Config struct {
	CgroupID      uint64
	CgroupPath    string
	SensitivePath string
}

func Open(objectPath string, config Config) (*Sensor, error) {
	if config.CgroupID == 0 {
		return nil, errors.New("target cgroup ID must be non-zero")
	}
	if config.CgroupPath == "" {
		return nil, errors.New("target cgroup path is empty")
	}
	cgroupInfo, err := os.Stat(config.CgroupPath)
	if err != nil {
		return nil, fmt.Errorf("stat target cgroup: %w", err)
	}
	stat, ok := cgroupInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino != config.CgroupID {
		return nil, errors.New("target cgroup path and ID do not match")
	}
	if len(config.SensitivePath) >= pathLength {
		return nil, errors.New("sensitive path exceeds kernel record limit")
	}
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load BPF object: %w", err)
	}
	target, ok := spec.Variables["target_cgroup_id"]
	if !ok {
		return nil, errors.New("BPF object lacks target_cgroup_id variable")
	}
	if err := target.Set(config.CgroupID); err != nil {
		return nil, fmt.Errorf("set target cgroup: %w", err)
	}
	sensitive, ok := spec.Variables["target_sensitive_path"]
	if !ok {
		return nil, errors.New("BPF object lacks target_sensitive_path variable")
	}
	var sensitivePath [pathLength]byte
	copy(sensitivePath[:], config.SensitivePath)
	if err := sensitive.Set(sensitivePath); err != nil {
		return nil, fmt.Errorf("set target sensitive path: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection: %w", err)
	}
	links := make([]link.Link, 0, 3)
	attach := func(group, name, programName string) error {
		program := collection.Programs[programName]
		if program == nil {
			return fmt.Errorf("BPF object lacks %s program", programName)
		}
		attached, attachErr := link.Tracepoint(group, name, program, nil)
		if attachErr != nil {
			return fmt.Errorf("attach %s:%s tracepoint: %w", group, name, attachErr)
		}
		links = append(links, attached)
		return nil
	}
	for _, target := range [][3]string{
		{"sched", "sched_process_exec", "observe_exec"},
		{"syscalls", "sys_enter_openat", "observe_openat_enter"},
		{"syscalls", "sys_exit_openat", "observe_openat_exit"},
	} {
		if err := attach(target[0], target[1], target[2]); err != nil {
			closeLinks(links)
			collection.Close()
			return nil, err
		}
	}
	connectProgram := collection.Programs["observe_connect4"]
	if connectProgram == nil {
		closeLinks(links)
		collection.Close()
		return nil, errors.New("BPF object lacks observe_connect4 program")
	}
	connectLink, err := link.AttachCgroup(link.CgroupOptions{
		Path: config.CgroupPath, Attach: ebpf.AttachCGroupInet4Connect, Program: connectProgram,
	})
	if err != nil {
		closeLinks(links)
		collection.Close()
		return nil, fmt.Errorf("attach cgroup connect4 program: %w", err)
	}
	links = append(links, connectLink)
	events := collection.Maps["events"]
	if events == nil {
		closeLinks(links)
		collection.Close()
		return nil, errors.New("BPF object lacks events map")
	}
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		closeLinks(links)
		collection.Close()
		return nil, fmt.Errorf("open events ring buffer: %w", err)
	}
	return &Sensor{collection: collection, links: links, reader: reader}, nil
}

func (sensor *Sensor) Read(ctx context.Context) (KernelEvent, error) {
	if sensor == nil || sensor.reader == nil {
		return KernelEvent{}, errors.New("sensor is not open")
	}
	for {
		if err := ctx.Err(); err != nil {
			return KernelEvent{}, err
		}
		deadline := time.Now().Add(250 * time.Millisecond)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		sensor.reader.SetDeadline(deadline)
		record, err := sensor.reader.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return KernelEvent{}, err
		}
		return decodeEvent(record.RawSample)
	}
}

func decodeEvent(raw []byte) (KernelEvent, error) {
	var wire wireExecEvent
	if len(raw) != binary.Size(wire) {
		return KernelEvent{}, fmt.Errorf("kernel sample has size %d, expected %d", len(raw), binary.Size(wire))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &wire); err != nil {
		return KernelEvent{}, fmt.Errorf("decode kernel sample: %w", err)
	}
	if wire.Kind != EventExec && wire.Kind != EventOpen && wire.Kind != EventSensitive && wire.Kind != EventConnect4 {
		return KernelEvent{}, fmt.Errorf("unsupported kernel event kind %d", wire.Kind)
	}
	return KernelEvent{
		MonotonicNS: wire.MonotonicNS, CgroupID: wire.CgroupID,
		StartTimeNS: wire.StartTimeNS, ParentStartTimeNS: wire.ParentStartTimeNS,
		PID: wire.PID, TGID: wire.TGID, PPID: wire.PPID, UID: wire.UID, GID: wire.GID,
		PIDNamespace: wire.PIDNamespace, MountNamespace: wire.MountNamespace,
		ParentPIDNamespace: wire.ParentPIDNamespace,
		Kind:               wire.Kind,
		Flags:              wire.Flags,
		DestinationIPv4:    wire.DestinationIPv4,
		DestinationPort:    wire.DestinationPort,
		Protocol:           wire.Protocol,
		Command:            cString(wire.Command[:]), Filename: cString(wire.Filename[:]),
	}, nil
}

func cString(value []byte) string {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		value = value[:index]
	}
	return string(value)
}

func (sensor *Sensor) Loss() (LossCounters, error) {
	if sensor == nil || sensor.collection == nil {
		return LossCounters{}, errors.New("sensor is not open")
	}
	read := func(name string) (uint64, error) {
		lossMap := sensor.collection.Maps[name]
		if lossMap == nil {
			return 0, fmt.Errorf("BPF object lacks %s map", name)
		}
		var perCPU []uint64
		if err := lossMap.Lookup(uint32(0), &perCPU); err != nil {
			return 0, fmt.Errorf("read %s: %w", name, err)
		}
		var total uint64
		for _, value := range perCPU {
			total += value
		}
		return total, nil
	}
	ring, err := read("ringbuf_drops")
	if err != nil {
		return LossCounters{}, err
	}
	correlation, err := read("correlation_drops")
	if err != nil {
		return LossCounters{}, err
	}
	pathRead, err := read("path_read_drops")
	if err != nil {
		return LossCounters{}, err
	}
	mapUpdate, err := read("map_update_drops")
	if err != nil {
		return LossCounters{}, err
	}
	cgroupMismatch, err := read("cgroup_mismatch_drops")
	if err != nil {
		return LossCounters{}, err
	}
	return LossCounters{RingBuffer: ring, Correlation: correlation, PathRead: pathRead,
		MapUpdate: mapUpdate, CgroupMismatch: cgroupMismatch}, nil
}

func (sensor *Sensor) Close() error {
	if sensor == nil {
		return nil
	}
	var result error
	if sensor.reader != nil {
		result = errors.Join(result, sensor.reader.Close())
	}
	result = errors.Join(result, closeLinks(sensor.links))
	if sensor.collection != nil {
		sensor.collection.Close()
	}
	return result
}

func closeLinks(links []link.Link) error {
	var result error
	for _, attached := range links {
		result = errors.Join(result, attached.Close())
	}
	return result
}

var _ io.Closer = (*Sensor)(nil)
