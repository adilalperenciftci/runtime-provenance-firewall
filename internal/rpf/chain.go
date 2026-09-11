package rpf

import (
	"errors"
	"fmt"
)

// EventChain assigns immutable stream metadata and hashes events in append order.
// It is intentionally not safe for concurrent writers.
type EventChain struct {
	build    BuildScope
	sensor   Sensor
	sequence uint64
	previous string
}

func NewEventChain(build BuildScope, source Sensor) (*EventChain, error) {
	if build.BuildID == "" || build.RunID == "" || build.BootID == "" ||
		build.CgroupID == 0 || build.CgroupPathHash == "" {
		return nil, errors.New("build scope is incomplete")
	}
	if source.Name == "" || source.Version == "" || source.ConfigDigest == "" {
		return nil, errors.New("sensor identity is incomplete")
	}
	return &EventChain{build: build, sensor: source, previous: zeroHash}, nil
}

func (chain *EventChain) Append(event Event) ([]byte, error) {
	if chain == nil {
		return nil, errors.New("event chain is nil")
	}
	if event.SchemaVersion != "" || event.EventID != "" || event.Sequence != 0 ||
		event.Build != (BuildScope{}) || event.Sensor != (Sensor{}) ||
		event.Integrity != (Integrity{}) {
		return nil, errors.New("caller supplied chain-owned event fields")
	}
	chain.sequence++
	event.SchemaVersion = EventSchema
	event.EventID = "urn:rpf:event:" + Digest([]byte(fmt.Sprintf("%s\x00%s\x00%d", chain.build.BuildID, chain.build.RunID, chain.sequence)))
	event.Sequence = chain.sequence
	event.Build = chain.build
	event.Sensor = chain.sensor
	event.Integrity.PreviousEventHash = chain.previous
	digest, err := eventDigest(event)
	if err != nil {
		chain.sequence--
		return nil, err
	}
	event.Integrity.EventHash = digest
	if err := validateEvent(event); err != nil {
		chain.sequence--
		return nil, err
	}
	raw, err := canonical(event)
	if err != nil {
		chain.sequence--
		return nil, err
	}
	chain.previous = digest
	return append(raw, '\n'), nil
}

func ProcessKey(bootID string, pidNamespace uint64, tgid uint32, startTimeNS uint64) string {
	if bootID == "" || pidNamespace == 0 || tgid == 0 || startTimeNS == 0 {
		return ""
	}
	material := fmt.Sprintf("boot=%s\npidns=%d\ntgid=%d\nstart=%d\n", bootID, pidNamespace, tgid, startTimeNS)
	return "sha256:" + Digest([]byte(material))
}
