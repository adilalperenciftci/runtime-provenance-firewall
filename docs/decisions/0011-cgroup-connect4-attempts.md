# ADR 0011: Observe scoped IPv4 connection attempts at the cgroup boundary

- Status: accepted
- Date: 2026-09-11

## Context

The policy must distinguish declared from unexpected build egress. DNS names are not reliable
kernel connection identities, syscall tracing has architecture and entry/exit correlation costs,
and a general packet monitor would exceed the build-attribution scope.

## Decision

Attach a `BPF_CGROUP_INET4_CONNECT` program directly to the registered cgroup v2 directory. The
loader verifies that the supplied path inode equals the configured cgroup ID and that its SHA-256
commitment matches the build scope before attachment. For each target-cgroup attempt, emit the
numeric IPv4 address, host-order port, protocol, and composite process identity. Return allow from
the BPF program; enforcement remains a later policy gate.

The controlled fixture uses a purpose-built client that rejects non-loopback addresses before
dialing and a mock server that rejects non-loopback bind addresses. No DNS, scanning, Internet
fallback, payload collection, or autonomous callback behavior exists.

## Consequences

The graph and policy can attribute a localhost TCP connection attempt and reject an undeclared
destination. The hook observes attempts before the transport result, so the event outcome is
`attempted`, not `success`. IPv6, UDP behavior, DNS attribution, descendants created after attach,
and network-namespace interpretation require separate work. The sensor is observe-only and does
not block the socket operation.
