# ADR 0004: Go core with correlation-first development

- Status: accepted
- Date: 2026-09-11

## Context

The initial Python repository proves strict parsing, deterministic decisions, redaction, and
a hash-chained ledger. The expanded objective requires privileged Linux telemetry, cgroup
attribution, Runtime Trace/SLSA integration, Sigstore verification, and a portable verifier.
Research found that CI eBPF collection and runtime-trace generation are already substantially
implemented by cicd-sensor. The differentiating work is integrity and correlation.

## Decision

The target implementation uses:

- small BPF C programs compiled as CO-RE objects;
- `cilium/ebpf` in a Linux-only Go collector;
- a portable Go graph, attestation, policy, replay, and verification core;
- protobuf after the fixed kernel-record boundary becomes stable;
- in-toto Statement v1 and Runtime Trace v0.1 with one correlation extension;
- maintained Sigstore libraries and Cosign-compatible bundles;
- cgroup v2 plus build nonce, boot ID, namespace, and process start time.

Development is correlation-first. The first vertical slice uses synthetic versioned runtime
events to prove artifact/evidence/provenance equality and loss-aware policy behavior. A real
sensor follows only after those verifier invariants are executable.

## Alternatives

Rust with Aya offers memory safety and no libbpf runtime dependency, but creates more work
around the most mature in-toto/Sigstore ecosystem. A pure adapter over Tetragon or cicd-sensor
delegates loss and lifecycle semantics that the reference proof needs to control. libbpf C for
both sensor and collector increases manual memory and parser risk without helping correlation.

## Consequences

The sensor is Linux-specific and requires BTF plus selected hooks. Verifier and replay tools
remain cross-platform. Go and Clang become build dependencies. Existing Python code remains
only until equivalent vertical-slice invariants exist in Go; it will not become a second
long-term policy implementation.

No claim is made that CO-RE guarantees semantic portability or that telemetry survives a
root-equivalent hostile host.
