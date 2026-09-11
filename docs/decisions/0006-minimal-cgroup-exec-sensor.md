# ADR 0006: Start kernel collection with cgroup-filtered successful exec events

- Status: accepted
- Date: 2026-09-11

## Context

The correlation model needs real kernel evidence, but collecting every syscall would create
noise and obscure the central verification thesis. The first kernel slice must validate CO-RE
loading, workload scoping, bounded delivery, ancestry fields, and observable loss without
prematurely claiming complete build attribution.

## Decision

Attach one BPF C CO-RE program to `sched_process_exec`. Filter in kernel on one cgroup v2 ID,
emit a fixed-size bounded record through `BPF_MAP_TYPE_RINGBUF`, and count reservation failures
in a per-CPU array. A Go loader based on `cilium/ebpf` rewrites the target cgroup constant,
decodes only exact-size records, and emits an explicit final loss count.

Keep this diagnostic JSON output separate from the canonical hash-chained evidence schema until
the registrar can bind build nonce, boot/cgroup identity, lifecycle boundaries, and composite
process identity. Do not infer executable content identity or artifact causality from filename
and ancestry alone.

## Consequences

The slice yields useful, low-volume process evidence and tests event-loss plumbing with modest
kernel complexity. It requires Linux BTF, cgroup v2, tracefs, ring-buffer support, and BPF load
privilege. Successful exec is visible; failed exec attempts and all file/network behavior are
not. Cgroup reuse and hostile root remain unresolved. Later hooks must each justify their
semantic value and must preserve the fail-closed completeness invariant.
