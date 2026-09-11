# ADR 0005: Completeness and composite process identity are verification inputs

- Status: accepted
- Date: 2026-09-11

## Context

Ring-buffer reservation can fail, userspace queues can drop, and PID/cgroup identifiers can be
reused. Treating absent counters as zero or identifying a process by PID permits clean verdicts
from ambiguous evidence.

## Decision

Every finalized evidence manifest carries mandatory loss counters and lifecycle states.
`ALLOW` requires all counters to be measured and zero, a valid event chain, and start/finalize
records. Policy cannot override completeness.

A process node is keyed by host boot ID, PID namespace inode, TGID, and process start time.
Cgroup attribution additionally binds cgroup ID to a build nonce, cgroup-path digest, and
monitoring interval. Missing identity components create an incomplete edge, not a guess.

## Consequences

Some benign builds produce `REVIEW` or `REJECT` when completeness cannot be established. This
is intentional. More counters enter the stable evidence contract. The model reduces ambiguity
but does not defend against hostile root forging all host-origin observations.
