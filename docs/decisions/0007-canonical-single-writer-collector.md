# ADR 0007: Persist canonical sensor evidence through one fail-closed writer

- Status: accepted
- Date: 2026-09-11

## Context

Raw diagnostic JSON cannot be correlated safely with the fixture verifier. Shell redirection
also permits accidental overwrite and provides no application-visible durability boundary.
Canonical events need trustworthy ordering, composite process identity, explicit lifecycle and
loss state, and exact bytes suitable for deterministic replay.

## Decision

The Go sensor process owns one `EventChain`. After the BPF program attaches, it emits
`sensor_started`, translates exact-size kernel records to `process_exec`, and emits
`sensor_finalized` with all current loss counters. It derives process keys from boot ID, active
PID namespace, TGID, and kernel start time. Parent keys are emitted only when all corresponding
kernel fields are present.

The collector creates the requested evidence path with `O_EXCL|O_APPEND`, mode `0600`, writes
one canonical event at a time, and syncs every event. It never appends to or overwrites an
existing stream. Sequence, event ID, build/sensor scope, and hash links are chain-owned fields.
The strict parser validates the resulting bytes in the privileged smoke test.

## Consequences

Order and local crash durability are explicit, and accidental evidence replacement fails.
Per-event sync has measurable overhead that must be benchmarked rather than guessed. The
collector and privileged loader are still one process, user-provided registration metadata is
not yet authenticated, abrupt termination has no final record, and filesystem/root attackers
can still remove or replace unsigned evidence. Those cases cannot produce complete evidence.
