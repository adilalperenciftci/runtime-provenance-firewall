# ADR 0008: Bind artifact finalization to a successful write-open observation

- Status: accepted
- Date: 2026-09-11

## Context

Hashing an artifact after a build proves only the final bytes. Assigning its producer from a
declared command would invent causality. The first artifact-binding slice needs a defensible
kernel observation while remaining honest about asynchronous file telemetry and pathname races.

## Decision

For target-cgroup processes, pair write-intent `openat` entry and exit tracepoints by host
PID/TGID. Copy a bounded user pathname at entry and emit `file_open_output` only when the syscall
returns a file descriptor. A bounded non-LRU pending map makes capacity failure observable;
reservation, pending-correlation, decoder/attribution, queue, and persistence loss are separate
final counters.

The collector remembers a bounded set of processes observed by successful exec. On orderly
shutdown it requires an exact pathname match between the configured absolute artifact path and
a successful write-open event, hashes the then-current artifact bytes, and emits
`artifact_finalized` associated with that process identity. Missing attribution fails before a
clean finalization rather than guessing.

## Consequences

The execution graph can answer which observed process opened the artifact for writing and which
final digest was associated with it. It cannot prove which bytes that process wrote, whether a
different file was reached through path resolution, or whether substitution occurred after
hashing. Relative paths, `openat2`, rename-based publication, memory-mapped writes, inherited file
descriptors, and non-`openat` write paths are currently blind spots. Strict verification of the
artifact bytes detects later substitution once this stream is assembled with provenance.
