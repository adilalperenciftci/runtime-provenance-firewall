# ADR 0016: Drop credentials for disposable build commands

Status: accepted

## Context

The first privileged lab ran both collector and build commands as root. A cgroup identifies a
workload but does not prevent same-UID filesystem access, so the synthetic build could potentially
modify root-owned evidence or inherit unrelated host environment values.

## Decision

`rpf-cgroup-enter` is a Linux-only lab helper. While root, it verifies the disposable
`/sys/fs/cgroup/rpf-*` target and moves itself into it. It then sets `no_new_privs`, clears
supplementary groups, drops to UID/GID 65534, supplies only `HOME`, `LANG`, `PATH`, and a lab marker,
and execs an absolute target. Because Linux credentials are thread-scoped, the helper locks its
goroutine to one OS thread before any of these operations. Artifacts are pre-created for that UID;
evidence remains root-owned 0600. Tests require exact UID/GID/group output, and the adversarial
fixture must fail a real evidence append attempt.

## Consequences

The build no longer shares ordinary Unix file authority or inherited environment secrets with the
collector. The helper is not a general sandbox: the container remains privileged, the collector
remains root, and kernel/host root is outside the defended threat boundary. The observed tamper
attempt co-occurred with correlation-loss counts of zero and one across repeated runs. Added
cause-specific counters attributed the non-zero case to path read, not map update or cgroup
mismatch. Strict verification accepts completeness only for zero and emits `RPF-EVIDENCE-001`
otherwise.
