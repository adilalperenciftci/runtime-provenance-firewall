# ADR 0010: Categorize one exact sensitive path without retaining its value

- Status: accepted
- Date: 2026-09-11

## Context

Collecting every read-open in a build would be noisy and expensive. A defensive credential-access
experiment needs a narrow kernel signal that cannot leak secret values into evidence.

## Decision

Rewrite one bounded absolute sensitive path into BPF read-only configuration. The `openat`
entry/exit correlator tracks it only on exact user-path equality and emits a successful-open event.
Userspace replaces the raw path with a configured category, binds a hash of the path and category
into sensor configuration identity, and never reads or records file content.
Sensitive-path equality takes precedence over generic write-open classification, so `O_RDWR` does
not erase the security category. The lab permanently exercises both `O_RDONLY` and `O_RDWR`.
When no sensitive path is configured, read-only opens are rejected by flags before dereferencing
the userspace pathname. They cannot produce a selected event and therefore cannot create false
correlation loss in the benign profile.

## Consequences

The signal is low-volume and the synthetic credential value cannot enter telemetry through this
path. Exact user-path matching misses aliases, symlinks, relative paths, alternate file APIs, and
descriptor inheritance. These are documented blind spots, not negative findings. Path capture or
correlation failure increments completeness counters.
