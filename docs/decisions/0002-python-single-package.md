# ADR 0002: Use a single Python package for the initial core

Status: accepted

## Context

The initial workload is bounded JSON validation, canonicalization, rule evaluation, and replay. It is not a transparent high-throughput gateway. Rust is not installed in the current environment and a mixed-language design would expand auditing and release complexity without proving a security benefit.

## Decision

Use Python 3.12+ with a small package and pinned development dependencies. Prefer the standard library in the trusted runtime path. Reconsider Rust only if measured adapter throughput, memory isolation, or deployment constraints justify it.

## Consequences

Development and adversarial testing are fast and portable. Explicit input limits are mandatory because Python does not supply resource isolation. Performance claims require a reproducible benchmark before publication.
