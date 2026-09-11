# ADR 0013: Explicitly label unobserved process parents

Status: accepted

## Context

Exec telemetry includes a composite parent key, but the parent may not have an exec event in the
captured interval. The original graph emitted an ancestry edge whose source node could be absent,
without distinguishing this from a completely reconstructed parent. That ambiguity could support
an unjustified causal or ancestry claim.

## Decision

Execution graph schema v0.2 adds `parent_observation` to every process node. `observed` means the
parent key resolves to another event-derived node; `unobserved` means a parent key exists but does
not resolve; `none` means no parent key was reported. Existing ancestry edges remain observational.

## Consequences

Consumers can fail closed or request review when ancestry required by policy is unobserved. The
field does not explain why a parent is absent and does not upgrade ancestry into causal influence.
The graph digest changes from schema v0.1 and compatibility tests must treat that as a deliberate
schema revision.
