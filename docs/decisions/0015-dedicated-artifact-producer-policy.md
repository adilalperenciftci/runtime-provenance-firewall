# ADR 0015: Authorize artifact producers separately

Status: accepted

## Context

The graph identifies the process associated with artifact write-open and finalization, but policy
previously evaluated that executable only through the general process allowlist. An unexpected
producer could therefore produce at most `REVIEW`, even though producer identity is central to the
artifact binding.

## Decision

Policy v0.1 requires `allowed_artifact_producers`. Every `artifact_finalized` event must have a
process whose executable path appears in that exact allowlist. Otherwise verification emits
`RPF-ARTIFACT-PRODUCER-001` with `REJECT`.

## Consequences

General execution permission and artifact-production authority are distinct. Exact paths are
deterministic and testable but remain vulnerable to representation and replacement ambiguity;
content-derived executable identity is future work. The rule relies on current write-open
attribution and does not claim byte-level causality.
