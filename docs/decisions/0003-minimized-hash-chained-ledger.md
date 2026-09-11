# ADR 0003: Persist minimized events in a hash-chained JSONL ledger

Status: accepted

## Context

Replay requires stable evidence, but raw tool arguments can contain secrets. Ordinary JSONL is easy to inspect yet cannot reveal record modification or reordering.

## Decision

Canonicalize each redacted record and hash it with the previous record hash. Store both hashes in each JSONL entry. Reject duplicate JSON keys and non-finite numbers. Verification starts from a known genesis value or an external checkpoint.

## Consequences

Modification, insertion, and reordering inside a segment are detectable. Whole-file deletion, truncation at the tail, or rollback to an older valid segment is not detectable without an external checkpoint. Hash chaining provides tamper evidence, not authenticity or non-repudiation.
