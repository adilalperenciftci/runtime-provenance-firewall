# ADR 0017: Bind source identity into runtime scope

Status: accepted

## Context

The runtime stream originally carried build and run IDs while repository and revision appeared
only in provenance. Comparing provenance fields to a Runtime Trace derived from that same
provenance did not establish an independent runtime-side equality. A consistently changed source
claim could therefore evade the intended commit-A/commit-B mismatch check.

## Decision

Every canonical event carries the source repository and revision asserted at sensor registration.
They participate in the event hash chain, immutable build scope, and sensor configuration digest.
Assembly requires exact equality between this runtime scope and the SLSA build identity,
`externalParameters`, and resolved source dependency. Local provenance creation refuses source
arguments that differ from the event stream. Sensor configuration is committed as typed JSON,
avoiding delimiter ambiguity in attacker-controlled registration strings.

## Consequences

A provenance/runtime source mismatch now fails before bundle creation. This is an equality and
tamper-detection property, not proof that the source was checked out: the local registrar supplies
both strings. A hosted profile still needs authenticated workflow/source-control identity or a
source VSA. Because the field is mandatory, canonical events advance from experimental schema
`0.1` to `0.2`; a compatibility regression requires explicit rejection of `0.1`.
