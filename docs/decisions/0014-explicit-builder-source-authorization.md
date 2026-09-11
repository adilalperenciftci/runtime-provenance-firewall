# ADR 0014: Require explicit builder and source authorization

Status: accepted

## Context

Structural SLSA correlation previously required a non-empty `runDetails.builder.id` but did not
bind it to the project identity extension or authorize it through policy. Repository identity was
cross-checked internally but likewise not authorized. A consistently forged provenance signed by
an otherwise accepted key could therefore pass the local policy profile.

## Decision

The namespaced correlation identity carries `builderId`. It must equal SLSA `runDetails.builder.id`.
Policy v0.1 now requires non-empty exact `allowed_builder_ids` and `allowed_repositories` arrays.
Unauthorized values produce `RPF-BUILDER-001` or `RPF-SOURCE-001` and strict `REJECT`.

## Consequences

Consistency and authorization are separate checks. Existing policies must add explicit allowlists.
Exact strings avoid ambiguous prefix matching but do not validate an OIDC certificate, source VSA,
or organizational ownership; those require a future production trust profile.
