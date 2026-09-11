# ADR 0009: Use a complete unsigned local SLSA profile before adding signatures

- Status: accepted
- Date: 2026-09-11

## Context

The privileged vertical slice needs provenance correlation before CI identity and Sigstore trust
roots are available. Calling an ad hoc or incomplete predicate “verified provenance” would
overstate assurance, while postponing structure checks would hide identity-confusion defects.

## Decision

`create-local-provenance` emits an in-toto Statement with SLSA Provenance v1 predicate type,
subject digest, build type, external/internal parameters, resolved source dependency, builder ID,
and invocation timestamps. The project identity extension repeats build, run, provider, source,
and revision for strict equality checks. The command and output explicitly identify assurance as
`unsigned-local-fixture`.

The verifier requires the external source, resolved dependency, extension source, invocation ID,
runtime build/run identity, and artifact subject to agree. It does not treat this local statement
as authenticated provenance. Production acceptance remains blocked until signature, certificate
identity/issuer, trust root, and transparency verification are implemented.

## Consequences

The local lab can exercise Runtime Trace composition and mismatch failures using realistic SLSA
v1 structure without making a SLSA level claim. A caller able to edit all unsigned files can forge
the entire bundle; hash correlation alone does not provide origin authenticity.
