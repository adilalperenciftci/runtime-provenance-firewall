# Provenance verification

Strict correlation never merges conflicting claims. The artifact digest must match SLSA and
Runtime Trace subjects. Build ID, provider, run ID/attempt, source repository/revision, graph,
evidence, policy, and sensor configuration commitments must agree exactly where required.
Missing required values fail; they are not wildcards.

The verifier parses SLSA Provenance v1 Statements and a project-namespaced build identity inside
`buildDefinition.internalParameters`. Its local profile requires non-empty build type, external
parameters, a matching resolved source dependency, builder ID, invocation ID, and start/finish
timestamps. External source, resolved revision, extension identity, runtime build/run identity,
runtime event source scope, and subject digest must agree. The builder ID in `runDetails` must
equal the namespaced identity,
then builder and repository must appear in policy allowlists. Regression tests reject conflicting
revisions, unauthorized-but-internally-consistent builders/repositories, and provenance replayed
from another build.

Repository and revision in the runtime stream are supplied at sensor registration and hash-chained
with kernel observations. This detects cross-document disagreement; it does not prove checkout
contents or authenticate the registrar. A hosted profile must bind those fields to platform OIDC,
source provenance, or a source VSA.

`create-local-provenance` exists only for the disposable lab and reports assurance
`unsigned-local-fixture`. The offline lab verifies signatures and exact builder/repository policy
authorization, but source VSA, hosted workload identity, and transparency verification are not
implemented and therefore are not claimed.
