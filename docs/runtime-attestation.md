# Runtime attestation

The project composes in-toto Runtime Trace v0.1 rather than defining a competing statement
format. Artifact digests remain in the standard Statement subject. Standard predicate fields
identify monitor and monitored run. The namespaced `runtime-provenance/v0.1` extension commits
to the evidence manifest, execution graph, SLSA provenance, policy, source, build/run identity,
and completeness.

Both synthetic fixtures and the privileged Linux lab initially emit an unsigned Statement. The
Linux lab composes it from real canonical kernel evidence, a final artifact hash, and an explicitly
`unsigned-local-fixture` SLSA statement, then verifies all commitments. Detailed event bytes remain
external and must be supplied by digest for forensic replay.

The M10 local lab signs exact Runtime Trace and provenance bytes with Cosign 3.1.2 standardized
bundles and a generated synthetic ECDSA key, verifies both, and requires modified statement bytes
to fail signature verification. Its signing configuration intentionally has no Rekor or TSA;
verification uses the conspicuous `--insecure-ignore-tlog` option. This is a local cryptographic
integrity fixture, not identity-bound keyless signing, trusted time, or transparency evidence.
`tools/verify-offline-signed-fixture.sh` is the single local fail-closed entry point: it verifies
both exact signed blobs before invoking artifact/evidence/provenance/policy correlation. If either
signature fails, semantic verification is never reached. Its name and warnings intentionally keep
this offline profile distinct from the future production requirement for authorized Fulcio issuer,
certificate identity, and transparency verification.
