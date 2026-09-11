# Release integrity

No release artifacts are published yet. The tag/manual `release-candidate.yml` workflow builds a
Linux amd64 archive on a hosted ephemeral runner, includes source-tree CycloneDX and SPDX SBOMs,
and creates GitHub/Sigstore-backed SLSA build provenance for the archive. It uploads short-lived
workflow artifacts; it does not create a GitHub Release. Consumers must verify repository identity,
workflow identity, source revision, and artifact digest rather than checking only that an
attestation exists.

The release-candidate job grants only `contents: read`, `id-token: write`, `attestations: write`,
and `artifact-metadata: write`; pull-request workflows receive none of these write permissions.
Every third-party action is pinned to a full commit. The workflow uses `actions/attest` rather than
the legacy provenance wrapper. Until an authoritative hosted run is inspected, this repository
does not claim that a release was signed or that any SLSA build level was achieved.

CI now runs Go race tests/vet and Python tests/static analysis with read-only default permissions.
Separate SHA-pinned CodeQL and OpenSSF Scorecard workflows grant `security-events: write` only to
their analysis jobs; only Scorecard receives `id-token: write` for authenticated result
publication. These workflows improve repository checks but do not themselves constitute a release
process, signed release, or SLSA provenance.

`tools/generate-sbom.sh` scans a read-only source mount with Syft v1.51.1 pinned by OCI manifest
digest, excludes generated/VCS/virtual-environment trees, and emits SPDX 2.3 JSON plus CycloneDX
1.7 JSON under `build/sbom`. A stdlib validator checks required top-level format fields, and a
read-only CI job uploads both as short-lived workflow artifacts. These are source-tree SBOMs, not
release-binary SBOMs; they are not signed and do not imply a published release.
The source component version is the full Git commit on a clean tree and gains a `-dirty` suffix
when local tracked or untracked changes are present, avoiding a false clean-revision claim.

Recommended branch controls are required reviews for runtime, policy, and workflow changes; successful CI; no force pushes on the release branch; private vulnerability reporting; and reviewed dependency updates. Host configuration cannot be enforced from this repository and must be verified separately.
