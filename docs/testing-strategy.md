# Testing strategy

Every evaluator requires a benign baseline, suspicious fixture, non-detection case, malformed-input cases, and expected findings. Fixtures are deterministic and use `.test` domains and synthetic credentials.

The initial suite verifies allow/deny behavior, exact-host matching, redaction, duplicate-key rejection, depth limits, undeclared nested-field rejection, ledger verification, and refusal to extend a modified ledger.

Unit and vertical-slice tests run without network access or third-party services. Rule metadata validation ensures fixture references exist and implemented IDs match documented IDs. CLI integration tests verify exit status and durable output. Property-based parsing tests are deferred until a dependency is justified; parser regression fixtures should be added for every discovered ambiguity.

No false-positive or false-negative rate is reported from these curated fixtures. Counts from deterministic fixtures describe coverage, not field performance.

## Privileged sensor tests

`tools/test-sensor.sh` runs only in a disposable privileged Linux environment. The sensor stays
outside a temporary fixture cgroup. Fixed static build-fixture and local-connect processes move into that
cgroup before exec and must be present, while a `/usr/bin/whoami` control executed outside the
target cgroup must be absent. The test also requires a `sensor_finalized` event and every
implemented loss counter to be zero, so a lossy run cannot pass as clean. This proves exact-ID
filtering in the tested namespace layout,
not exclusion under every cgroup namespace/delegation arrangement or inclusion of nested cgroups.

The smoke test passes the resulting stream through `rpf validate-events`, then attempts to reuse
the same evidence path. The second collector must fail and the file digest must remain unchanged.
It also executes a target-cgroup shell that opens an absolute synthetic artifact for writing,
requires the final digest to match the file, reconstructs both output-open and artifact edges,
and requires every implemented loss counter to be zero.
The same test creates full-structure unsigned local SLSA provenance, assembles Runtime Trace and
manifest commitments, requires an `ALLOW`, modifies the artifact bytes, and requires verifier
exit status 3 with `RPF-ARTIFACT-001`. This demonstrates correlation and tamper rejection, not
provenance authenticity or signature verification.

`tools/test-signing.sh` generates a synthetic ephemeral Cosign key, signs exact provenance and
Runtime Trace bytes into standardized bundles, verifies both against the public key, and requires
a one-byte statement modification to fail. The private key is removed on exit. The local config
has no Rekor/TSA services, so this test deliberately does not satisfy production transparency or
trusted-time requirements.

`tools/test-adversarial.sh` runs MBE-001 with a repository-owned fake credential. It requires two
category findings (ordinary and renamed shell), observed shell-to-child ancestry, no fixture value
in evidence, one fixed numeric localhost callback attributed to its helper, all loss counters
zero, and final `REJECT` containing both sensitive-access and egress reasons. The client and mock
server have unit tests rejecting non-loopback configuration. This is behavior emulation, not
malware execution or a field detection-rate benchmark.

The benign privileged baseline separately contacts `127.0.0.1:18082`, which is declared in the
versioned policy. Its exec and connect edges must be present while the final decision remains
`ALLOW` with no reasons. This is a controlled non-detection case proving that the network hook
does not make every observed connection suspicious.

`tools/test-evidence-integrity.sh` derives three negative fixtures from that real sensor stream.
Tail truncation retains a valid hash-chain prefix, but the absent `sensor_finalized` lifecycle event
must yield `completeness=unknown`, `RPF-EVIDENCE-001`, and `REJECT`. Removing an interior event or
changing a retained byte must fail event parsing because sequence/hash commitments no longer
verify. These tests demonstrate fail-closed handling; they do not make an unsigned stream
authentic or detect rollback to a separately checkpointed older complete stream.

`tools/test-attestation-negative.sh` exercises the actual CLI with malformed provenance and a
provenance subject carrying the wrong artifact digest, plus provenance whose repository differs
from runtime scope; assembly must fail before writing a bundle.
The offline Cosign test additionally requires rejection of changed attestation bytes, malformed
substitute bytes, and a valid bundle checked under an unrelated laboratory public key. Private
keys and the unrelated public key are removed after the run; all credentials are synthetic.

`tools/test-runtime-replay.sh` captures a second benign build under a distinct build/run identity
and cgroup, then supplies its complete runtime bundle to the first build's verifier inputs. Strict
verification must return `REJECT` with identity and recomputed-manifest/runtime-trace mismatch
reasons. Supplying the second build's provenance alongside the first event stream must fail
assembly without writing a bundle. This uses two observed kernel runs rather than relabelled JSON.

The same script runs EXP-001 as two separate monitored builds with byte-identical authorization
claims: explicitly vulnerable mode must grant the synthetic marker and patched mode must deny it.
Each run has its own cgroup, build/run identity, stream, graph, artifact, provenance, runtime trace,
and policy decision. Both proof chains must appear in their own telemetry. This is a complete local
exploit/patch path, while both builds still `REJECT` because sensitive access and undeclared egress
remain intentionally unchanged; current kernel signals do not detect authorization semantics.

Both adversarial builds run as UID/GID 65534 with `no_new_privs` and a four-variable synthetic
environment. An attempted append to the root-owned 0600 evidence file must fail. On the tested
kernel repeated runs observed either zero or one correlation-loss event. Cause-specific counters
later identified the non-zero case as a path-read failure, while map-update and cgroup-mismatch
remained zero. The test therefore requires `complete` when the aggregate and all causes are zero, or
`incomplete` plus `RPF-EVIDENCE-001` when it is non-zero; sensitive/egress findings and `REJECT`
remain mandatory in both cases. The benign UID-dropped baseline separately requires all counters
to remain zero and `ALLOW`.

`tools/test-cgroup-enter.sh` repeats the complete cgroup-entry, supplementary-group clearing,
UID/GID drop, and exec transition 100 times and requires exact `id` output. This permanently
regresses the Linux per-thread credential race found during the full-suite review. Credential
diagnostics are kept outside the zero-loss benign sensor baseline because dynamically linked
identity lookup can introduce unrelated `openat` path-capture uncertainty; the baseline instead
requires UID/GID 65534 on its actual build events.

The benign path also runs the network-free package fixture against the repository-owned synthetic
lockfile; it receives no credential or package-manager network access. The artifact producer is a
static repository-lab helper restricted to the fixed generated artifact name under `/src/build/out`.
Once read-only opens were filtered before pathname access
when no sensitive profile is active, 20 consecutive baseline runs completed with zero implemented
loss and `ALLOW`. This is a bounded reproducibility check on the recorded WSL2 kernel, not a rate
or portability claim.

`tools/kernel-lab.sh` builds the checked-in pinned-base lab image and runs BPF compilation, Go
race tests, vet, both binaries, and the privileged smoke test. Debian packages installed into
that image are not yet snapshot-pinned, so the image build is repeatable but not byte-reproducible.

The wire decoder has unprivileged exact-size and bounded-string unit tests. Linux CI must build
and vet all Go packages; privileged kernel coverage is a separate gate because ordinary hosted
CI does not provide equivalent eBPF semantics.

`tools/build-release-candidate.sh` generates source SBOMs, builds Linux amd64 `rpf` and
`rpf-sensor` with fixed Go flags, normalizes archive ordering, ownership, and modification time,
and emits `SHA256SUMS`. For an offline repeat, first generate and validate `build/sbom`, then set
`RPF_USE_EXISTING_SBOM=1`; this bypasses generation, not the required non-empty SBOM checks. Two
consecutive local container runs produced the same archive digest. This is evidence for that
environment and commit, not a cross-builder reproducibility claim. `actionlint` validates the
SHA-pinned release-candidate workflow; only an inspected hosted run can establish its attestation.

Native Go fuzz targets cover canonical event streams, policy documents, and in-toto/SLSA
Statement parsing. Ordinary `go test` executes their checked-in seeds; a read-only weekly/manual
workflow runs each target for 30 seconds. This is bounded parser robustness coverage, not evidence
that all parser defects are absent. Privileged BPF behavior is not fuzzed by these userspace tests.

The SBOM generator runs the digest-pinned Syft container against a read-only source mount and then
validates SPDX 2.3 and CycloneDX 1.7 format markers. Unit tests reject version-confused documents.
This validates format/profile expectations, not completeness of every language cataloger.
