# Runtime Provenance Firewall

Runtime Provenance Firewall is a security research project about one question: can evidence of
what a software build did at runtime be cryptographically bound to the artifact and provenance
that claim to describe that build?

SLSA provenance identifies source, builder, declared inputs, and artifact digests. It does not
normally state which child processes executed, whether an install script opened a credential
location, or which network destinations were contacted. Linux runtime tools observe much of
that behavior, but observation alone does not prove that a trace, artifact, provenance
statement, CI run, and policy belong to the same execution.

This project studies that correlation and verification gap. It is not another general syscall
logger and does not claim to replace SLSA, in-toto, Sigstore, Tetragon, Tracee, Falco, or
cicd-sensor.

## Current state

The repository contains a tested correlation-first vertical slice and a narrow Linux CO-RE sensor:

```text
synthetic canonical runtime events
        -> verified event chain and loss state
        -> deterministic execution graph
        -> artifact digest commitment
        -> in-toto Runtime Trace v0.1 correlation extension
        -> SLSA v1 identity/digest equality checks
        -> deterministic policy
        -> ALLOW / REVIEW / REJECT
```

The correlation slice uses repository-owned fixtures. The Linux path collects cgroup-filtered
successful exec, selected `openat`, and IPv4 connect-attempt events; records composite process
identity, canonical hash chains, and explicit loss state; and binds an observed exact-path
artifact write-open to the final artifact hash. The lab assembles that evidence with a SLSA
Provenance v1 Statement and signs both provenance and Runtime Trace bytes with Cosign bundles.
An offline script verifies both signatures before invoking semantic verification. `verify-fixture`
is deliberately named because its semantic verifier does not itself establish signer identity or
transparency inclusion.

Implemented invariants include:

- artifact bytes must match provenance, evidence, and Runtime Trace subjects;
- build and CI run identity must agree across runtime evidence and SLSA provenance;
- source repository and revision must agree between runtime scope and SLSA provenance;
- event order and hash-chain integrity must verify;
- execution graph and evidence manifest are recomputed, not trusted;
- non-zero or unknown event loss cannot produce `ALLOW`;
- missing artifact-finalization/process attribution fails closed;
- policy findings carry stable machine-readable reason codes.

## Reproduce the implementation

Go 1.27 or newer is required for the Go research core. Python 3.12 and `uv` remain temporarily
required for the original decision-engine tests while that code is migrated or retired.

```console
go test ./...
go vet ./...
uv run --extra dev --locked ruff check .
uv run --extra dev --locked pyright
uv run --locked python -m unittest discover -s tests -v
```

The disk round-trip demonstration is:

```console
go test ./internal/rpf -run TestBundleDiskRoundTrip -v
```

The test constructs synthetic build evidence, writes the graph/manifest/Runtime Trace bundle,
reloads it through strict parsers, recomputes every binding, and requires `ALLOW`. Adjacent
tests alter the artifact and manifest, inject event loss, and emulate forbidden sensitive-file
access and localhost egress; those paths must reject.

The privileged sensor smoke test requires Docker on a Linux kernel with cgroup v2, BTF, tracefs,
and BPF loading privilege. Run `./tools/kernel-lab.sh`; it builds the checked-in lab image and
requires scoped exec/file/network records, a valid canonical chain, overwrite refusal, and a
finalized zero-loss record. It then creates explicitly unsigned local SLSA v1 provenance, assembles the
Runtime Trace bundle, requires `ALLOW`, substitutes the artifact, and requires `REJECT`. See
[kernel support](docs/kernel-support.md) for exact limits.

The same command ends with `tools/final-acceptance.sh`, which reruns benign, vulnerable, and
patched paths and writes the machine-readable explanation to
`build/out/final-acceptance-report.json`. See the
[acceptance demonstration](docs/acceptance-demonstration.md).
The complete controlled-case index is in the [laboratory scenario matrix](docs/lab/scenario-matrix.md).

The lab also signs the Runtime Trace and local provenance with Cosign 3.1.2 standardized bundles
using a synthetic ephemeral key and verifies byte tampering. Transparency is deliberately absent
and explicitly bypassed in this local-only test; no keyless identity or Rekor claim is made.

The first controlled behavior specimen reads only a checked-in fake credential, executes a fixed
child, and repeats the read through a renamed local shell. Runtime evidence records category and
ancestry but not content; policy must return `REJECT`. It is explicitly malware-behavior
emulation, not deployable malicious software.

The specimen also contacts only a fixed localhost mock. A cgroup-attached IPv4 connect hook binds
the numeric attempt to the helper process; undeclared `127.0.0.1:18080` egress yields
`RPF-EGRESS-001`. The hook observes attempts and does not claim successful transport or DNS origin.

An intentionally vulnerable localhost authorization fixture demonstrates adapter-role confusion
with a fixed synthetic marker, then reruns identical input against a patched mode. Exploitability
and remediation are demonstrated locally. Runtime evidence attributes the proof but cannot tell
grant from denial; the current rejection is due to undeclared egress, not authorization awareness.

A separate benign mock endpoint at `127.0.0.1:18082` is explicitly policy-declared. The kernel
event and graph edge remain present, but verification returns `ALLOW`, providing a controlled
expected-network non-detection case.

## Implemented research architecture

The selected architecture is a narrow BPF CO-RE sensor, a Go collector/graph builder, in-toto
Runtime Trace plus SLSA provenance, standard Sigstore bundles, and a portable fail-closed
verifier. Current kernel signals cover successful exec, policy-selected sensitive and artifact
write-open activity, and numeric IPv4 connection attempts. Privilege transitions, IPv6, DNS
origin, `openat2`, rename publication, and descendant-cgroup attribution remain outside this slice.

The build cgroup is treated as adversarial. The monitor must start outside it. A root-equivalent
host attacker that can disable kernel telemetry and reach signing authority is explicitly not
solved.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md),
[trust model](docs/trust-model.md), and the
[2026 landscape review](docs/research/landscape-2026.md).

## Research findings

The original broad thesis was narrowed after source-level review. `cicd-sensor` already
provides CI-focused eBPF telemetry, ancestry-aware detection, loss counters, and Runtime Trace
predicate output. The remaining hypothesis is whether a loss-aware verification profile can
prove all required artifact/evidence/provenance/CI identity equalities without silently
reconciling missing data. See the [gap analysis](docs/research/runtime-attestation-gap.md).

## Limits

- Kernel validation currently covers exec, selected successful `openat`, and numeric IPv4 connect
  attempts on Linux 6.8 and 6.18 WSL2 Docker hosts; it is not a portability claim.
- Offline Cosign bundle verification with a synthetic key is implemented; keyless workload
  identity and transparency-log verification are not.
- Runtime Trace v0.1 is experimental and monitor event fields are not standardized.
- Async eBPF cannot prove atomic file-content identity at access time.
- Process/file observations establish documented edges, not semantic causation.
- Core microbenchmarks and a narrow process-launch-dominated sensor comparison are recorded; no
  representative build-overhead, detection-rate, SLSA-level, or production-readiness claim is made.

All adversarial work is restricted to synthetic fixtures, localhost, repository-controlled
containers/VMs, and explicitly authorized systems. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
