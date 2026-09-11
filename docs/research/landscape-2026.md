# Runtime build evidence landscape, 2026

## Scope and method

This review asks which current standards and open-source systems can bind observed build-time
behavior to an artifact and make that relationship independently verifiable. It distinguishes
inventory, declared provenance, runtime observation, signing, and policy evaluation because no
one of those functions supplies the others.

Primary specifications, project documentation, and source code were preferred. The review was
refreshed against material available on 2026-09-11. Capability statements are limited to
documented behavior or inspected implementation. Absence from this review does not prove
global novelty.

## Standards and integrity infrastructure

### SLSA v1.2

SLSA v1.2 is the current approved specification. It separates Build and Source tracks. The
Build track increases confidence in provenance existence, authenticity, accuracy, and build
isolation. Provenance describes the builder, build process, external parameters, resolved
dependencies, and digest-identified outputs. The Source track addresses how source revisions
are created and controlled; full source provenance remains source-control-system specific.

SLSA is deliberately not a kernel-observation format. A conforming provenance statement can
identify the expected builder and inputs without enumerating every process, sensitive file
access, or network connection that occurred. Build L3 hardening reduces opportunities for a
build to influence its provenance, but does not turn declared provenance into a runtime trace.
Runtime evidence therefore complements rather than replaces SLSA.

Sources: [SLSA v1.2](https://slsa.dev/spec/v1.2/),
[tracks](https://slsa.dev/spec/v1.2/tracks),
[build requirements](https://slsa.dev/spec/v1.2/build-requirements), and
[source requirements](https://slsa.dev/spec/v1.2/source-requirements).

### in-toto Attestation Framework and Runtime Trace

The in-toto Attestation Framework supplies a Statement with digest-addressed subjects and a
typed predicate. Authentication is normally provided by a DSSE envelope or Sigstore bundle.
Consumers must authenticate the envelope before trusting the statement and use
`predicateType`, not a media type, to select predicate semantics.

Runtime Trace v0.1 defines a monitor, monitored process, process/network/file-access logs, and
optional timing metadata. It intentionally leaves process and network object formats
monitor-specific. It also warns that asynchronous eBPF observation cannot atomically hash a
file before use, so a recorded file digest has weaker TOCTOU properties than one obtained by a
synchronous monitor.

Runtime Trace is the appropriate interoperability envelope, but v0.1 does not define:

- a canonical execution graph or process identity rule;
- event ordering, loss accounting, or a completeness state;
- a digest commitment to an external detailed event stream;
- mandatory equality links among build ID, CI run, SLSA invocation, and trace;
- replay resistance beyond producer-selected identity fields;
- deterministic policy verdict semantics.

These are extension points, not defects. The smallest compatible design is a Runtime Trace
v0.1 predicate with a namespaced correlation extension, not a new top-level attestation family.

Sources: [in-toto Attestation Framework](https://github.com/in-toto/attestation),
[Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md),
[Envelope specification](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md),
and [Runtime Trace v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md).

### Sigstore, Cosign, and transparency

Sigstore supplies identity-bound short-lived signing certificates, transparency services,
trusted-root distribution, and client libraries. Cosign signs and verifies artifacts and
in-toto attestations, including keyless OIDC workflows. A Sigstore bundle packages the
signature and verification material needed for offline verification. Verification must
constrain certificate identity and issuer; cryptographic validity alone is not authorization.

Rekor v1 is in maintenance mode. Rekor v2 uses tile-based logs and shard discovery through
TUF-distributed signing configuration and trusted roots. This project should consume standard
Sigstore bundles through maintained libraries, not hard-code a public log URL or implement
transparency cryptography. A local lab may use an ephemeral key and offline verification;
public keyless signing belongs in CI release jobs.

Sources: [Cosign](https://github.com/sigstore/cosign),
[Sigstore bundle format](https://docs.sigstore.dev/about/bundle/),
[Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/),
[Rekor](https://github.com/sigstore/rekor), and
[Rekor v2](https://github.com/sigstore/rekor-tiles).

As of the 2026-07-17 Cosign 3.1.2 release, standardized Sigstore bundles are the default and the
v3 signing path supports Rekor v2 through signing configuration. The local lab pins 3.1.2 and
uses an empty generated signing configuration with a synthetic self-managed key. Verification
therefore explicitly skips transparency and proves signature integrity only; production policy
must not inherit that exception. Cosign v3.0.4 or newer also contains the fix for
GHSA-whqx-f9j3-ch6m affecting certain older bundle verification paths.

### SPDX and CycloneDX

SPDX 3.0.1 includes a Build profile modeling build instances, inputs, outputs, tools, agents,
and parent/child build relationships. CycloneDX 1.7 supports inventory, formulation workflows,
declarations, claims, evidence, and attestation references. Both are useful for describing
components and build formulation.

Neither standard by itself authenticates kernel observations or defines the event-loss and
cross-attestation equality rules required here. Runtime evidence should reference SBOMs as
materials or companion attestations rather than duplicate their inventory models.

Sources: [SPDX 3.0.1 Build profile](https://spdx.github.io/spdx-spec/v3.0.1/model/Build/Build/)
and [CycloneDX 1.7](https://cyclonedx.org/docs/1.7/json/).

## Linux observation substrate

### eBPF, BTF, CO-RE, and cgroups

eBPF provides verified programs attached to kernel hooks. BTF describes kernel and BPF types;
CO-RE uses compiler relocation metadata plus running-kernel BTF to adapt one BPF object across
compatible kernels. CO-RE improves portability but does not guarantee that a required hook,
helper, LSM configuration, or semantic behavior exists.

`BPF_MAP_TYPE_RINGBUF`, introduced in Linux 5.8, preserves reservation order across CPUs and
supports variable-sized records. Reservation is non-blocking and fails when full. Every failed
reservation relevant to a monitored build must therefore increment a counter included in final
evidence. Buffer size and polling reduce loss but cannot justify treating unmeasured loss as
zero.

The current-cgroup helper is available from Linux 4.18. Cgroup v2 is the practical workload
boundary, but cgroup ID alone is not a durable global identity: IDs can be reused and processes
can move if the host permits it. The collector must bind cgroup ID to a build nonce, observed
cgroup path/inode, monitoring interval, and host boot identity. Namespace IDs and process
start time reduce PID ambiguity.

BPF LSM can observe or enforce security hooks, but requires `CONFIG_BPF_LSM` and a kernel LSM
configuration containing `bpf`. Stable tracepoints and LSM hooks are preferred over unstable
kprobes. Initial collection should be selective:

- successful process execution and exit for ancestry;
- sensitive-path file opens selected by policy;
- artifact write/rename events inside declared output roots;
- IPv4/IPv6 socket connect attempts and outcomes;
- credential or privilege transitions where stable hooks exist;
- explicit sensor loss and lifecycle records.

It should not stream every syscall. DNS names cannot be reliably inferred from `connect(2)`;
kernel telemetry normally establishes only IP and port. Name evidence requires a separately
identified resolver observation and must not be presented as kernel-established causality.

Sources: Linux kernel documentation for [BTF](https://docs.kernel.org/bpf/btf.html),
[libbpf CO-RE](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html),
[BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html), and
[ring buffers](https://docs.kernel.org/bpf/ringbuf.html).

## Runtime-security implementations

### Tetragon

Tetragon provides eBPF-based process, file, network, capability, namespace, and Kubernetes
observability with in-kernel filtering and optional enforcement. TracingPolicy is expressive,
and executable integrity measurements are available on supported kernels. It solves much of
selective, identity-aware kernel telemetry, but does not define an artifact/runtime/SLSA
correlation contract or strict build verifier. It can be a future event-source adapter.

Sources: [Tetragon overview](https://tetragon.io/docs/overview/) and
[TracingPolicy reference](https://tetragon.io/docs/reference/tracing-policy/).

### Tracee

Tracee exposes broad Linux runtime events and detections using eBPF, with container context,
filtering, signatures, and forensic output. Its event surface is broader than this project
needs. A former Tracee GitHub Action demonstrated CI monitoring but is documented as an
unmaintained demonstration. Tracee does not supply an artifact-to-runtime-to-SLSA verification
contract. Source: [Tracee](https://github.com/aquasecurity/tracee).

### Falco

Falco evaluates kernel and plugin event streams against rules. Its modern eBPF driver, drop
accounting, mature rule language, and ecosystem solve runtime detection well. Falco documents
that it does not correlate events from different event sources. It does not construct
artifact-bound build graphs or compose SLSA and Runtime Trace attestations.

Sources: [Falco event sources](https://falco.org/docs/concepts/event-sources/),
[kernel architecture](https://falco.org/docs/concepts/event-sources/kernel/architecture/), and
[dropped events](https://falco.org/docs/concepts/event-sources/kernel/dropped-events/).

### cicd-sensor

`cicd-sensor` is the closest implementation and materially narrows any novelty claim. It is
an eBPF CI/CD sensor for GitHub Actions and GitLab CI. It records process ancestry, file and
network observations, runs correlation rules, produces reports, counts ring-buffer drops, and
generates a predicate based on Runtime Trace v0.1. Its documentation recommends signing the
predicate later with GitHub Artifact Attestations.

Source inspection on 2026-09-11 found that its v1alpha1 predicate intentionally aggregates
detections and network/domain observations. It omits per-event process trees and dedicated
file access. Ring-buffer loss is an agent-wide audit signal and is not represented in the
predicate as a verifier-enforced completeness state. The predicate is generated separately
from the outer artifact subject and does not itself require equality with a SLSA invocation.

This project must not claim novelty for CI eBPF collection, ancestry-aware detection, Runtime
Trace predicate generation, or runtime reports. The research gap is a portable deterministic
verifier that treats evidence completeness as a security property and proves a closed set of
digest and identity equalities across artifact, detailed evidence, Runtime Trace, SLSA
provenance, policy, and signer identity.

Sources: [cicd-sensor](https://github.com/cicd-sensor/cicd-sensor) and its
[attestation documentation](https://github.com/cicd-sensor/cicd-sensor/blob/main/docs/user-guide/attestation-predicate.md).

## CI platforms and repository controls

GitHub artifact attestations use Sigstore and bind artifact digests to workflow, repository,
commit, and OIDC identity. GitHub warns that attestations do not prove an artifact is secure.
It recommends least-privilege tokens, full-SHA action pinning, OIDC, and isolation of
untrusted pull-request code. GitHub-hosted runners do not scan downloaded dependencies for
malicious behavior.

GitLab documents that shell executors and privileged containers can expose runner hosts and
cross-job secrets. It recommends isolated ephemeral runners for privileged jobs, network
segmentation, non-root containers, capability reduction, and OIDC ID tokens.

The defensible sensor deployment is a host/VM-owned monitor outside the untrusted build
cgroup, with each build in a fresh cgroup or disposable VM. A sensor started by the build
itself cannot establish strong provenance against that build.

Sources: GitHub [secure use](https://docs.github.com/en/actions/reference/security/secure-use),
[artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations),
and [compromised runners](https://docs.github.com/en/actions/concepts/security/compromised-runners);
GitLab [runner security](https://docs.gitlab.com/runner/security/) and
[OIDC](https://docs.gitlab.com/ci/secrets/id_token_authentication/).

OpenSSF Scorecard checks pinned dependencies, token permissions, dangerous workflows, branch
protection, dependency updates, fuzzing, SAST, and signed releases. CISA guidance calls for
hardened build environments, minimized approved internet access, build-chain monitoring,
audit logs, SBOM use, and artifact integrity. These controls protect this repository but do
not replace per-build runtime evidence.

Sources: [OpenSSF Scorecard](https://github.com/ossf/scorecard) and CISA/NSA/ESF
[developer guidance](https://www.cisa.gov/sites/default/files/2023-12/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.pdf).

## Conclusion

The broad thesis is already partially implemented. Runtime collection, ancestry-aware CI
detection, Runtime Trace production, and signing infrastructure exist. The defensible
narrowed hypothesis is:

> A loss-aware correlation and verification profile can cryptographically bind a build
> artifact to one detailed runtime evidence stream, SLSA provenance, CI execution identity,
> policy version, and signer authorization, while refusing a clean verdict when any required
> equality or completeness condition is unproven.

This is a hypothesis to test, not a novelty claim. The first vertical slice validates the
correlation contract with synthetic evidence before privileged sensor engineering expands.
