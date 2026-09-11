# Architecture

## Thesis

The system correlates runtime evidence with existing provenance standards. The core result is
not a claim that events were collected; it is a verifier result over explicit digest and
identity equalities.

```text
source revision
      |
CI identity + build nonce
      |
isolated build cgroup <--- host-owned CO-RE sensor
      |                           |
artifact bytes              bounded events + loss counters
      |                           |
artifact SHA-256        canonical stream -> execution graph
      |                           |
SLSA provenance <------ evidence manifest ------> Runtime Trace v0.1
              \             |                    /
               \------ signed Sigstore bundle --/
                              |
                strict correlation + policy verifier
                              |
                    ALLOW / REVIEW / REJECT
```

The implemented local path includes cgroup-filtered exec, selected write-open, sensitive-open,
and IPv4 connect-attempt collection; a canonical single-writer collector; exact-path artifact
finalization; SLSA Provenance v1 correlation; and offline Cosign bundle verification. Hosted CI
identity, keyless signing, and transparency verification remain target components.

## Components

### Kernel sensor (narrow vertical slice implemented)

The BPF C CO-RE program attaches to `sched_process_exec`, `sys_enter_openat`,
`sys_exit_openat`, and `cgroup/connect4`. It scopes tracepoint observations by one
loader-supplied cgroup ID and attaches connect observation directly to that cgroup. Bounded exec,
selected file, and numeric IPv4 destination records use a BPF ring buffer. Reservation and
open-entry/exit correlation failures increment explicit counters that userspace emits during
finalization. This slice does not claim resolved-path, DNS, IPv6, privilege-transition, or
descendant-cgroup attribution.

### Go sensor loader and collector (M2/M3 implemented)

`cmd/rpf-sensor` loads the CO-RE object using `cilium/ebpf`, rewrites the target cgroup constant,
attaches the tracepoint, and defensively decodes fixed-size records. It constructs composite
process/parent keys, writes canonical hash-chained lifecycle and exec events through one
exclusive append writer, syncs each record, correlates successful write-intent `openat` events,
and finalizes an exact-path artifact digest plus loss counts. Authenticating build registration,
resolved-path coverage, and privilege separation remain.

### Evidence and graph core (implemented for fixtures)

`internal/rpf` strictly parses canonical JSONL, rejects duplicate/unknown fields, verifies
event order and hash chaining, constructs typed observation edges, and commits graph and
stream digests to an evidence manifest. Process identity combines boot ID, PID namespace,
TGID, and start time; PID alone is never a node key.

### Attestation composer (implemented for fixtures)

The composer emits an in-toto Statement v1 with Runtime Trace v0.1. Standard fields identify
the monitor and run; one namespaced extension commits to build/run/source identity, evidence
manifest, graph, SLSA provenance, policy, and completeness. Detailed events remain external
content-addressed evidence.

### Signature verification (offline fixture implemented; workload identity planned)

The disposable lab uses Cosign 3.1.2 to sign Runtime Trace and provenance bytes with an ephemeral
synthetic key and verifies both bundles under the corresponding public key before semantic
verification. Tampered bytes, malformed statements, and an unrelated key are rejected. This does
not verify a hosted workload identity or transparency inclusion. A future keyless profile must
verify Fulcio identity/issuer and current Sigstore transparency evidence without inventing
cryptographic primitives or hard-coding a Rekor shard.

### Correlation and policy verifier (fixture slice implemented)

The verifier recomputes artifact, stream, graph, manifest, provenance, and policy commitments;
checks cross-document build/run/source identities; evaluates deterministic behavior policy;
and applies precedence `REJECT > REVIEW > ALLOW`. Incomplete evidence is a verification state
that policy cannot upgrade to `ALLOW`.

## Data ownership and ordering

The sensor supplies kernel observations, not policy decisions. The collector owns event
sequence and persistence. Graph construction is pure and replayable. The attestation composer
does not mutate evidence. The signer authenticates immutable statement bytes. The verifier
receives untrusted bytes and recomputes all links under local policy.

Build registration supplies repository and revision to the sensor before collection. Those values
are immutable event-scope fields and must equal provenance, but the local registrar is not an
authenticated source-control authority. This separates demonstrated equality from future hosted
identity assurance.

## Technology choices

Go plus `cilium/ebpf` was selected over Aya and a pure third-party adapter after comparison in
the [gap analysis](research/runtime-attestation-gap.md). The choice favors mature Go in-toto,
Sigstore, and eBPF ecosystems while keeping BPF code small. Protobuf is deferred until kernel
record semantics have been exercised; versioned canonical JSON prevents premature schema
stability claims in the first slice.

## Failure behavior

Malformed data, duplicate keys, unsupported versions, digest mismatch, identity conflict, and
missing artifact attribution fail closed. Event loss produces `incomplete`; strict policy maps
that to `REVIEW` or `REJECT`. Operational parser errors use a distinct exit status from policy
decisions.

## Privilege and host trust

The sensor needs BPF/perfmon-style privileges appropriate to the host configuration; the tested
lab uses a privileged disposable container. Future BPF LSM programs may need additional host
configuration. After loading,
capabilities should be reduced; evidence output and policy should be read-only to the build.
Seccomp, Landlock, map freezing, and split loader/collector processes will be evaluated against
actual required syscalls. None of these controls defeats hostile root.
