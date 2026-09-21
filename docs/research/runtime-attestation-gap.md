# Runtime attestation gap analysis

## Research question

Can a verifier establish that one artifact, one declared build, and one observed runtime
execution belong to the same authorized build instance without trusting a filename, mutable
CI workspace, or producer-supplied label?

## What is already solved

| Capability | Existing mechanism | Status |
| --- | --- | --- |
| Digest-addressed artifact subject | in-toto Statement, SLSA provenance | Standardized |
| Builder, source, invocation metadata | SLSA v1.2 provenance | Standardized |
| Source revision governance | SLSA v1.2 Source Track | Standardized at track level |
| Identity-bound signing | Sigstore/Fulcio/Cosign | Implemented |
| Transparency/offline verification material | Rekor, Sigstore bundles | Implemented |
| Runtime trace carrier | in-toto Runtime Trace v0.1 | Experimental predicate |
| Rich kernel telemetry | Tetragon, Tracee, Falco | Implemented |
| CI ancestry detection and Runtime Trace output | cicd-sensor | Implemented |
| SBOM/build formulation | SPDX 3.0.1, CycloneDX 1.7 | Standardized |

Another generic sensor or unsigned JSON report would not close a meaningful gap.

## Unclosed verification obligations

### Evidence commitment

Runtime Trace permits monitor-specific arrays but does not require an ordered canonical event
stream. Large evidence should not be duplicated in every attestation. A predicate needs a
content digest over a versioned evidence manifest, and the verifier needs the manifest bytes.
The digest must commit to ordering, schema version, monitor configuration, build scope, loss
counters, and graph derivation inputs.

### Cross-document identity

Signing two attestations about the same artifact does not prove that they came from the same
build execution. A strict verifier must compare explicit values:

- artifact SHA-256 equals every required in-toto subject digest;
- runtime `build_id` equals the correlation ID carried by provenance;
- source repository and revision equal provenance parameters/materials;
- CI provider, run ID/attempt, workflow identity, and builder ID satisfy policy;
- the monitoring interval encloses the artifact production observation;
- policy and sensor-configuration digests equal trace commitments;
- signer identity and OIDC issuer satisfy authorization policy.

A missing field is not a wildcard in strict mode.

### Completeness and loss

Kernel ring buffers can fill. A collector can fail decoding, restart, or miss build start. A
trace can be truncated after collection. A signed incomplete trace is authentic but not
complete evidence. The profile therefore needs explicit counters and lifecycle facts:

- sensor attached before build-cgroup activation;
- sensor remained attached through artifact finalization;
- kernel reservation failures;
- userspace decode, queue, and persistence failures;
- first and last monotonic sequence observations;
- clean collector shutdown and finalized manifest;
- hash-chain verification result.

Strict verification maps unknown or non-zero relevant loss to `INCOMPLETE`, which cannot
produce `ALLOW`. Policy may map it to `REVIEW` or `REJECT`; it may not erase completeness.

### Execution-graph semantics

An event list does not answer which process produced an artifact. Graph node keys need host
boot ID, PID namespace inode, TGID, and process start time; PID/PPID alone is ambiguous.
Parentage observed at exec supports ancestry. File write or rename supports an observed
association with an output path. Neither proves semantic causation or that every output byte
came from that process.

Edges must therefore state observation semantics such as `observed_exec_parent`,
`unobserved_exec_parent`,
`opened_for_write`, `renamed_to_output`, and `connected_to`, never generic `caused`.

### Replay resistance

An old valid trace can share source and artifact digests with a reproducible build. If policy
requires evidence for the current CI execution, the trace must bind an unpredictable build
nonce or platform-issued run identity and the verifier must compare it with provenance.
Timestamp freshness alone is insufficient. Reproducible artifacts may legitimately have
multiple attestations; replay is an identity/policy mismatch, not necessarily a digest mismatch.

## Comparison

| System | Strong area | Gap relative to narrowed thesis |
| --- | --- | --- |
| SLSA v1.2 | Declared build/source provenance and platform assurance | No required kernel trace or event completeness model |
| Runtime Trace v0.1 | Interoperable monitor-output carrier | Monitor-specific event schema; no loss or equality profile |
| Sigstore/Cosign/Rekor | Signature identity, bundles, transparency | Authenticates claims; does not establish completeness/correlation |
| SPDX/CycloneDX | Inventory and build formulation | Not a kernel evidence integrity protocol |
| Tetragon | Selective rich kernel observation/enforcement | No artifact/SLSA/build-instance verification profile |
| Tracee | Broad runtime and forensic events | No artifact-bound build verifier |
| Falco | Streaming rules and drop visibility | No cross-source correlation or build graph |
| cicd-sensor | CI eBPF, ancestry detections, loss counters, Runtime Trace | Predicate omits detailed graph/file evidence; loss and cross-document equality are not strict verifier states |
| OpenSSF Scorecard | Repository-practice heuristics | Static posture, not per-build runtime evidence |

## Three implementation strategies

### A. Go collector and verifier with cilium/ebpf CO-RE

Small BPF C CO-RE objects emit bounded records. A Go collector loads them with `cilium/ebpf`,
filters by cgroup, persists canonical events, builds the graph, and emits attestations. A
portable Go verifier uses mature in-toto and Sigstore libraries.

Security value: high. Novel work stays in correlation. Kernel complexity: moderate.
Portability: Linux sensor and cross-platform replay/verifier. Reproducibility: good with pinned
Go modules, Clang, and disposable VM tests. Maintainability: strongest because relevant Go
libraries and reference implementations are mature.

### B. Rust collector and verifier with Aya

Aya avoids a C/libbpf runtime dependency and can share Rust types between eBPF and userspace.
Rust gives strong memory-safety properties for parsers and graph handling.

Security value: high. Kernel complexity: moderate to high because fewer examples cover the
complete CI trace and Sigstore path. Portability: comparable. Reproducibility: good after a
larger toolchain bootstrap. Maintainability: credible, but in-toto/Sigstore integration is less
mature than Go for this project.

### C. Collector-agnostic verifier over Tetragon/cicd-sensor adapters

This consumes existing JSON/protobuf events and focuses on normalization, graphing,
attestation, and verification.

Security value: high only if source-specific loss/lifecycle signals are faithfully adapted.
Kernel complexity: low. Portability: best. Reproducibility: mixed because upstream event
semantics enter the trusted computing base. Maintainability: adapter-heavy. This is useful as
a future integration mode but too dependent on external semantics for the reference proof.

## Selected architecture

Strategy A is selected. Go is chosen because in-toto, Sigstore, and cilium/ebpf support are
mature and cicd-sensor demonstrates stack viability. CO-RE BPF C is restricted to stable
tracepoints, LSM/cgroup hooks, and fixed wire records. The verifier remains usable without
Linux or privilege.

Adapters can follow, but the reference sensor preserves loss and lifecycle semantics under
project control. Aya remains an alternative if the Go prototype exposes memory-safety or
deployment problems not addressed by narrow parsers and privilege separation.

## Smallest Runtime Trace extension

The outer object remains an in-toto Statement v1 with the Runtime Trace v0.1 predicate type
and artifact digest subjects. Standard `monitor`, `monitoredProcess`, `monitorLog`, and
`metadata` fields remain. One namespaced extension carries only correlation commitments:

```text
https://github.com/adilalperenciftci/runtime-provenance-firewall/runtime-provenance/v0.1
  buildId
  runIdentity
  sourceRevision
  evidenceManifestDigest
  executionGraphDigest
  slsaProvenanceDigest
  policyDigest
  completeness
  sensorLifecycle
```

Detailed events remain external content-addressed evidence. This minimizes attestation size
while making omission, substitution, reordering, and cross-build reuse detectable when the
verifier has the evidence bundle.

## Claim boundary

The design can test whether signed claims and supplied evidence are internally consistent and
policy-conforming. It cannot prove that a root-equivalent hostile host emitted truthful
telemetry, that every kernel path was observable, or that an observed process semantically
caused every artifact byte. These limits remain even when cryptographic checks pass.
