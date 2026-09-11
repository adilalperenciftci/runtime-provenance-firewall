# Threat model

## Security objective

Runtime Provenance Firewall (RPF) determines whether an artifact's supplied build provenance,
runtime evidence, CI identity, and policy are mutually consistent and whether observed build
behavior conforms to policy. It preserves minimized evidence supporting that decision.

The primary integrity claim is conditional:

> Given an authorized sensor and signer, an uncompromised kernel/host trust boundary, a
> complete evidence stream, and the supplied verification inputs, the verifier detects any
> mismatch among the artifact, runtime trace, execution graph, SLSA provenance, build identity,
> policy digest, and signed statement.

This is not proof that the build host was honest or that unobserved behavior did not occur.

## Assets

- artifact bytes and digest;
- source repository and revision identity;
- CI workflow, run, attempt, runner, and builder identity;
- runtime event ordering, completeness, and build attribution;
- process ancestry and relevant file/network observations;
- SLSA provenance and Runtime Trace statements;
- signing identity, trust roots, and transparency verification material;
- policy and sensor configuration;
- build credentials, whose values must never enter retained event content.

## Trust boundaries

1. Source control to build platform: source and workflow definitions enter execution.
2. CI control plane to runner: run identity, OIDC claims, and credentials enter a host.
3. Host monitor to untrusted build cgroup: privileged observation surrounds build processes.
4. Kernel to collector: bounded records cross a BPF ring buffer that can lose events.
5. Collector to evidence store: normalized records and manifests become persistent claims.
6. Artifact finalization to digest binding: mutable filesystem state becomes a named subject.
7. Evidence/provenance to signer: claims become authenticated but not necessarily true.
8. Bundle and artifact to verifier: untrusted parsers process attacker-controlled documents.
9. Trust policy to verdict: local authorization determines whether valid identities are accepted.

## Trust assumptions

- The monitor starts outside and before the untrusted build cgroup.
- The kernel, boot chain, sensor binary, collector, and host controls are trusted for the
  strength of kernel-origin claims.
- CI identity is authenticated by a platform mechanism or explicitly classified as asserted.
- Policy and trust roots arrive through an administrator-controlled channel.
- Artifact hashing occurs after the last monitored output mutation and before unmonitored
  substitution, or substitution is later caught by digest verification.
- Strict mode receives every required document and external evidence blob.

When an assumption is not established, the result is `INCOMPLETE`, `REVIEW`, or `REJECT`, not
an implicit clean verdict.

## Adversaries

- a malicious dependency or install script inside the build;
- a compromised repository build script or CI step;
- an attacker with a stolen build credential;
- a malicious or compromised tool provider;
- an attacker modifying artifacts, provenance, evidence, or signatures;
- a compromised CI runner with user-level or root-equivalent access;
- a platform administrator able to disable the kernel sensor;
- a verifier-input attacker supplying malformed, ambiguous, or replayed documents.

## Threat analysis

| Threat | Observable evidence/control | Classification | Residual limitation |
| --- | --- | --- | --- |
| Malicious dependency executes | exec ancestry under package manager; policy finding | Detects/records | Cannot infer malicious intent from execution alone |
| Install script reads credential path | policy-selected file-open; no content | Detects/records; later BPF LSM may prevent | Path aliases, inherited FDs, mmap, and unsupported filesystems need coverage |
| Unexpected build egress | connect destination and ancestry | Detects/records; policy may reject | DNS association is weaker than IP evidence |
| Undeclared child tool | exec edge and ancestry policy | Detects/records | Interpreter/JIT semantics exceed executable path |
| Compromised CI step | behavior and identity inconsistencies | Detects some outcomes | Allowed-looking malicious action may remain undetected |
| Stolen build credential | credential-category access plus egress | Detects some use | Theft before monitoring or outside hooks is unseen |
| Provenance tampering | signature/provenance digest mismatch | Prevents acceptance | Trusted compromised signer can sign false claims |
| Artifact substitution | current digest differs from subjects | Prevents acceptance | Verifier must receive exact consumed bytes |
| Runtime-log modification/reordering | event chain and manifest digest | Detects/rejects | Whole-bundle deletion is availability loss |
| Forged event injection | sensor identity, chain, sequence, signature | Detects/rejects | Authorized compromised collector can forge output |
| Sensor disablement | lifecycle gap or counter read failure | Detects if evidence survives | Root can disable sensor and forge local evidence if signer is reachable |
| Event loss | kernel/decode/queue/persistence counters | Marks incomplete; blocks `ALLOW` | Dropped content is unknowable |
| Privileged host attacker | no sufficient initial control | Explicitly not defended against | Needs measured boot/remote attestation/isolated signer |
| Compromised CI runner | mismatch checks and behavior policy | Detects some actions | Root-equivalent compromise is outside strong claim |
| Replayed attestation | build nonce/run identity mismatch | Rejects when current run is required | Reproducible builds may validly have multiple attestations |
| File-identity TOCTOU | final subject digest and event timing | Detects final mismatch | Async eBPF cannot atomically hash every accessed input |
| PID identity ambiguity | boot ID + PID namespace + TGID + start time | Reduces ambiguity | Missing fields make attribution incomplete |
| Cgroup escape/reassignment | cgroup lifecycle and movement signals | Detects supported transitions | Host-authorized movement before observation can evade attribution |
| Malformed input | bounded strict parser; duplicate rejection | Prevents acceptance | Cross-parser differentials require conformance tests |
| Invalid/unauthorized signature | Sigstore verification plus identity policy | Prevents acceptance | Trust-root compromise remains trusted |
| Unobserved output write | missing artifact-producing edge | Marks incomplete/review | Coverage depends on hooks and filesystems |

## Security classifications

### Prevents in strict verification

- acceptance of artifact, evidence, graph, policy, or provenance digest mismatches;
- acceptance of malformed required documents;
- `ALLOW` when evidence is absent or loss is non-zero/unknown;
- acceptance of signatures outside configured identity and issuer constraints;
- silent reconciliation of conflicting build, source, workflow, or run identities.

### Detects or records

- selected process ancestry and executable identity;
- selected sensitive-path access without contents;
- selected artifact write/rename associations;
- network connection destinations and outcomes;
- event loss and sensor lifecycle failures;
- deterministic behavioral-policy findings.

### Cannot reliably observe

- activity before sensor attachment or after finalization;
- semantic intent, shell-language meaning, or all in-process/JIT behavior;
- data already in memory or inherited open descriptors without a later relevant hook;
- complete DNS causality from socket telemetry alone;
- hardware, firmware, hypervisor, or kernel compromise;
- external services behind an allowed proxy beyond the observed proxy endpoint.

### Explicit non-goals

- resisting root-equivalent hosts that control sensor and signer;
- replacing SLSA, Sigstore, SBOMs, sandboxing, OAuth, EDR, or network policy;
- collecting file contents, environment values, credential values, or packet payloads;
- claiming prevention when verification happens only after artifact use;
- deriving causality stronger than captured kernel semantics.

## Event-loss invariant

Completeness is `complete`, `incomplete`, `unknown`, or `invalid`. `complete` requires a
verified chain, lifecycle start/finalization, and zero kernel, decode, queue, and persistence
loss. Only `complete` evidence can contribute to `ALLOW`; policy cannot upgrade another state.

## Root attacker boundary

Hash chains and signatures make post-collection changes evident to a verifier with correct
trust roots. They do not make a compromised producer truthful. Future work may bind the
sensor to measured boot or a remotely attested confidential VM and keep signing authority
outside the runner. Until demonstrated, results describe evidence from an authorized sensor,
not proof against the host administrator.
