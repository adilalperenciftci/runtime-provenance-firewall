# Security review

This document records demonstrated results separately from hypotheses. “Observed” means runtime
evidence exists; “detected” means a rule emitted a finding; “rejected” means the final policy
decision was `REJECT`.

The sections below are three role-separated review passes performed during implementation, not a
claim of third-party human audit. Each pass used its own threat questions and converted material
findings into code and regressions; unresolved trust and portability limits remain explicit.

## Kernel/security reviewer

The kernel pass found that kernel-reported parent keys could produce graph edges whose parent node
was absent from the observation interval without an explicit uncertainty marker. Graph schema
v0.2 fixes this by labelling each parent `observed`, `unobserved`, or `none`; unit and privileged
graph assertions cover the distinction. This improves claim precision but does not recover missing
ancestry or defend against a privileged hostile host.

A final graph review found the edge label still said `observed_exec_parent` when its source node
was absent, contradicting the node label. Graph construction now assigns
`unobserved_exec_parent` after collecting all nodes, with positive, negative, and privileged
regressions. No missing ancestor is synthesized.

Loss-cause instrumentation exposed that the no-sensitive-path baseline still read every read-only
`openat` pathname and could report irrelevant no-fault read failures. The BPF program now filters
those operations by flags before pathname access when sensitive monitoring is disabled. Write
opens and all opens under an active sensitive-path profile retain fail-closed path-read accounting.

## Supply-chain reviewer

The supply-chain pass found that SLSA `builder.id` was required but not authorized, while repository
identity was only internally correlated. A consistently forged identity could pass policy if its
signature key was otherwise trusted. The verifier now binds `runDetails.builder.id` to the runtime
correlation identity and requires exact policy allowlists for builder and repository. Regression
tests require `RPF-BUILDER-001` and `RPF-SOURCE-001` rejections. This does not establish OIDC
workload identity, source VSA validation, or transparency freshness.

Supply-chain review then found that runtime evidence carried build/run IDs but source identity was
introduced only by provenance. Repository and revision are now immutable event-scope fields and
part of sensor configuration identity; assembly rejects exact source disagreement. Unit and CLI
regressions cover commit/repository mismatch. These fields remain local registration assertions,
not authenticated checkout proof.

The same review found delimiter ambiguity in the sensor configuration hash's former line-oriented
encoding. It now hashes typed JSON fields, so embedded separators cannot change field boundaries.

## Detection engineer

The detection-engineering pass found that artifact-producer identity was present in evidence and
graph edges but
had no dedicated policy control; the general executable rule could produce only `REVIEW`. Policy
now requires an exact artifact-producer allowlist and emits `RPF-ARTIFACT-PRODUCER-001` with
`REJECT` for any other producer. A regression uses a consistently renamed producer so the finding
is semantic to artifact finalization, not a conflicting graph identity. Exact path identity remains
representation-sensitive and does not substitute for content/package identity.

Parser review added bounded native fuzz targets for event, policy, and attestation boundaries.
Seeds include valid canonical fixtures and malformed minimal documents. Scheduled runs are
time-bounded and unprivileged; they do not cover kernel verifier behavior or establish exhaustive
parser safety.

The lab originally placed root build processes beside a root collector; cgroup membership alone
does not restrict filesystem access. Build commands now enter the monitored cgroup through a
fixed helper, set `no_new_privs`, clear supplementary groups, drop to UID/GID 65534, and receive no
host environment values. A full-suite rerun exposed a Go thread-credential race that intermittently
retained supplementary group 0; locking the helper to one OS thread before credential changes and
requiring exact `id` output fixed the observed path. A real append to the collector's 0600 evidence
file is denied. Repeated
runs observed correlation-loss counts of zero and one. Cause-specific counters identified the
non-zero case as path-read failure, not the previously hypothesized process-exit race; map update
and cgroup mismatch remained zero. Strict verification requires complete evidence for zero, and
`incomplete` plus `RPF-EVIDENCE-001` for non-zero. Either path retains the
behavioral `REJECT`. This isolates the synthetic build from ordinary collector files but not from
host root, the privileged container, kernel compromise, or a malicious collector.

## Controlled malware-behavior experiments

MBE-001 emulates a synthetic credential-file read, child execution, artifact staging, an
executable-renaming variation, and a fixed localhost-only callback. It is not malware. Both reads
and the numeric callback attempt were observed and detected, the secret value was absent from
evidence, process attribution was retained, and policy rejected the bundle with
`RPF-SENSITIVE-001` and `RPF-EGRESS-001`. See
[MBE-001](lab/MBE-001-sensitive-read-and-child.md).

## Intentionally vulnerable fixtures

EXP-001 provides a single-request localhost service whose explicitly vulnerable mode trusts
attacker-controlled adapter-role metadata. The paired patched mode derives authorization from the
synthetic session role. Both are repository-owned, disposable, and use only fixed synthetic data.

## Exploitability-confirmed findings

EXP-001 exists and was dynamically exploitable: the fixed proof crossed the synthetic reader/admin
boundary and obtained a harmless marker. See
[EXP-001](lab/EXP-001-adapter-role-confusion.md). Telemetry observed the proof but did not identify
the authorization semantic; policy rejection came from undeclared egress.

## Exploitability-rejected hypotheses

None yet; no exploit hypothesis has completed the required dynamic validation cycle.

## Authorization-boundary experiments

EXP-001 vulnerable mode granted a synthetic admin marker based on adapter metadata. A separate
patched build denied identical input. Each run has an independent cgroup, identity, evidence chain,
graph, artifact, provenance, and runtime trace. The responsible proof process and connection were
attributed correctly. The detector cannot distinguish grant from denial; this is a confirmed blind
spot, not a negative exploitability result.

## Detection-evasion experiments

Renaming `/bin/sh` to the generated local path `build/out/rpf-renamed-shell` did not bypass the
sensitive-path finding. Telemetry observed the renamed executable, detection emitted the same
`RPF-SENSITIVE-001`, and policy remained `REJECT`. This tests one representation change only and
does not establish general evasion resistance.

Kernel review found that a sensitive path opened with write flags was previously classified as a
generic write before sensitive-path matching. Sensitive equality now has precedence. A writable
synthetic credential copy is opened with `O_RDWR` in both adversarial builds; all three sensitive
opens retain `RPF-SENSITIVE-001`. This fixes that representation bypass without treating every
write as credential access.

The same numeric-connect signal is exercised negatively and positively: undeclared ports 18080
and 18081 produce `RPF-EGRESS-001`, while policy-declared port 18082 remains finding-free in the
benign baseline. This validates exact endpoint semantics only, not domain, proxy, or IPv6 handling.

The kernel baseline now feeds permanent stream-integrity regressions. Interior deletion and
byte modification are rejected by sequence/hash validation. Tail truncation is structurally a
valid hash-chain prefix, so the lifecycle invariant—not the chain—forces `unknown` completeness
and strict `REJECT`. A signed external checkpoint remains necessary to detect rollback to another
complete historical stream.

The signing path rejects modified or malformed attestation bytes and rejects a genuine bundle
under an unrelated generated public key. Separately, the verifier CLI rejects malformed SLSA
provenance and a provenance subject with a wrong artifact digest without creating an output
bundle. This demonstrates local fixture rejection, not keyless identity or transparency-log
verification; the current lab intentionally uses an offline key and skips tlog verification.
The baseline now invokes one fail-closed offline entry point that verifies both signed blobs before
semantic correlation; signature failure prevents the policy verifier from running. This closes the
local orchestration gap but does not supply keyless workload identity or transparency freshness.

Runtime replay is exercised with two independently captured, complete kernel event streams. A
bundle from build B presented with build A's artifact, events, and provenance produces explicit
identity, manifest, and runtime-trace integrity reasons and `REJECT`; build B provenance presented
with build A events fails assembly. This establishes cross-build mismatch handling for the local
identity profile, not freshness against a trusted external clock or transparency checkpoint.

## Exploit-to-telemetry correlation

For MBE-001, the non-exploit chain is: fixture shell input → successful `openat` → kernel
entry/exit correlation → categorized event → process/graph edge → `RPF-SENSITIVE-001` → `REJECT`.

For EXP-001: fixed proof input → vulnerable role selection → synthetic marker grant → proof
process/connect observation → graph edge → undeclared-egress finding → `REJECT`. The vulnerability
was exploitable and observable, but the authorization violation itself was not detected.

## Patch validation

EXP-001 patched mode was rerun as an independent monitored build with the exact proof and denied
the marker while returning a valid response and still producing its benign test artifact. Kernel
telemetry remained present. Benign authorization functionality is unit-tested for the trusted
admin role through the common authorization function. Parser resource limits and artifact
substitution checks remain defensive regressions, not this target's remediation.

The consolidated acceptance script preserves these as separate claims in a generated report:
exploitability, telemetry, detection reasons, policy outcome, and remediation are not collapsed
into one boolean.

Both the intentionally vulnerable target and its fixed proof run in the monitored disposable
cgroup. Their separate exec identities and the proof's localhost connection are retained in the
execution graph; kernel telemetry still cannot infer the target's semantic grant decision.

## Claim matrix

| Experiment | Vulnerability exists | Exploit demonstrated | Telemetry observed | Detection identified | Policy rejected | Remediation validated |
| --- | --- | --- | --- | --- | --- | --- |
| MBE-001 baseline | not applicable | not applicable | yes | yes | yes | not applicable |
| MBE-001 renamed shell | not applicable | not applicable | yes | yes | yes | not applicable |
| MBE-001 localhost callback | not applicable | not applicable | yes | yes | yes | not applicable |
| EXP-001 vulnerable role confusion | yes | yes | yes | no (authorization semantic) | yes (egress reason) | not applicable |
| EXP-001 patched role handling | no for original flaw | original proof rejected | yes | no (authorization semantic) | yes (egress reason) | yes |
