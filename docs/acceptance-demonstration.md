# Acceptance demonstration

`tools/final-acceptance.sh` is the single privileged acceptance entry point after binaries and the
CO-RE object are built. `tools/kernel-lab.sh` builds the pinned-base lab, runs unit/race/vet and
negative integrity/replay checks, then invokes that acceptance script.

The acceptance script executes three actual paths:

1. a zero-loss benign build whose artifact, source/build identity, SLSA provenance, Runtime Trace,
   offline Cosign signatures, and policy verify as `ALLOW`; subsequent artifact substitution is
   `REJECT` with `RPF-ARTIFACT-001`;
2. the intentionally vulnerable localhost authorization fixture, where the fixed proof obtains
   only a synthetic marker while both target and proof execute in the monitored cgroup, sensitive
   access and localhost egress are attributed, and policy returns `REJECT`;
3. the patched fixture with identical proof input, where marker access is denied and benign
   artifact creation remains functional; unchanged sensitive/egress behavior still returns
   `REJECT`.

On success it writes `build/out/final-acceptance-report.json`. The report names responsible
executables, retained evidence/graph/attestation paths, affected invariants, reason codes, and the
important blind spot: authorization grant versus denial is not itself visible in current kernel
telemetry. Fixed report claims are emitted only after the scripts assert their underlying files,
outcomes, signatures, and decisions. Generated output is not committed as immutable test history.

The benign path includes the fixed, network-free synthetic package-install fixture. The artifact
helper accepts only a pre-created regular `sensor-*-artifact.txt` directly under the
generated lab output directory, rejects symbolic links at open time, and requires the
disposable-lab environment marker. This supports independent replay fixtures without becoming a
general file-writing utility.
