# Limitations

This repository is a research prototype and does not establish production suitability.

## Trust and integrity limits

- A root-equivalent or runner-host attacker can disable, replace, or lie to the sensor. The system
  records and detects some evidence inconsistencies; it does not create a trusted kernel or host.
- The disposable lab drops build commands to UID/GID 65534 with `no_new_privs` and a minimal
  environment after entering the target cgroup. The collector itself still runs as root in a
  privileged container; this is fixture isolation, not hardened loader/collector privilege
  separation.
- Hash chaining detects retained-record modification, insertion, and interior deletion. It does
  not authenticate an unsigned stream, and a complete historical rollback needs a trusted signed
  checkpoint or transparency mechanism to detect.
- The reproducible lab signs with an offline Cosign key and intentionally skips transparency-log
  verification. Keyless workload identity, certificate constraints, Rekor monitoring, and trusted
  time/freshness are not demonstrated.
- Local provenance is an explicitly unsigned fixture profile. It is structurally SLSA v1.2 Build
  compatible but does not claim a SLSA Build level or hosted-builder trust.
- Runtime events bind repository/revision registration claims to provenance, but the local sensor
  does not verify checkout contents or authenticate those claims against source control.

## Observation and attribution limits

- Current CO-RE telemetry covers exec, selected output/sensitive opens, and IPv4 TCP connect
  attempts for one registered cgroup v2 identity. It does not cover all syscalls or all file access.
- Network evidence is a numeric connection attempt, not proof of DNS name, TLS identity, request
  content, successful delivery, proxy origin, UDP, or IPv6 behavior.
- Exact path comparison misses aliases, symlinks, inherited descriptors, mmap-based reads,
  `openat2`, and relevant activity that predates an observed process identity.
- Process ancestry is observational. PID namespace, start time, boot ID, and cgroup reduce ambiguity
  but do not prove causal influence, data flow, or application authorization outcomes.
- Artifact write-open attribution identifies an observed writer ancestor and final digest. It does
  not prove every byte-level causal contributor or eliminate TOCTOU between observation and use.
- Ring-buffer and collector counters make known loss fail closed. They cannot prove that a hostile
  privileged host reported counters honestly or expose every unknown sensor blind spot.

## Policy and portability limits

- Policies currently match exact executable paths, numeric endpoints, and sensitive categories.
  Domain, certificate, package identity, content-derived executable identity, and semantic
  application authorization policies are not implemented.
- The privileged sensor requires Linux with cgroup v2, BTF, eBPF ring buffers, and the documented
  hook support. Windows is only a developer host; Docker Desktop/WSL2 does not provide identical
  semantics to a dedicated Linux CI runner.
- The adversarial corpus is synthetic, localhost-only, and intentionally non-deployable. Passing it
  demonstrates those fixtures, not malware coverage, exploit prevention, or field detection rates.
- Performance, sustained event throughput, and representative build overhead remain unmeasured;
  see `benchmarks.md` for the exact status and reproducible microbenchmark command.

Durable threat classifications are in `threat-model.md`; kernel/version details are in
`kernel-support.md`; cryptographic boundaries are in `runtime-attestation.md` and
`release-integrity.md`.
