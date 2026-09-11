# References

Primary specifications and project documentation are listed first. Access was verified on
2026-09-11 unless otherwise noted.

## Provenance and attestations

1. SLSA. [Specification v1.2](https://slsa.dev/spec/v1.2/).
2. SLSA. [Build requirements](https://slsa.dev/spec/v1.2/build-requirements).
3. SLSA. [Build provenance](https://slsa.dev/spec/v1.2/build-provenance).
4. SLSA. [Source requirements](https://slsa.dev/spec/v1.2/source-requirements).
5. in-toto. [Attestation Framework](https://github.com/in-toto/attestation).
6. in-toto. [Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md).
7. in-toto. [Envelope specification](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md).
8. in-toto. [Runtime Trace v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md).
9. Sigstore. [Cosign](https://github.com/sigstore/cosign).
10. Sigstore. [Bundle format](https://docs.sigstore.dev/about/bundle/).
11. Sigstore. [Verification](https://docs.sigstore.dev/cosign/verifying/verify/).
12. Sigstore. [Rekor v1](https://github.com/sigstore/rekor).
13. Sigstore. [Rekor v2](https://github.com/sigstore/rekor-tiles).
14. Sigstore. [Signing blobs with Cosign](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/).
15. Sigstore. [Cosign v3 releases](https://github.com/sigstore/cosign/releases).
16. Sigstore. [GHSA-whqx-f9j3-ch6m](https://github.com/sigstore/cosign/security/advisories/GHSA-whqx-f9j3-ch6m).
17. SPDX. [Specification 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/).
18. SPDX. [Build profile](https://spdx.github.io/spdx-spec/v3.0.1/model/Build/Build/).
19. CycloneDX. [Specification 1.7](https://cyclonedx.org/docs/1.7/json/).

## Linux kernel and eBPF

20. Linux kernel. [BPF Type Format](https://docs.kernel.org/bpf/btf.html).
21. Linux kernel. [libbpf and CO-RE](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html).
22. Linux kernel. [BPF ring buffer](https://docs.kernel.org/bpf/ringbuf.html).
23. Linux kernel. [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html).
24. Linux kernel. [Cgroup storage](https://docs.kernel.org/bpf/map_cgroup_storage.html).
25. libbpf. [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap).
26. Cilium. [`cilium/ebpf`](https://github.com/cilium/ebpf).
27. Aya. [Aya book](https://aya-rs.dev/book/).

## Runtime and CI security

28. Cilium. [Tetragon](https://tetragon.io/docs/).
29. Aqua Security. [Tracee](https://github.com/aquasecurity/tracee).
30. Falco. [Event sources](https://falco.org/docs/concepts/event-sources/).
31. Falco. [Dropped events](https://falco.org/docs/concepts/event-sources/kernel/dropped-events/).
32. cicd-sensor. [Repository](https://github.com/cicd-sensor/cicd-sensor).
33. cicd-sensor. [Runtime Trace predicate](https://github.com/cicd-sensor/cicd-sensor/blob/main/docs/user-guide/attestation-predicate.md).
34. GitHub. [Secure use](https://docs.github.com/en/actions/reference/security/secure-use).
35. GitHub. [Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations).
36. GitHub Actions. [`actions/attest`](https://github.com/actions/attest).
37. GitHub. [Compromised runners](https://docs.github.com/en/actions/concepts/security/compromised-runners).
38. GitLab. [Runner security](https://docs.gitlab.com/runner/security/).
39. GitLab. [OIDC ID tokens](https://docs.gitlab.com/ci/secrets/id_token_authentication/).
40. OpenSSF. [Scorecard](https://github.com/ossf/scorecard).
41. OpenSSF. [Scorecard checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md).
42. CISA/NSA/ESF. [Recommended Practices for Developers](https://www.cisa.gov/sites/default/files/2023-12/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_DEVELOPERS.pdf).
43. CISA/NSA/ESF. [Managing OSS and SBOMs](https://www.cisa.gov/sites/default/files/2024-08/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN%20RECOMMENDED%20PRACTICES%20FOR%20MANAGING%20OPEN%20SOURCE%20SOFTWARE%20AND%20SOFTWARE%20BILL%20OF%20MATERIALS_508.pdf).

## Research-use note

The comparison in `docs/research/` reflects documented and inspected capabilities, not a
certification of any listed project. Upstream behavior and schemas can change; integrations
must pin and re-review exact versions.
