# Security Policy

## Supported Versions

The project is an experimental prototype. Fixes are applied to the `main` branch; no stable release line exists yet.

## Reporting

Do not open public issues for security vulnerabilities. Use GitHub's private vulnerability reporting feature for this repository. If unavailable, contact the maintainer directly through the contact information in their profile.

Reports should include:
- Affected commit hash or version
- Reproduction environment and prerequisites (e.g., Linux kernel version, BPF capabilities)
- Minimal synthetic reproducer (scripts, event stream, or attestation fixtures)
- Technical description of the vulnerability and security impact

Do not submit tests against production infrastructure or third-party environments.

## Scope

The following areas are in scope:
- Parser differential, ambiguity, or denial-of-service vulnerabilities in event stream or policy decoding
- Hash chain or event commitment validation bypasses
- Provenance correlation verification bypasses (e.g., mismatched build identity or source revision accepted)
- Execution graph reconstruction errors that miss unobserved ancestry or unauthorized process transitions
- Sensor scope evasion allowing cgroup-isolated processes to perform unmonitored security-relevant operations

Out of scope:
- Host-level root/kernel compromises that bypass eBPF hooks entirely
- Intentional kernel event drops under extreme throughput when properly identified and rejected by the verifier's loss-detection policy
