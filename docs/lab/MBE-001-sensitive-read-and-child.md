# MBE-001: synthetic sensitive-file read and child execution

## Classification and scope

This is malware-behavior emulation, not deployable malware. It has no scanning, propagation,
persistence, Internet communication, credential collection, destructive action, or host-targeting
logic. It runs in a disposable cgroup, reads only
an isolated writable copy of `lab/fixtures/synthetic-credential.txt` under `build/out`, and writes
only generated files under `build/out`.

## Intended observations

The target-cgroup `/bin/sh` must successfully open the configured synthetic credential path,
launch `/usr/bin/id`, and write the synthetic artifact. Telemetry must retain category
`synthetic_credential`, process identity and ancestry, but never the fixture value. A second run
inside the same monitored interval executes a copied shell named
`build/out/rpf-renamed-shell` and repeats the read to test representation robustness.
The first shell also opens the same generated fixture with `O_RDWR` without changing it, ensuring
generic write classification cannot hide a sensitive-path event.

Expected policy result: `REJECT` with `RPF-SENSITIVE-001`. The renamed executable may add
`RPF-PROCESS-001` but must not suppress the sensitive-access finding.

## Reproduction and actual result

Run `./tools/test-adversarial.sh` in the checked-in kernel lab image. On 2026-09-11, Linux
`6.18.33.2-microsoft-standard-WSL2` produced two independent valid 17-event streams (vulnerable
and patched authorization fixtures), each with seven graph nodes, 15 graph edges and three
`file_open_sensitive` events. Repeated runs produced correlation-loss counts of zero or one; the
non-zero cause was a kernel path-read failure. Completeness and `RPF-EVIDENCE-001` followed that
counter. Both runs ended in
`REJECT` containing sensitive-access and egress reasons.

The exact process IDs vary; the script asserts stable reason codes and security invariants. It
also searches both evidence streams and fails if the synthetic value occurs.

The expanded specimen also executes the fixed `rpf-local-connect` helper against the repository
mock at `127.0.0.1:18080`. The helper and server reject non-loopback configuration. Kernel
telemetry records one numeric attempted connection, graph reconstruction attributes it to the
helper, and policy additionally emits `RPF-EGRESS-001`. No claim is made that TCP completed based
on the kernel event alone; the mock's marker receipt independently proves the local fixture path.

## Evasion result and blind spots

Executable renaming and an `O_RDWR` representation did not bypass category detection because
kernel filtering keys on the exact sensitive path before generic write classification. Current
blind spots include aliases/symlinks, relative paths,
`openat2`, inherited descriptors, mmap access, path replacement, and reads that begin before the
process has an observed exec identity. The test does not claim that reading a file is malicious;
policy makes this specific synthetic category forbidden for the build.

The callback variation currently covers IPv4 TCP only. IPv6, DNS-to-address attribution, proxies,
UDP, and connection outcomes are not inferred from this hook.
