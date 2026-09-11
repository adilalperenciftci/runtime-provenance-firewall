# Kernel support

## Current tested slice

The sensor has been exercised on Linux 6.8 WSL2 and, most recently on 2026-09-11, Linux
`6.18.33.2-microsoft-standard-WSL2` through a disposable privileged Docker container. Those runs
prove the checked-in exec/open/connect programs loaded, attached, filtered on the test cgroup ID,
delivered records, and exposed implemented loss state in those environments. They are not a
broader compatibility result.

The current implementation requires:

- 64-bit little-endian Linux; the userspace wire decoder currently assumes little endian;
- cgroup v2 and a userspace cgroup ID corresponding to `bpf_get_current_cgroup_id()`;
- kernel BTF at `/sys/kernel/btf/vmlinux` for CO-RE compilation/relocation;
- tracefs and the `sched:sched_process_exec` tracepoint;
- `syscalls:sys_enter_openat` and `syscalls:sys_exit_openat` tracepoints;
- cgroup v2 program attachment with `BPF_CGROUP_INET4_CONNECT` support;
- BPF ring-buffer support (Linux 5.8 or newer);
- permissions to load BPF maps/programs and attach the tracepoint.

The reproducible support floor is intentionally recorded as “tested on Linux 6.8,” not merely
the oldest kernel exposing each helper. CI must add actual kernel-matrix results before the
project advertises additional versions or architectures.

## Semantics and limitations

The cgroup ID is a scope selector, not a stable global build identity. Cgroup reuse, migration,
delegation, nested cgroups, or namespace presentation can invalidate naive attribution. The
future registrar must bind cgroup ID to boot ID, cgroup path digest, build nonce, and monitoring
interval as required by ADR 0005.

Filtering currently uses exact cgroup ID equality. Descendant cgroups are not automatically in
scope. The privileged smoke test keeps the collector outside a disposable target cgroup and
verifies one parent-cgroup control exec is excluded, but it does not establish namespace-wide
noninterference.

`sched_process_exec` reports successful exec transitions. The current record includes kernel
start time plus active PID and mount namespace inode numbers; these are attribution inputs, not
proof of semantic causation. It does not report failed attempts, interpreted script content,
file reads, network activity, or artifact causality. The filename is bounded to 255 bytes plus
NUL and may be truncated by the kernel helper; policy treats it explicitly as `path_only`, not
cryptographic executable identity.

Ring-buffer reservation failures are measured in a per-CPU counter and emitted on orderly
sensor shutdown. Abrupt collector loss currently produces no signed finalization and therefore
must be incomplete, never `ALLOW`. Host root can disable or forge this telemetry and remains
outside the defended trust boundary.

Write-open telemetry pairs `openat` entry and exit in a bounded hash map. Map insertion failure,
path read/truncation, or cgroup migration during the syscall increments `kernel_correlation`.
Finalization also reports those causes separately as `kernel_map_update`, `kernel_path_read`, and
`kernel_cgroup_mismatch`; their sum is expected to equal the aggregate in current code.
Only successful write-intent opens are emitted. Paths are copied user arguments, not resolved
kernel dentries: symlinks, relative paths, directory FDs, rename publication, `openat2`, inherited
descriptors, and mmap writes are not yet resolved. Artifact attribution therefore means
“observed successful write-open plus final userspace hash,” not proof of written bytes.

One optional sensitive path is rewritten into BPF read-only configuration. Successful exact-path
read opens become a category-only userspace event; the raw path and file value are not persisted.
This intentionally narrow filter has the same unresolved path-alias and alternate-I/O blind spots.

IPv4 connect telemetry attaches to the exact registered cgroup directory and records numeric
address, port, protocol, and process identity before the transport result. It is an attempted
connection observation, not proof that a peer accepted data. IPv6 and DNS attribution are not
implemented. The BPF return value always allows; policy enforcement occurs during verification.
