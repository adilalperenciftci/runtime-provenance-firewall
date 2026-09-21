# Runtime event and evidence schema

## Design goals

The event model is versioned, bounded, deterministic, and security-minimal. It records facts
needed for build attribution and policy while excluding argv by default, environment values,
file contents, credential values, packet payloads, and arbitrary syscall arguments.

Version `0.2` is a research schema. It adds mandatory source registration identity to `0.1`;
legacy `0.1` events fail explicitly rather than being interpreted under new semantics. Unknown
fields and versions fail strict parsing. Protobuf
is deferred until the fixed kernel/user ABI has been exercised on supported Linux kernels.

## Canonical event

The first vertical slice uses strict UTF-8 JSON Lines. Each line is canonicalized with sorted
keys, no insignificant whitespace, no duplicate keys, finite numbers only, and a final newline.

```json
{
  "schema_version": "0.2",
  "event_id": "urn:rpf:event:...",
  "sequence": 1,
  "observed_at": "2026-09-11T12:00:00.123456Z",
  "monotonic_ns": 9123456789,
  "build": {
    "build_id": "bld_7d44f4a5bfc24bfa",
    "run_id": "local-lab-0001",
    "source": {
      "repository": "https://example.test/runtime-provenance-firewall",
      "revision": "1111111111111111111111111111111111111111"
    },
    "boot_id": "4f25a5e2-3a0d-4bb0-99dd-a4e4b6c2a100",
    "cgroup_id": 99122,
    "cgroup_path_hash": "sha256:..."
  },
  "process": {
    "process_key": "sha256:...",
    "parent_key": "sha256:...",
    "pid": 4120,
    "tgid": 4120,
    "ppid": 4100,
    "start_time_ns": 9012345000,
    "pid_namespace": 4026533001,
    "mount_namespace": 4026533002,
    "uid": 1000,
    "gid": 1000,
    "executable": {
      "path": "/usr/bin/cc",
      "identity": "sha256:...",
      "identity_kind": "content_sha256"
    }
  },
  "operation": "process_exec",
  "resource": null,
  "outcome": {"status": "success", "errno": 0},
  "sensor": {"name": "rpf-sensor", "version": "0.2.0", "config_digest": "sha256:..."},
  "integrity": {"previous_event_hash": "sha256:...", "event_hash": "sha256:..."}
}
```

`process_key` derives from boot ID, PID namespace, TGID, and kernel process start time. PID
alone is insufficient. `parent_key` exists only when parent identity was observed. Executable
content identity is optional until measured without misleading TOCTOU claims; `path_only` is
an explicit weaker `identity_kind`.

The current collector derives `event_id` deterministically from build ID, run ID, and sequence;
its uniqueness therefore depends on the registrar never reusing a build execution identity.
`observed_at` is userspace collection time, while `monotonic_ns` comes from kernel boot time for
kernel events. Neither timestamp alone establishes event identity or causal ordering across hosts.
Repository and revision are registration assertions committed into every event and the sensor
configuration digest. They enable strict provenance equality but are not independently
authenticated source-control evidence in the local profile.

## Operations and resources

| Operation | Resource | Meaning |
| --- | --- | --- |
| `sensor_started` | lifecycle scope | Monitor attached before build release |
| `process_exec` | executable | Successful executable transition |
| `process_exit` | exit status | Observed process exit |
| `file_open_sensitive` | categorized path | Open of a policy-selected sensitive path |
| `file_open_output` | output path category/flags | Opened for write; not proof bytes were written |
| `file_rename_output` | old/new categorized paths | Rename into declared output root |
| `network_connect` | IP, port, protocol | Connection attempt and kernel result |
| `privilege_change` | capability/credential category | Supported transition without secret material |
| `artifact_finalized` | relative name and SHA-256 | Collector-computed final subject digest |
| `sensor_finalized` | lifecycle counters | End interval and loss totals |

Paths are retained only when policy permits. Sensitive paths default to categories such as
`github_token_file`, `ssh_private_key`, or `cloud_credentials`; raw paths can be omitted.
Network resources contain numeric addresses. Resolver-derived names are separate fields with
an explicit origin and never replace the numeric destination.

## Evidence manifest

```json
{
  "schema_version": "0.1",
  "build_id": "bld_7d44f4a5bfc24bfa",
  "run_identity": {"provider": "local", "run_id": "local-lab-0001", "attempt": 1},
  "source": {"repository": "https://example.test/repo", "revision": "<40-hex>"},
  "event_stream": {
    "sha256": "...",
    "first_sequence": 1,
    "last_sequence": 14,
    "event_count": 14
  },
  "loss": {
    "kernel_reserve": 0,
    "kernel_correlation": 0,
    "kernel_path_read": 0,
    "kernel_map_update": 0,
    "kernel_cgroup_mismatch": 0,
    "decode": 0,
    "queue": 0,
    "persistence": 0,
    "counter_read_error": false
  },
  "lifecycle": {"started": true, "finalized": true},
  "execution_graph_sha256": "...",
  "artifact": {"name": "dist/app", "sha256": "..."},
  "policy_sha256": "...",
  "sensor_config_sha256": "..."
}
```

Manifest canonical bytes are hashed and referenced from Runtime Trace. Loss fields are
mandatory even when zero. Missing fields mean `unknown`, never assumed zero.

`kernel_correlation` counts failures before a semantically complete kernel event can be emitted,
including bounded pending-map insertion and pathname capture failures. It is distinct from ring
buffer reservation loss. Any non-zero value makes strict evidence incomplete.

## Chain construction

For event `n`, `previous_event_hash` equals the canonical hash of event `n-1`; the first uses
64 zero hexadecimal digits. `event_hash` is SHA-256 over the event without `event_hash` but
including `previous_event_hash`. The manifest separately hashes exact canonical JSONL bytes.
Sequence, chain, and byte digest must all verify.

The collector creates a new mode-`0600` stream with exclusive-create and append flags and syncs
each event. Existing evidence is never resumed or overwritten. This reduces accidental overwrite
and crash ambiguity; it is not immutable storage and does not resist a filesystem administrator.

This detects modification, insertion, deletion inside a supplied complete segment, and
reordering. It does not prevent whole-bundle deletion, valid-prefix rollback, or forgery by
an authorized collector. Build ID, finalization, CI correlation, and signatures address
replay only within their stated trust assumptions.

## Resource limits

Initial limits are 256 KiB per event, 64 MiB per stream, depth 16, 2,000 values per event,
32 KiB strings, and 1,000,000 events per manifest. Implementations may lower limits but may not
silently raise them while claiming schema conformance.

## Compatibility

Additive optional fields require explicit parser support and a `0.x` update. Removing fields,
changing security meaning/canonicalization, or widening accepted values is breaking. Unknown
versions are never interpreted as the latest known version.
