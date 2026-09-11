# EXP-001: attacker-controlled adapter role confusion

| Field | Value |
| --- | --- |
| EXP-ID | EXP-001 |
| Target fixture | `cmd/rpf-authz-target`, mode `intentionally-vulnerable` |
| Patched fixture | same binary, mode `patched` |
| Affected invariant | authorization derives from authenticated session role, not request adapter metadata |
| Vulnerability class | confused deputy / missing authorization boundary |
| Preconditions | disposable local target on `127.0.0.1:18081`; synthetic reader session |
| Proof objective | obtain only `RPF_SYNTHETIC_ADMIN_MARKER` by claiming adapter admin role |
| Expected telemetry | proof exec plus numeric TCP attempt attributed to its process |
| Expected policy | `REJECT` because destination is undeclared; no authorization-specific detector exists |
| Regression | `tools/test-adversarial.sh` and Go unit tests for vulnerable/patched modes |

## Target and minimum proof

The intentionally vulnerable branch replaces the synthetic session role with the request's
`adapter_role`. The proof is hard-coded to target identity `rpf-authz-fixture-v1`, reader session,
claimed admin adapter role, and numeric loopback. It contains no discovery, scanning, reusable
target selection, persistence, credentials, or post-exploitation behavior. Success is limited to
the service returning a fixed synthetic marker; the marker is not written into runtime evidence.

## Actual result

On 2026-09-11 in the Linux `6.18.33.2-microsoft-standard-WSL2` disposable lab, the vulnerable run returned
`granted=true reason=authorized`. The exact same proof against patched mode returned
`granted=false reason=authorization_denied`. These were independent monitored builds, not two
application calls hidden in one stream. Each produced a valid 17-event stream, seven process nodes,
15 graph edges, one attributed connection attempt to `127.0.0.1:18081`, an artifact, provenance,
and runtime trace. The independent loss state was zero or one correlation event; cause-specific
telemetry attributed the non-zero case to path read, and completeness reflected it.

The vulnerability exists and exploitability was dynamically demonstrated. Runtime telemetry
observed the proof process and network attempts. Current detection did **not** identify the
authorization violation: vulnerable grant and patched denial have the same available kernel
shape. Policy nevertheless returned `REJECT` because the destination was undeclared, not because
it understood authorization semantics. Therefore this experiment does not claim authorization
prevention.

## Fix and patch validation

Patched mode ignores `adapter_role` for authorization and uses only `session_role`. In a fresh
cgroup/build identity, the original proof no longer obtains the marker while the target still
accepts the request, returns a structured denial, and the surrounding benign artifact build still
completes. A unit test also confirms an incorrect target identity is denied in both modes.

Residual risk: the fixture models session role as an in-process trusted input rather than a real
cryptographically authenticated identity. Runtime-only observation cannot infer application
authorization outcomes without a trustworthy semantic signal. Adding self-reported app events
would require authentication and correlation design before policy could rely on them.
