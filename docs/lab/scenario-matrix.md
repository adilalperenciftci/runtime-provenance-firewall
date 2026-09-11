# Controlled laboratory scenario matrix

This matrix is the durable index for the local adversarial laboratory. Every row names the
evidence expected from the event stream and graph, the finding and policy result, and the verifier
outcome. “Executed” means the current checked-in script asserts the result; “fixture only” means
the case is represented by a negative test but is not a separate build workload. No row targets
anything outside the repository-owned disposable container.

| ID | Controlled case | Evidence and graph expectation | Finding / policy | Verifier result | Status |
| --- | --- | --- | --- | --- | --- |
| LAB-01 | deterministic benign artifact build | build-fixture exec, artifact output and local callback attributed to one cgroup graph | no findings; `ALLOW` | complete binding and signatures accepted | Executed by `test-sensor.sh` |
| LAB-02 | synthetic credential read by shell chain | sensitive-open events, shell ancestry, renamed interpreter and proof child in graph; no secret bytes | `RPF-SENSITIVE-001`; `REJECT` | complete or fail-closed incomplete evidence, never `ALLOW` | Executed by `test-adversarial.sh` |
| LAB-03 | undeclared localhost egress | numeric TCP attempt from the responsible proof process and ancestry | `RPF-EGRESS-001`; `REJECT` | artifact/evidence/provenance binding checked | Executed by `test-adversarial.sh` |
| LAB-04 | undeclared child / interpreter chain | `process_exec` nodes for shell, renamed shell, target and proof; absent ancestry is explicit | `RPF-PROCESS-001` may be `REVIEW`; combined policy is `REJECT` | graph and policy verification complete | Executed by `test-adversarial.sh` |
| LAB-05 | artifact substitution | graph/evidence remain unchanged but consumed artifact digest differs | `RPF-ARTIFACT-001`; `REJECT` | signed fixture verification fails closed | Executed by `test-sensor.sh` and `test-evidence-integrity.sh` |
| LAB-06 | wrong artifact in provenance | subject digest disagrees with local artifact/evidence | correlation failure; `REJECT` | provenance negative fixture rejected | Executed by `test-attestation-negative.sh` |
| LAB-07 | runtime-trace replay from another build | build/run/source identity and commitments differ across streams | `RPF-IDENTITY-001` / integrity finding; `REJECT` | replay cannot be accepted | Executed by `test-runtime-replay.sh` |
| LAB-08 | missing runtime records | loss or truncated evidence changes completeness; no fabricated graph edges | `RPF-EVIDENCE-001`; strict mode `REJECT` | completeness is `unknown` or `incomplete`, never `ALLOW` | Executed by integrity negative tests |
| LAB-09 | malformed attestation | parser emits no trusted graph or binding from malformed input | malformed-input finding; `REJECT` | malformed provenance/trace/signature rejected | Executed by `test-attestation-negative.sh` and `test-signing.sh` |
| LAB-10 | forged or invalid signature | payload or signer key does not match the signed bundle | signature/integrity finding; `REJECT` | Cosign offline verification fails | Executed by `test-signing.sh` |
| LAB-11 | expected network access | allowed local callback event is retained and attributed | no egress finding for declared endpoint; baseline `ALLOW` | binding verifies | Executed by `test-sensor.sh` |
| LAB-12 | credential-independent package-install baseline | fixed package fixture reads only the repository-owned synthetic lockfile, receives no credential and makes no network attempt; graph has no sensitive edge | no sensitive finding; baseline `ALLOW` | complete zero-loss fixture accepted | Executed by the benign path in `test-sensor.sh` |

The matrix deliberately does not label the authorization result itself as kernel-detected. The
vulnerable and patched targets are both observed in the cgroup, while the target's grant/deny
semantic is supplied by its explicit local proof result. The current policy rejection is based on
observable sensitive access and undeclared egress; the authorization-boundary detector gap is
recorded in `EXP-001-adapter-role-confusion.md`.

The package fixture is a deterministic lab surrogate, not a real package manager and does not
claim package ecosystem coverage. A realistic dependency workload and representative performance
corpus remain follow-up research, as recorded in `benchmarks.md` and `limitations.md`.
