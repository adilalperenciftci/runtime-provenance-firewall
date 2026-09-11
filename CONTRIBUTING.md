# Contributing

Before changing the verifier or telemetry pipeline, review `docs/architecture.md`,
`docs/threat-model.md`, and `docs/security-invariants.md`. Keep the trusted runtime path small and
deterministic. Update the threat model when a trust boundary changes, and record
security-significant design changes under `docs/decisions/`.

Treat event fields, tool definitions, results, and rule files as attacker-controlled until strict
validation succeeds. Matched secret values must never be persisted. A finding is detection, not
prevention, unless an inline adapter enforces the decision before the action.

Detection changes require stable metadata under `rules/`, positive and negative fixtures,
malformed and edge cases, expected output, and documented limitations. Fixtures must be synthetic
and must not call external systems. Do not add mappings unsupported by observable evidence.

Before submitting a change, run the commands under README's reproduction section. Keep commits
coherent; architecture, event contracts, evaluator changes, fixtures, and CI hardening should
remain reviewable.
