# Detection model

Rules are stable security contracts. Metadata under `rules/` documents requirements, rationale, fixtures, severity, confidence, and mappings. Evaluator code lives in the reviewed package; rule files are non-executable.

## Decision semantics

- `allow`: no configured evaluator produced a finding.
- `review`: at least one finding requires a human or adapter-specific gate.
- `deny`: policy requires the adapter not to execute the call.

Precedence is deny, review, allow. Identical normalized inputs and policy produce identical findings ordered by rule ID.

`AB-EGRESS-001` identifies an exact destination outside policy. It does not infer exfiltration and therefore has no ATT&CK mapping by itself.

`AB-SECRET-001` identifies a supported secret format in arguments. If the same call targets an unapproved destination, the effect is deny and mapping to T1567 is defensible only in downstream telemetry showing the data-transfer attempt. The repository records OWASP mappings for design context and keeps ATT&CK mappings conditional.

## Known limitations

Regex indicators are neither secret validation nor complete DLP. Encoded, split, novel, and low-entropy credentials can evade detection. Documentation examples can cause matches. Destination policy cannot see DNS rebinding, redirect targets, proxy behavior, or traffic generated inside the tool implementation.
