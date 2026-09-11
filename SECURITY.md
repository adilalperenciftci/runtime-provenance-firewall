# Security policy

## Supported versions

The project is pre-1.0. Security fixes are applied to the current `main` branch; no stable release line exists yet.

## Reporting

Do not open a public issue for a vulnerability that could expose real credentials or bypass an inline decision. Use the repository host's private vulnerability-reporting feature when enabled. If it is unavailable, contact the maintainer through a private channel listed in the repository profile.

Include affected revision, deployment assumptions, a minimal synthetic reproducer, impact, and suggested remediation. Do not include production secrets or target third-party systems.

## Scope

Parser ambiguity, redaction bypass, decision inconsistency, policy bypass, ledger-integrity errors, and unsafe defaults are in scope. A missed natural-language prompt injection is not by itself a vulnerability because the project does not claim semantic injection detection. Valid-prefix ledger rollback is a documented limitation until external checkpoints exist.
