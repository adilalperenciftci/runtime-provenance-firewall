# Security invariants

1. Input is strict UTF-8 JSON with unique keys, finite numbers, known versions, known structural fields, and resource limits.
2. A tool action must not be described as prevented unless evaluation occurred before action and the adapter enforced the decision.
3. Matched secret values and secret-derived fingerprints never appear in decisions or persisted event records.
4. Destination authorization compares normalized scheme, exact host, and effective port. Substring and suffix implication are forbidden.
5. Missing evidence never increases trust or lowers a decision.
6. Decision ordering and finding ordering are deterministic for identical event and policy bytes.
7. A ledger is verified before extension and each entry commits to its predecessor. The ledger has exactly one writer.
8. Hash-chain validity is not described as producer authenticity, completeness, rollback protection, or non-repudiation.
9. Rules cannot execute code loaded from the rule directory.
10. Fixtures use synthetic identities, secrets, and reserved domains; tests perform no external requests.
