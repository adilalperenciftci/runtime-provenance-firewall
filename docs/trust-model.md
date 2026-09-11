# Trust model

## Principals

| Principal | Authority | Evidence accepted in strict mode |
| --- | --- | --- |
| Source control | Repository/revision and protected workflow state | Authenticated source provenance or pinned revision |
| CI control plane | Workflow, run, attempt, and runner identity | OIDC/signed claims constrained by policy |
| Builder | Executes build and emits SLSA provenance | Provenance signed by authorized builder identity |
| Kernel sensor | Observes selected events for one cgroup | Version/config, lifecycle, boot/build scope, and loss counters |
| Collector | Normalizes and persists evidence | Manifest covered by an authorized attestation |
| Policy administrator | Defines expected behavior/identities | Content-addressed policy from trusted channel |
| Verifier | Recomputes links and emits decision | Local binary/configuration is consumer trust base |

Producer labels are assertions unless authenticated by one of these channels.

## Trust domains

The build cgroup is adversarial. It must not modify sensor configuration, event maps, evidence
output, or signing material. The host monitor is more trusted than the build but not more
trusted than root. Signing should occur after collection in a separate job or service with
read-only evidence input and no ability to mutate artifact bytes.

## Evidence strength

Fields carry an origin classification:

- `kernel_observed`: obtained from an attached kernel hook;
- `platform_authenticated`: derived from verified CI/OIDC claims;
- `content_verified`: recomputed from supplied bytes;
- `producer_asserted`: supplied without independent authentication;
- `policy_expected`: required by local policy.

The verifier never upgrades an asserted value. Equality between asserted values does not
authenticate either value.

## Decision states

- `ALLOW`: all mandatory cryptographic, identity, completeness, and behavior checks pass.
- `REVIEW`: evidence is inspectable, but policy identifies non-fatal behavior or permits human
  handling of incomplete evidence.
- `REJECT`: mismatch, malformed input, forbidden behavior, invalid signature, or strict failure.
- `INCOMPLETE`: machine-readable verification state mapped to `REVIEW` or `REJECT`, never `ALLOW`.

## Deployment assurance

These are project terms, not SLSA levels:

1. `fixture`: synthetic events; validates parser/correlation only.
2. `local-observed`: sensor on an owned Linux host; no hostile-host resistance.
3. `isolated-runner`: sensor outside an ephemeral build cgroup/VM, signer separated from build.
4. `remotely-attested`: reserved for future measured-platform integration; no current claim.

An attestation records an asserted level; policy decides whether its signer/platform may make
that assertion.
