# ADR 0012: Preserve paired vulnerable and patched authorization fixtures

- Status: accepted
- Date: 2026-09-11

## Context

Static reasoning cannot prove exploitability or remediation. A reusable offensive client would
violate laboratory scope, while unit-only mocks would not exercise process, socket, kernel event,
graph, and policy boundaries.

## Decision

Provide one localhost-only, single-request service with explicit `intentionally-vulnerable` and
`patched` modes. The vulnerable mode trusts attacker-controlled adapter-role metadata; patched
mode uses the synthetic session role. A dedicated proof rejects non-loopback targets, validates a
fixed target identity, sends one deterministic request, and can only verify grant or denial of a
fixed synthetic marker.

Execute both modes inside the existing disposable adversarial run. Preserve the same proof input,
capture kernel process/connect evidence, and record application outcome separately from detector
and policy outcome.

## Consequences

Exploitability and patch effectiveness are reproducible without a generalized exploit framework.
The experiment demonstrates a detector blind spot: socket telemetry cannot distinguish an
authorization grant from denial. Undeclared-egress policy rejects both, so that result must not be
reported as authorization-aware prevention.
