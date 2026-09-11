# ADR 0001: Build a provenance-aware decision engine

Status: accepted

## Context

MCP proxies can enforce transport policy, manifest linters can inspect definitions, and telemetry collectors can retain calls. None alone relates attacker influence, authority, sink behavior, catalog state, and approval evidence at the action boundary. Text classifiers have unavoidable semantic blind spots and should not be the sole prevention control.

## Decision

Build a deterministic engine that accepts adapter-supplied events, validates evidence, evaluates source-to-sink and integrity policy, and emits enforceable decisions plus minimized forensic records. Adapters remain responsible for transport, authentication, and enforcing decisions.

## Consequences

The core is portable and testable without an LLM or network. Its confidence is bounded by provenance quality. Integrations must do more work than sending ordinary application logs, and the core cannot guarantee prevention in observe-only mode.
