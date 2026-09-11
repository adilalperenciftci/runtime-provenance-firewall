from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .canonical import sha256_hex
from .model import Decision, Finding, ToolCallEvent
from .policy import Policy
from .secrets import find_secrets, redact


@dataclass(frozen=True, slots=True)
class Evaluation:
    decision: Decision
    event_digest: str
    findings: tuple[Finding, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "event_digest": self.event_digest,
            "findings": [asdict(finding) for finding in self.findings],
        }


def event_record(event: ToolCallEvent) -> dict[str, Any]:
    destination = asdict(event.destination) if event.destination else None
    return {
        "schema_version": event.schema_version,
        "event_id": event.event_id,
        "event_type": "tool_call.requested",
        "occurred_at": event.occurred_at.isoformat(),
        "producer": {"id": event.producer_id},
        "session": {"id": event.session_id},
        "source": {"trust": event.source_trust},
        "tool": {"name": event.tool_name},
        "arguments": redact(event.arguments),
        "destination": destination,
    }


def _destination_allowed(event: ToolCallEvent, policy: Policy) -> bool:
    destination = event.destination
    if destination is None:
        return True
    effective_port = destination.port or (443 if destination.scheme == "https" else 80)
    return (
        destination.host in policy.allowed_hosts
        and destination.scheme in policy.allowed_schemes
        and effective_port in policy.allowed_ports
    )


def evaluate(event: ToolCallEvent, policy: Policy) -> Evaluation:
    findings: list[Finding] = []
    secrets = find_secrets(event.arguments)
    destination_allowed = _destination_allowed(event, policy)
    if event.destination is not None and not destination_allowed:
        findings.append(
            Finding(
                rule_id="AB-EGRESS-001",
                title="Tool call targets an unapproved destination",
                severity="high",
                confidence="high",
                effect="review",
                evidence=(
                    {
                        "scheme": event.destination.scheme,
                        "host": event.destination.host,
                        "port": event.destination.port,
                    },
                ),
                remediation="Use an approved destination or update policy through review.",
            )
        )
    if secrets:
        effect = "deny" if event.destination is not None and not destination_allowed else "review"
        findings.append(
            Finding(
                rule_id="AB-SECRET-001",
                title="Secret-like value present in tool arguments",
                severity="critical" if effect == "deny" else "high",
                confidence="high",
                effect=effect,
                evidence=tuple(
                    {
                        "path": match.path,
                        "detector": match.detector,
                    }
                    for match in secrets
                ),
                remediation=(
                    "Remove the credential from arguments and use a scoped credential broker."
                ),
            )
        )
    if any(f.effect == "deny" for f in findings):
        decision: Decision = "deny"
    elif findings:
        decision = "review"
    else:
        decision = "allow"
    return Evaluation(
        decision=decision,
        event_digest=sha256_hex(event_record(event)),
        findings=tuple(sorted(findings, key=lambda item: item.rule_id)),
    )
