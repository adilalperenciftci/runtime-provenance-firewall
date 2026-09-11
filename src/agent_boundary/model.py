from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

Decision = Literal["allow", "review", "deny"]
Trust = Literal["trusted", "untrusted", "mixed", "unknown"]


@dataclass(frozen=True, slots=True)
class Destination:
    scheme: str
    host: str
    port: int | None


@dataclass(frozen=True, slots=True)
class ToolCallEvent:
    schema_version: str
    event_id: str
    occurred_at: datetime
    producer_id: str
    session_id: str
    source_trust: Trust
    tool_name: str
    arguments: dict[str, Any]
    destination: Destination | None


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    effect: Literal["review", "deny"]
    evidence: tuple[dict[str, Any], ...]
    remediation: str
