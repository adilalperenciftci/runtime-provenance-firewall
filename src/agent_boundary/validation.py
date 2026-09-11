from __future__ import annotations

import ipaddress
import json
import math
import re
from datetime import datetime
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID

from .model import Destination, ToolCallEvent, Trust

MAX_EVENT_BYTES = 262_144
MAX_DEPTH = 16
MAX_ITEMS = 2_000
MAX_STRING = 32_768
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
_TRUST = {"trusted", "untrusted", "mixed", "unknown"}


class ValidationError(ValueError):
    pass


def pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValidationError(f"non-finite JSON number: {value}")


def _bounded(value: Any, *, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    if depth > MAX_DEPTH:
        raise ValidationError("event exceeds maximum nesting depth")
    count[0] += 1
    if count[0] > MAX_ITEMS:
        raise ValidationError("event exceeds maximum item count")
    if isinstance(value, str) and len(value) > MAX_STRING:
        raise ValidationError("event contains an oversized string")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationError("event contains a non-finite number")
    if isinstance(value, dict):
        mapping = cast(dict[object, object], value)
        for key, child in mapping.items():
            if not isinstance(key, str):
                raise ValidationError("object keys must be strings")
            _bounded(child, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for child in cast(list[object], value):
            _bounded(child, depth=depth + 1, count=count)


def _required_object(parent: dict[str, Any], name: str) -> dict[str, Any]:
    value = parent.get(name)
    if not isinstance(value, dict):
        raise ValidationError(f"{name} must be an object")
    return cast(dict[str, Any], value)


def _exact_fields(value: dict[str, Any], name: str, fields: set[str]) -> None:
    if set(value) != fields:
        raise ValidationError(f"{name} fields are invalid")


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValidationError(f"{field} is not a valid identifier")
    return value


def _destination(value: Any) -> Destination | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 2_048:
        raise ValidationError("destination must be a URI string")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValidationError("destination is malformed") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValidationError("destination must be an absolute HTTP(S) URI")
    if parsed.username is not None or parsed.password is not None:
        raise ValidationError("destination userinfo is forbidden")
    host = parsed.hostname.rstrip(".").lower()
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValidationError("destination host is invalid") from exc
    return Destination(scheme=parsed.scheme.lower(), host=host, port=port)


def parse_event(raw: bytes) -> ToolCallEvent:
    if len(raw) > MAX_EVENT_BYTES:
        raise ValidationError("event exceeds maximum byte size")
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs_no_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("event is not strict UTF-8 JSON") from exc
    if not isinstance(data, dict):
        raise ValidationError("event root must be an object")
    data = cast(dict[str, Any], data)
    _bounded(data)
    allowed = {
        "schema_version",
        "event_id",
        "event_type",
        "occurred_at",
        "producer",
        "session",
        "source",
        "tool",
        "arguments",
        "destination",
    }
    unknown = set(data) - allowed
    if unknown:
        raise ValidationError(f"unknown top-level fields: {', '.join(sorted(unknown))}")
    if data.get("schema_version") != "1.0":
        raise ValidationError("unsupported schema_version")
    if data.get("event_type") != "tool_call.requested":
        raise ValidationError("unsupported event_type")
    event_id = _identifier(data.get("event_id"), "event_id")
    try:
        UUID(event_id)
    except ValueError as exc:
        raise ValidationError("event_id must be a UUID") from exc
    timestamp = data.get("occurred_at")
    if not isinstance(timestamp, str):
        raise ValidationError("occurred_at must be a string")
    try:
        occurred_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("occurred_at must be RFC 3339 compatible") from exc
    if occurred_at.tzinfo is None:
        raise ValidationError("occurred_at must include a timezone")
    producer = _required_object(data, "producer")
    session = _required_object(data, "session")
    source = _required_object(data, "source")
    tool = _required_object(data, "tool")
    _exact_fields(producer, "producer", {"id"})
    _exact_fields(session, "session", {"id"})
    _exact_fields(source, "source", {"trust"})
    _exact_fields(tool, "tool", {"name"})
    trust = source.get("trust")
    if trust not in _TRUST:
        raise ValidationError("source.trust is invalid")
    arguments = data.get("arguments")
    if not isinstance(arguments, dict):
        raise ValidationError("arguments must be an object")
    arguments = cast(dict[str, Any], arguments)
    return ToolCallEvent(
        schema_version="1.0",
        event_id=event_id,
        occurred_at=occurred_at,
        producer_id=_identifier(producer.get("id"), "producer.id"),
        session_id=_identifier(session.get("id"), "session.id"),
        source_trust=cast(Trust, trust),
        tool_name=_identifier(tool.get("name"), "tool.name"),
        arguments=arguments,
        destination=_destination(data.get("destination")),
    )
