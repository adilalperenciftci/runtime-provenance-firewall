from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .validation import ValidationError, pairs_no_duplicates, reject_constant


@dataclass(frozen=True, slots=True)
class Policy:
    allowed_hosts: frozenset[str]
    allowed_schemes: frozenset[str]
    allowed_ports: frozenset[int]


def load_policy(path: Path) -> Policy:
    try:
        data: Any = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs_no_duplicates,
            parse_constant=reject_constant,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError("policy cannot be read as JSON") from exc
    if not isinstance(data, dict):
        raise ValidationError("policy must contain only egress")
    data = cast(dict[str, Any], data)
    if set(data) != {"egress"}:
        raise ValidationError("policy must contain only egress")
    raw_egress = data["egress"]
    if not isinstance(raw_egress, dict):
        raise ValidationError("egress policy fields are invalid")
    egress = cast(dict[str, Any], raw_egress)
    if set(egress) != {
        "allowed_hosts",
        "allowed_schemes",
        "allowed_ports",
    }:
        raise ValidationError("egress policy fields are invalid")
    raw_hosts = egress["allowed_hosts"]
    raw_schemes = egress["allowed_schemes"]
    raw_ports = egress["allowed_ports"]
    if not isinstance(raw_hosts, list) or not all(
        isinstance(x, str) for x in cast(list[Any], raw_hosts)
    ):
        raise ValidationError("allowed_hosts must be a string list")
    if not isinstance(raw_schemes, list) or not all(
        x in {"http", "https"} for x in cast(list[Any], raw_schemes)
    ):
        raise ValidationError("allowed_schemes must contain HTTP schemes")
    if not isinstance(raw_ports, list) or not all(
        isinstance(x, int) and not isinstance(x, bool) and 1 <= x <= 65535
        for x in cast(list[Any], raw_ports)
    ):
        raise ValidationError("allowed_ports must contain valid ports")
    hosts = cast(list[str], raw_hosts)
    schemes = cast(list[str], raw_schemes)
    ports = cast(list[int], raw_ports)
    return Policy(
        allowed_hosts=frozenset(x.lower().rstrip(".") for x in hosts),
        allowed_schemes=frozenset(schemes),
        allowed_ports=frozenset(ports),
    )
