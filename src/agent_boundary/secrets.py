from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, cast


@dataclass(frozen=True, slots=True)
class SecretMatch:
    path: str
    detector: str


_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(?:gh[oprsu]_[A-Za-z0-9]{36,255})\b")),
    ("openai-project-key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,255}\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
)


def _walk(value: Any, path: str = "$.arguments") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        mapping = cast(dict[str, Any], value)
        for key in sorted(mapping):
            yield from _walk(mapping[key], f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(cast(list[Any], value)):
            yield from _walk(child, f"{path}[{index}]")


def find_secrets(arguments: dict[str, Any]) -> tuple[SecretMatch, ...]:
    matches: list[SecretMatch] = []
    for path, value in _walk(arguments):
        for detector, pattern in _PATTERNS:
            if pattern.search(value):
                matches.append(SecretMatch(path, detector))
    return tuple(matches)


def redact(value: Any) -> Any:
    if isinstance(value, str):
        result = value
        for detector, pattern in _PATTERNS:
            result = pattern.sub(f"[REDACTED:{detector}]", result)
        return result
    if isinstance(value, dict):
        mapping = cast(dict[str, Any], value)
        return {key: redact(child) for key, child in mapping.items()}
    if isinstance(value, list):
        return [redact(child) for child in cast(list[Any], value)]
    return value
