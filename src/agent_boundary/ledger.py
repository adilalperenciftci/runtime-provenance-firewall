from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

from .canonical import canonical_bytes, sha256_hex
from .validation import ValidationError, pairs_no_duplicates, reject_constant

GENESIS = "0" * 64


def _last(path: Path) -> tuple[int, str]:
    if not path.exists() or path.stat().st_size == 0:
        return 0, GENESIS
    sequence = 0
    current = GENESIS
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            entry = json.loads(line)
            sequence = entry["sequence"]
            current = entry["record_hash"]
    return sequence, current


def append(path: Path, record: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Verification before extension prevents a damaged local chain from becoming
    # the accepted parent. The initial ledger contract requires one writer.
    if path.exists() and path.stat().st_size:
        verify(path)
    sequence, previous = _last(path)
    body = {"sequence": sequence + 1, "previous_hash": previous, "record": record}
    entry = {**body, "record_hash": sha256_hex(body)}
    with path.open("ab", buffering=0) as handle:
        handle.write(canonical_bytes(entry) + b"\n")
        os.fsync(handle.fileno())
    return entry


def verify(path: Path) -> int:
    previous = GENESIS
    expected_sequence = 1
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                entry = json.loads(
                    line,
                    object_pairs_hook=pairs_no_duplicates,
                    parse_constant=reject_constant,
                )
                if not isinstance(entry, dict):
                    raise ValidationError(f"ledger line {line_number} has invalid fields")
                entry = cast(dict[str, Any], entry)
                if set(entry) != {
                    "sequence",
                    "previous_hash",
                    "record",
                    "record_hash",
                }:
                    raise ValidationError(f"ledger line {line_number} has invalid fields")
                body = {
                    "sequence": entry["sequence"],
                    "previous_hash": entry["previous_hash"],
                    "record": entry["record"],
                }
                if entry["sequence"] != expected_sequence:
                    raise ValidationError(f"ledger sequence breaks at line {line_number}")
                if entry["previous_hash"] != previous:
                    raise ValidationError(f"ledger chain breaks at line {line_number}")
                if entry["record_hash"] != sha256_hex(body):
                    raise ValidationError(f"ledger hash mismatch at line {line_number}")
                previous = entry["record_hash"]
                expected_sequence += 1
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError("ledger cannot be verified") from exc
    return expected_sequence - 1
