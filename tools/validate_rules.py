from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
REQUIRED = {
    "id",
    "title",
    "description",
    "rationale",
    "event_types",
    "required_fields",
    "severity",
    "confidence",
    "effect",
    "mappings",
    "positive_fixtures",
    "negative_fixtures",
    "expected_rule_ids",
}


def main() -> int:
    failures: list[str] = []
    identifiers: set[str] = set()
    for path in sorted((ROOT / "rules").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if set(data) != REQUIRED:
            failures.append(f"{path.name}: invalid fields")
            continue
        if data["id"] in identifiers or path.stem != data["id"]:
            failures.append(f"{path.name}: ID is duplicate or differs from filename")
        identifiers.add(data["id"])
        for fixture in data["positive_fixtures"] + data["negative_fixtures"]:
            if not (ROOT / fixture).is_file():
                failures.append(f"{path.name}: missing fixture {fixture}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(json.dumps({"valid": True, "rules": sorted(identifiers)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
