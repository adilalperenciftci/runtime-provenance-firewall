from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level value must be an object")
    return value


def validate_spdx(document: dict[str, Any]) -> None:
    if document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("SPDX document must declare SPDX-2.3")
    if not isinstance(document.get("documentNamespace"), str):
        raise ValueError("SPDX document namespace is missing")
    if not isinstance(document.get("packages"), list):
        raise ValueError("SPDX packages must be an array")


def validate_cyclonedx(document: dict[str, Any]) -> None:
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("CycloneDX document has the wrong bomFormat")
    if document.get("specVersion") != "1.7":
        raise ValueError("CycloneDX document must declare specification 1.7")
    if not isinstance(document.get("components"), list):
        raise ValueError("CycloneDX components must be an array")


def main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        raise ValueError("usage: validate_sbom.py SPDX_JSON CYCLONEDX_JSON")
    validate_spdx(load_object(Path(arguments[0])))
    validate_cyclonedx(load_object(Path(arguments[1])))
    print(json.dumps({"cyclonedx": "valid", "spdx": "valid"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
