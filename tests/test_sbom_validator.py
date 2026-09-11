from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import ModuleType


def load_validator() -> ModuleType:
    path = Path(__file__).parents[1] / "tools" / "validate_sbom.py"
    spec = importlib.util.spec_from_file_location("validate_sbom", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load SBOM validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SBOMValidatorTests(unittest.TestCase):
    def test_accepts_required_formats(self) -> None:
        validator = load_validator()
        validator.validate_spdx(
            {"spdxVersion": "SPDX-2.3", "documentNamespace": "urn:test", "packages": []}
        )
        validator.validate_cyclonedx(
            {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}
        )

    def test_rejects_wrong_versions(self) -> None:
        validator = load_validator()
        with self.assertRaises(ValueError):
            validator.validate_spdx(
                {"spdxVersion": "SPDX-2.2", "documentNamespace": "urn:test", "packages": []}
            )
        with self.assertRaises(ValueError):
            validator.validate_cyclonedx(
                {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
            )


if __name__ == "__main__":
    unittest.main()
