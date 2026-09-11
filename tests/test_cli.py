from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).parents[1]


class CliIntegrationTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        # The executable and fixed module are trusted; arguments are test-owned paths.
        return subprocess.run(  # noqa: S603
            [sys.executable, "-m", "agent_boundary.cli", *arguments],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_denied_event_is_recorded_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "events.jsonl"
            result = self.run_cli(
                "evaluate",
                "--input",
                "fixtures/suspicious/secret-egress.json",
                "--policy",
                "policy/example.json",
                "--ledger",
                str(ledger),
            )
            self.assertEqual(result.returncode, 3, result.stderr)
            output = cast(dict[str, Any], json.loads(result.stdout))
            self.assertEqual(output["decision"], "deny")
            self.assertNotIn("sk-proj-", ledger.read_text(encoding="utf-8"))

            verified = self.run_cli("verify-ledger", "--ledger", str(ledger))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(json.loads(verified.stdout), {"records": 2, "valid": True})

    def test_malformed_event_fails_closed_without_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event = root / "event.json"
            ledger = root / "events.jsonl"
            event.write_text('{"schema_version":"1.0"}', encoding="utf-8")
            result = self.run_cli(
                "evaluate",
                "--input",
                str(event),
                "--policy",
                "policy/example.json",
                "--ledger",
                str(ledger),
            )
            self.assertEqual(result.returncode, 4)
            self.assertEqual(json.loads(result.stderr)["decision"], "deny")
            self.assertFalse(ledger.exists())


if __name__ == "__main__":
    unittest.main()
