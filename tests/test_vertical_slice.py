from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent_boundary.engine import evaluate, event_record
from agent_boundary.ledger import append, verify
from agent_boundary.policy import load_policy
from agent_boundary.validation import ValidationError, parse_event

ROOT = Path(__file__).parents[1]
POLICY = load_policy(ROOT / "policy" / "example.json")


class VerticalSliceTests(unittest.TestCase):
    def event(self, name: str) -> bytes:
        return (ROOT / "fixtures" / name).read_bytes()

    def test_benign_baseline_is_allowed(self) -> None:
        result = evaluate(parse_event(self.event("benign/approved-call.json")), POLICY)
        self.assertEqual(result.decision, "allow")
        self.assertEqual(result.findings, ())

    def test_secret_to_unapproved_egress_is_denied(self) -> None:
        event = parse_event(self.event("suspicious/secret-egress.json"))
        result = evaluate(event, POLICY)
        self.assertEqual(result.decision, "deny")
        self.assertEqual(
            [finding.rule_id for finding in result.findings],
            ["AB-EGRESS-001", "AB-SECRET-001"],
        )
        rendered = json.dumps(result.as_dict())
        self.assertNotIn("sk-proj-", rendered)
        self.assertNotIn("fingerprint", rendered)

    def test_persisted_event_is_redacted(self) -> None:
        event = parse_event(self.event("suspicious/secret-egress.json"))
        record = event_record(event)
        self.assertIn("[REDACTED:openai-project-key]", record["arguments"]["body"])
        self.assertNotIn("sk-proj-", json.dumps(record))

    def test_duplicate_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "duplicate JSON key"):
            parse_event(b'{"schema_version":"1.0","schema_version":"1.0"}')

    def test_unknown_nested_fields_are_rejected(self) -> None:
        data = json.loads(self.event("benign/approved-call.json"))
        data["producer"]["verified"] = True
        with self.assertRaisesRegex(ValidationError, "producer fields"):
            parse_event(json.dumps(data).encode())

    def test_deep_input_is_rejected(self) -> None:
        raw = self.event("benign/approved-call.json")
        data = json.loads(raw)
        nested: dict[str, object] = {}
        cursor = nested
        for _ in range(20):
            child: dict[str, object] = {}
            cursor["x"] = child
            cursor = child
        data["arguments"] = nested
        with self.assertRaisesRegex(ValidationError, "nesting depth"):
            parse_event(json.dumps(data).encode())

    def test_lookalike_host_is_not_allowed(self) -> None:
        data = json.loads(self.event("benign/approved-call.json"))
        data["destination"] = "https://api.internal.test.attacker.test/"
        result = evaluate(parse_event(json.dumps(data).encode()), POLICY)
        self.assertEqual(result.decision, "review")

    def test_ledger_detects_modification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            append(path, {"kind": "event", "value": 1})
            append(path, {"kind": "decision", "value": 2})
            self.assertEqual(verify(path), 2)
            content = path.read_text(encoding="utf-8").replace('"value":1', '"value":9')
            path.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "hash mismatch"):
                verify(path)
            with self.assertRaisesRegex(ValidationError, "hash mismatch"):
                append(path, {"kind": "event", "value": 3})


if __name__ == "__main__":
    unittest.main()
