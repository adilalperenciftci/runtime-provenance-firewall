from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .engine import evaluate, event_record
from .ledger import append, verify
from .policy import load_policy
from .validation import ValidationError, parse_event


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-boundary")
    commands = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = commands.add_parser("evaluate", help="evaluate one event")
    evaluate_parser.add_argument("--input", type=Path, required=True)
    evaluate_parser.add_argument("--policy", type=Path, required=True)
    evaluate_parser.add_argument("--ledger", type=Path, required=True)
    verify_parser = commands.add_parser("verify-ledger", help="verify a ledger chain")
    verify_parser.add_argument("--ledger", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify-ledger":
            count = verify(args.ledger)
            print(json.dumps({"valid": True, "records": count}, sort_keys=True))
            return 0
        event = parse_event(args.input.read_bytes())
        policy = load_policy(args.policy)
        evaluation = evaluate(event, policy)
        append(args.ledger, {"kind": "event", "event": event_record(event)})
        append(args.ledger, {"kind": "decision", **evaluation.as_dict()})
        print(json.dumps(evaluation.as_dict(), sort_keys=True))
        return {"allow": 0, "review": 2, "deny": 3}[evaluation.decision]
    except (OSError, ValidationError) as exc:
        print(json.dumps({"error": str(exc), "decision": "deny"}, sort_keys=True), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
