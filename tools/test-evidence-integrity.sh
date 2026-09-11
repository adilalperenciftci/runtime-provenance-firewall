#!/bin/sh
set -eu

validator=${1:-build/out/rpf}
events=${2:-build/out/sensor-test.jsonl}
artifact=${3:-build/out/sensor-test-artifact.txt}
provenance=${4:-build/out/sensor-test-provenance.json}
policy=${5:-lab/kernel/policy.json}
truncated=build/out/sensor-test-tail-truncated.jsonl
missing=build/out/sensor-test-interior-missing.jsonl
tampered=build/out/sensor-test-tampered.jsonl
bundle=build/out/sensor-test-incomplete-bundle
decision=build/out/sensor-test-incomplete-decision.json

test -x "$validator"
test -s "$events"
test -s "$artifact"
test -s "$provenance"

rm -f "$truncated" "$missing" "$tampered" "$decision"
rm -rf "$bundle"

# Tail truncation preserves every retained event hash. Lifecycle closure must still fail closed.
sed '$d' "$events" >"$truncated"
"$validator" validate-events --events "$truncated" >/dev/null
"$validator" assemble --artifact "$artifact" --events "$truncated" \
  --provenance "$provenance" --policy "$policy" --output "$bundle" >/dev/null
status=0
"$validator" verify-fixture --artifact "$artifact" --events "$truncated" \
  --provenance "$provenance" --policy "$policy" --bundle "$bundle" >"$decision" || status=$?
test "$status" -eq 3
grep -q '"decision":"REJECT"' "$decision"
grep -q '"completeness":"unknown"' "$decision"
grep -q '"code":"RPF-EVIDENCE-001"' "$decision"

# Removing an interior record leaves a sequence/hash discontinuity and must not parse.
sed '3d' "$events" >"$missing"
status=0
"$validator" validate-events --events "$missing" >/dev/null 2>&1 || status=$?
test "$status" -eq 4

# A byte-level modification without recomputing commitments must not parse.
sed 's#rpf-build-fixture#rpf-build-fixtur0#' "$events" >"$tampered"
status=0
"$validator" validate-events --events "$tampered" >/dev/null 2>&1 || status=$?
test "$status" -eq 4

cat "$decision"
