#!/bin/sh
set -eu

validator=build/out/rpf
first_artifact=/src/build/out/sensor-test-artifact.txt
first_events=build/out/sensor-test.jsonl
first_provenance=build/out/sensor-test-provenance.json
policy=lab/kernel/policy.json
second_events=build/out/sensor-replay.jsonl
second_graph=build/out/sensor-replay-graph.json
second_artifact=/src/build/out/sensor-replay-artifact.txt
second_provenance=build/out/sensor-replay-provenance.json
second_bundle=build/out/sensor-replay-bundle
decision=build/out/sensor-replay-decision.json
mismatch_bundle=build/out/sensor-replay-mismatch-bundle

rm -f "$second_events" "$second_graph" "$second_artifact" "$second_provenance" "$decision"
rm -rf "$second_bundle" "$mismatch_bundle"

RPF_TEST_BUILD_ID=rpf-independent-build \
RPF_TEST_RUN_ID=local-independent-run \
RPF_TEST_READY=build/out/sensor-replay-mock.ready \
RPF_TEST_PROVENANCE="$second_provenance" \
RPF_TEST_BUNDLE="$second_bundle" \
RPF_TEST_FULL_ACCEPTANCE=0 \
  ./tools/test-sensor.sh build/out/rpf-sensor.bpf.o build/out/rpf-sensor "$second_events" \
    "$validator" "$second_graph" "$second_artifact" >/dev/null

status=0
"$validator" verify-fixture --artifact "$first_artifact" --events "$first_events" \
  --provenance "$first_provenance" --policy "$policy" --bundle "$second_bundle" \
  >"$decision" || status=$?
test "$status" -eq 3
grep -q '"decision":"REJECT"' "$decision"
grep -q '"code":"RPF-IDENTITY-001"' "$decision"
grep -q '"code":"RPF-INTEGRITY-002"' "$decision"
grep -q '"code":"RPF-INTEGRITY-003"' "$decision"

status=0
"$validator" assemble --artifact "$first_artifact" --events "$first_events" \
  --provenance "$second_provenance" --policy "$policy" --output "$mismatch_bundle" \
  >/dev/null 2>&1 || status=$?
test "$status" -eq 4
test ! -e "$mismatch_bundle"

cat "$decision"
