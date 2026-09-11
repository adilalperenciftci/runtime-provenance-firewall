#!/bin/sh
set -eu

validator=${1:-build/out/rpf}
artifact=${2:-build/out/sensor-test-artifact.txt}
events=${3:-build/out/sensor-test.jsonl}
provenance=${4:-build/out/sensor-test-provenance.json}
policy=${5:-lab/kernel/policy.json}
malformed=build/out/provenance.malformed.json
wrong_digest=build/out/provenance.wrong-digest.json
unauthorized_builder=build/out/provenance.unauthorized-builder.json
runtime_source_mismatch=build/out/provenance.runtime-source-mismatch.json
unauthorized_repository_policy=build/out/policy.unauthorized-repository.json
output=build/out/negative-attestation-bundle
decision=build/out/negative-attestation-decision.json

cleanup() {
  rm -f "$malformed" "$wrong_digest" "$unauthorized_builder" "$runtime_source_mismatch" \
    "$unauthorized_repository_policy" "$decision"
  rm -rf "$output"
}
trap cleanup EXIT INT TERM
cleanup

printf '{' >"$malformed"
status=0
"$validator" assemble --artifact "$artifact" --events "$events" --provenance "$malformed" \
  --policy "$policy" --output "$output" >/dev/null 2>&1 || status=$?
test "$status" -eq 4
test ! -e "$output"

sed '0,/"sha256":"[0-9a-f]*"/s//"sha256":"0000000000000000000000000000000000000000000000000000000000000000"/' \
  "$provenance" >"$wrong_digest"
status=0
"$validator" assemble --artifact "$artifact" --events "$events" --provenance "$wrong_digest" \
  --policy "$policy" --output "$output" >/dev/null 2>&1 || status=$?
test "$status" -eq 4
test ! -e "$output"

sed 's#https://github.com/adilalperenciftci/agent-boundary/builders/local-fixture/v0.1#https://attacker.example/builder#g' \
  "$provenance" >"$unauthorized_builder"
"$validator" assemble --artifact "$artifact" --events "$events" --provenance "$unauthorized_builder" \
  --policy "$policy" --output "$output" >/dev/null
status=0
"$validator" verify-fixture --artifact "$artifact" --events "$events" \
  --provenance "$unauthorized_builder" --policy "$policy" --bundle "$output" >"$decision" || status=$?
test "$status" -eq 3
grep -q '"code":"RPF-BUILDER-001"' "$decision"
rm -rf "$output"

sed 's#https://example.test/agent-boundary#https://attacker.example/repo#g' \
  "$provenance" >"$runtime_source_mismatch"
status=0
"$validator" assemble --artifact "$artifact" --events "$events" --provenance "$runtime_source_mismatch" \
  --policy "$policy" --output "$output" >/dev/null 2>&1 || status=$?
test "$status" -eq 4
test ! -e "$output"

sed 's#https://example.test/agent-boundary#https://attacker.example/repo#g' \
  "$policy" >"$unauthorized_repository_policy"
"$validator" assemble --artifact "$artifact" --events "$events" --provenance "$provenance" \
  --policy "$unauthorized_repository_policy" --output "$output" >/dev/null
status=0
"$validator" verify-fixture --artifact "$artifact" --events "$events" \
  --provenance "$provenance" --policy "$unauthorized_repository_policy" --bundle "$output" >"$decision" || status=$?
test "$status" -eq 3
grep -q '"code":"RPF-SOURCE-001"' "$decision"

printf '%s\n' '{"malformed_provenance":"REJECTED","wrong_artifact_digest":"REJECTED","runtime_source_mismatch":"REJECTED","unauthorized_builder":"REJECTED","unauthorized_repository":"REJECTED"}'
