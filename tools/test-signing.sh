#!/bin/sh
set -eu

runtime=${1:-build/out/sensor-test-bundle/runtime-trace.json}
provenance=${2:-build/out/sensor-test-provenance.json}
artifact=${3:-/src/build/out/sensor-test-artifact.txt}
events=${4:-build/out/sensor-test.jsonl}
policy=${5:-lab/kernel/policy.json}
evidence_bundle=${6:-build/out/sensor-test-bundle}
prefix=build/out/lab-signing
attacker_prefix=build/out/lab-untrusted-signing
config=build/out/lab-offline-signing-config.json
runtime_bundle=build/out/runtime-trace.sigstore.json
provenance_bundle=build/out/provenance.sigstore.json
tampered=build/out/runtime-trace.tampered.json
malformed=build/out/runtime-trace.malformed.json

cleanup() {
  rm -f "$prefix.key" "$attacker_prefix.key" "$attacker_prefix.pub" "$tampered" "$malformed"
}
trap cleanup EXIT INT TERM
rm -f "$prefix.key" "$prefix.pub" "$attacker_prefix.key" "$attacker_prefix.pub" "$config" \
  "$runtime_bundle" "$provenance_bundle" "$tampered" "$malformed"

cosign signing-config create --out "$config"
COSIGN_PASSWORD=rpf-synthetic-password cosign generate-key-pair --output-key-prefix "$prefix"
COSIGN_PASSWORD=rpf-synthetic-password cosign sign-blob --yes --signing-config "$config" \
  --key "$prefix.key" --bundle "$runtime_bundle" "$runtime"
COSIGN_PASSWORD=rpf-synthetic-password cosign sign-blob --yes --signing-config "$config" \
  --key "$prefix.key" --bundle "$provenance_bundle" "$provenance"

./tools/verify-offline-signed-fixture.sh "$prefix.pub" "$runtime_bundle" "$runtime" \
  "$provenance_bundle" "$provenance" "$artifact" "$events" "$policy" "$evidence_bundle"

cp "$runtime" "$tampered"
printf ' ' >> "$tampered"
tamper_status=0
cosign verify-blob --insecure-ignore-tlog --key "$prefix.pub" --bundle "$runtime_bundle" "$tampered" \
  >/dev/null 2>&1 || tamper_status=$?
if [ "$tamper_status" -eq 0 ]; then
  echo "Cosign accepted modified attestation bytes" >&2
  exit 1
fi

COSIGN_PASSWORD=rpf-untrusted-synthetic-password cosign generate-key-pair \
  --output-key-prefix "$attacker_prefix" >/dev/null
wrong_key_status=0
./tools/verify-offline-signed-fixture.sh "$attacker_prefix.pub" "$runtime_bundle" "$runtime" \
  "$provenance_bundle" "$provenance" "$artifact" "$events" "$policy" "$evidence_bundle" \
  >/dev/null 2>&1 || wrong_key_status=$?
if [ "$wrong_key_status" -eq 0 ]; then
  echo "Cosign accepted a bundle under an unrelated public key" >&2
  exit 1
fi

printf '{' >"$malformed"
malformed_status=0
./tools/verify-offline-signed-fixture.sh "$prefix.pub" "$runtime_bundle" "$malformed" \
  "$provenance_bundle" "$provenance" "$artifact" "$events" "$policy" "$evidence_bundle" \
  >/dev/null 2>&1 || malformed_status=$?
if [ "$malformed_status" -eq 0 ]; then
  echo "Cosign accepted malformed substituted attestation bytes" >&2
  exit 1
fi
