#!/bin/sh
set -eu

if [ "$#" -ne 9 ]; then
  echo "usage: $0 PUBLIC_KEY RUNTIME_SIGSTORE_BUNDLE RUNTIME_STATEMENT PROVENANCE_SIGSTORE_BUNDLE PROVENANCE ARTIFACT EVENTS POLICY EVIDENCE_BUNDLE" >&2
  exit 4
fi

public_key=$1
runtime_signature=$2
runtime=$3
provenance_signature=$4
provenance=$5
artifact=$6
events=$7
policy=$8
evidence_bundle=$9
validator=${RPF_VALIDATOR:-build/out/rpf}

for path in "$public_key" "$runtime_signature" "$runtime" "$provenance_signature" \
  "$provenance" "$artifact" "$events" "$policy"; do
  test -f "$path"
done
test -d "$evidence_bundle"
test -x "$validator"

# This command is deliberately named offline: bypassing tlog verification is unacceptable for a
# production keyless profile, but deterministic local fixtures have no Fulcio/Rekor dependency.
cosign verify-blob --insecure-ignore-tlog --key "$public_key" \
  --bundle "$runtime_signature" "$runtime" >/dev/null
cosign verify-blob --insecure-ignore-tlog --key "$public_key" \
  --bundle "$provenance_signature" "$provenance" >/dev/null

exec "$validator" verify-fixture --artifact "$artifact" --events "$events" \
  --provenance "$provenance" --policy "$policy" --bundle "$evidence_bundle"
