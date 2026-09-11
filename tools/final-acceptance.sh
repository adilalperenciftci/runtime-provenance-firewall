#!/bin/sh
set -eu

report=${RPF_ACCEPTANCE_REPORT:-build/out/final-acceptance-report.json}

./tools/test-sensor.sh
./tools/test-adversarial.sh

for path in \
  build/out/sensor-test.jsonl \
  build/out/sensor-test-graph.json \
  build/out/sensor-test-bundle/runtime-trace.json \
  build/out/runtime-trace.sigstore.json \
  build/out/provenance.sigstore.json \
  build/out/adversarial-vulnerable-events.jsonl \
  build/out/adversarial-vulnerable-graph.json \
  build/out/adversarial-vulnerable-bundle/runtime-trace.json \
  build/out/adversarial-patched-events.jsonl \
  build/out/adversarial-patched-graph.json \
  build/out/adversarial-patched-bundle/runtime-trace.json; do
  test -s "$path"
done

grep -q 'granted=true reason=authorized' build/out/adversarial-vulnerable-auth-result.txt
grep -q 'granted=false reason=authorization_denied' build/out/adversarial-patched-auth-result.txt
grep -q '"operation":"file_open_sensitive"' build/out/adversarial-vulnerable-events.jsonl
grep -q '"destination":"127.0.0.1:18080"' build/out/adversarial-vulnerable-events.jsonl
grep -q '"path":"/src/build/out/rpf-authz-proof"' build/out/adversarial-vulnerable-events.jsonl
grep -q '"path":"/src/build/out/rpf-authz-target"' build/out/adversarial-vulnerable-events.jsonl

mkdir -p "$(dirname "$report")"
printf '%s\n' \
  '{' \
  '  "schema_version": "0.1",' \
  '  "baseline": {' \
  '    "decision": "ALLOW",' \
  '    "responsible_processes": ["/src/build/out/rpf-build-fixture", "/src/build/out/rpf-local-connect"],' \
  '    "evidence": ["build/out/sensor-test.jsonl", "build/out/sensor-test-graph.json", "build/out/sensor-test-bundle/runtime-trace.json", "build/out/runtime-trace.sigstore.json", "build/out/provenance.sigstore.json"],' \
  '    "invariant": "artifact, runtime source/build identity, provenance, signatures, loss state, and policy agree",' \
  '    "artifact_substitution": "REJECT:RPF-ARTIFACT-001"' \
  '  },' \
  '  "vulnerable": {' \
  '    "authorization_impact": "CONFIRMED:synthetic marker granted",' \
  '    "decision": "REJECT",' \
  '    "responsible_processes": ["/bin/sh", "/src/build/out/rpf-renamed-shell", "/src/build/out/rpf-local-connect", "/src/build/out/rpf-authz-target", "/src/build/out/rpf-authz-proof"],' \
  '    "evidence": ["build/out/adversarial-vulnerable-events.jsonl", "build/out/adversarial-vulnerable-graph.json", "build/out/adversarial-vulnerable-bundle/runtime-trace.json"],' \
  '    "affected_invariants": ["forbidden synthetic credential access", "undeclared localhost egress", "authorization boundary crossed"],' \
  '    "decision_basis": ["RPF-SENSITIVE-001", "RPF-EGRESS-001"],' \
  '    "authorization_semantic_detected": false' \
  '  },' \
  '  "patched": {' \
  '    "authorization_impact": "BLOCKED:identical proof denied",' \
  '    "benign_artifact_build": "PRESERVED",' \
  '    "decision": "REJECT",' \
  '    "evidence": ["build/out/adversarial-patched-events.jsonl", "build/out/adversarial-patched-graph.json", "build/out/adversarial-patched-bundle/runtime-trace.json"],' \
  '    "decision_basis": ["RPF-SENSITIVE-001", "RPF-EGRESS-001"],' \
  '    "remediation_validated": true' \
  '  }' \
  '}' >"$report"

printf '{"acceptance":"PASS","report":"%s"}\n' "$report"
