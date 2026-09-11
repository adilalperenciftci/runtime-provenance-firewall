#!/bin/sh
set -eu

RPF_ADVERSARIAL_CASE=adversarial-vulnerable \
RPF_AUTH_MODE=intentionally-vulnerable \
  ./tools/test-adversarial-case.sh "$@"

RPF_ADVERSARIAL_CASE=adversarial-patched \
RPF_AUTH_MODE=patched \
  ./tools/test-adversarial-case.sh "$@"

grep -q 'granted=true reason=authorized' build/out/adversarial-vulnerable-auth-result.txt
grep -q 'granted=false reason=authorization_denied' build/out/adversarial-patched-auth-result.txt
printf '%s\n' '{"vulnerable_security_impact":"CONFIRMED","patched_security_impact":"BLOCKED","benign_artifact_build":"PRESERVED"}'
