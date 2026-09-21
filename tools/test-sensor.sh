#!/bin/sh
set -eu

object=${1:-build/out/rpf-sensor.bpf.o}
binary=${2:-build/out/rpf-sensor}
output=${3:-build/out/sensor-test.jsonl}
validator=${4:-build/out/rpf}
graph=${5:-build/out/sensor-test-graph.json}
artifact=${6:-/src/build/out/sensor-test-artifact.txt}
build_id=${RPF_TEST_BUILD_ID:-rpf-sensor-smoke}
run_id=${RPF_TEST_RUN_ID:-local-container-smoke}
repository=https://example.test/runtime-provenance-firewall
revision=1111111111111111111111111111111111111111
callback=/src/build/out/rpf-local-connect
mock=/src/build/out/rpf-mock-server
ready=${RPF_TEST_READY:-build/out/sensor-test-mock.ready}
mock_pid=
provenance=${RPF_TEST_PROVENANCE:-build/out/sensor-test-provenance.json}
bundle=${RPF_TEST_BUNDLE:-build/out/sensor-test-bundle}
full_acceptance=${RPF_TEST_FULL_ACCEPTANCE:-1}
enter=/src/build/out/rpf-cgroup-enter
build_fixture=/src/build/out/rpf-build-fixture
package_fixture=/src/build/out/rpf-package-fixture
policy=lab/kernel/policy.json
if ! mountpoint -q /sys/kernel/tracing; then
  mount -t tracefs tracefs /sys/kernel/tracing
fi
fixture_cgroup=/sys/fs/cgroup/rpf-sensor-test-$$
mkdir "$fixture_cgroup"
cleanup() {
  if [ -n "$mock_pid" ]; then
    kill "$mock_pid" 2>/dev/null || true
  fi
  rm -f "$ready"
  rmdir "$fixture_cgroup" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
cgroup_id=$(stat -c %i "$fixture_cgroup")
boot_id=$(cat /proc/sys/kernel/random/boot_id)
cgroup_path_hash=sha256:$(printf '%s' "$fixture_cgroup" | sha256sum | cut -d ' ' -f 1)
rm -f "$output"
rm -f "$graph"
rm -f "$artifact"
: >"$artifact"
chown 65534:65534 "$artifact"
chmod 0600 "$artifact"
rm -f "$ready"
rm -f "$provenance"
if [ -d "$bundle" ]; then
  rm -f "$bundle/execution-graph.json" "$bundle/evidence-manifest.json" "$bundle/runtime-trace.json"
  rmdir "$bundle"
fi

status=0
timeout --signal=INT 4 "$binary" --object "$object" --cgroup-id "$cgroup_id" --cgroup-path "$fixture_cgroup" \
  --build-id "$build_id" --run-id "$run_id" --boot-id "$boot_id" \
  --repository "$repository" --revision "$revision" \
  --cgroup-path-hash "$cgroup_path_hash" --artifact "$artifact" --output "$output" &
sensor_pid=$!
sleep 1
"$mock" --listen 127.0.0.1:18082 --ready-file "$ready" &
mock_pid=$!
attempt=0
while [ ! -f "$ready" ] && [ "$attempt" -lt 50 ]; do
  sleep 0.05
  attempt=$((attempt + 1))
done
test -f "$ready"
/usr/bin/whoami >/dev/null
"$enter" --cgroup "$fixture_cgroup" -- "$package_fixture" --manifest /src/lab/fixtures/synthetic-package-lock.json
"$enter" --cgroup "$fixture_cgroup" -- "$build_fixture" --artifact "$artifact"
"$enter" --cgroup "$fixture_cgroup" -- "$callback" --address 127.0.0.1:18082
wait "$mock_pid"
mock_pid=
wait "$sensor_pid" || status=$?

if [ "$status" -ne 0 ] && [ "$status" -ne 124 ] && [ "$status" -ne 130 ]; then
  echo "sensor exited unexpectedly: $status" >&2
  exit "$status"
fi
grep -q '"operation":"sensor_started"' "$output"
grep -q '"path":"/src/build/out/rpf-build-fixture"' "$output"
grep -q '"path":"/src/build/out/rpf-package-fixture"' "$output"
grep -q '"operation":"file_open_output"' "$output"
grep -q '"operation":"artifact_finalized"' "$output"
grep -q '"destination":"127.0.0.1:18082"' "$output"
artifact_hash=$(sha256sum "$artifact" | cut -d ' ' -f 1)
grep -q '"sha256":"'"$artifact_hash"'"' "$output"
if grep -q '"path":"/usr/bin/whoami"' "$output"; then
  echo "sensor admitted an executable outside the target cgroup" >&2
  exit 1
fi
grep -q '"kernel_reserve":0' "$output"
grep -q '"kernel_correlation":0' "$output"
grep -q '"kernel_path_read":0' "$output"
grep -q '"kernel_map_update":0' "$output"
grep -q '"kernel_cgroup_mismatch":0' "$output"
correlation=$(sed -n 's/.*"kernel_correlation":\([0-9][0-9]*\).*/\1/p' "$output")
path_read=$(sed -n 's/.*"kernel_path_read":\([0-9][0-9]*\).*/\1/p' "$output")
map_update=$(sed -n 's/.*"kernel_map_update":\([0-9][0-9]*\).*/\1/p' "$output")
cgroup_mismatch=$(sed -n 's/.*"kernel_cgroup_mismatch":\([0-9][0-9]*\).*/\1/p' "$output")
test "$correlation" -eq $((path_read + map_update + cgroup_mismatch))
grep -q '"decode":0' "$output"
grep -q '"uid":65534' "$output"
grep -q '"gid":65534' "$output"
grep -q '"operation":"sensor_finalized"' "$output"
"$validator" validate-events --events "$output"
"$validator" graph-events --events "$output" --output "$graph"
grep -q '"executable":"/src/build/out/rpf-build-fixture"' "$graph"
grep -q '"kind":"unobserved_exec_parent"' "$graph"
grep -q '"kind":"file_open_output"' "$graph"
grep -q '"kind":"artifact_finalized"' "$graph"
grep -q '"kind":"network_connect"' "$graph"
grep -q '"schema_version":"0.2"' "$graph"
grep -q '"parent_observation":"unobserved"' "$graph"
"$validator" create-local-provenance --artifact "$artifact" --events "$output" \
  --repository "$repository" --revision "$revision" \
  --output "$provenance"
"$validator" assemble --artifact "$artifact" --events "$output" --provenance "$provenance" \
  --policy "$policy" --output "$bundle"
"$validator" verify-fixture --artifact "$artifact" --events "$output" --provenance "$provenance" \
  --policy "$policy" --bundle "$bundle"
grep -q 'https://in-toto.io/attestation/runtime-trace/v0.1' "$bundle/runtime-trace.json"
if [ "$full_acceptance" -eq 1 ]; then
  ./tools/test-signing.sh "$bundle/runtime-trace.json" "$provenance" "$artifact" "$output" \
    "$policy" "$bundle"
  original=$artifact.original
  cp "$artifact" "$original"
  printf substituted >> "$artifact"
  tamper_status=0
  "$validator" verify-fixture --artifact "$artifact" --events "$output" --provenance "$provenance" \
    --policy "$policy" --bundle "$bundle" || tamper_status=$?
  mv "$original" "$artifact"
  if [ "$tamper_status" -ne 3 ]; then
    echo "artifact substitution did not produce verifier REJECT" >&2
    exit 1
  fi
fi
before=$(sha256sum "$output")
if "$binary" --object "$object" --cgroup-id "$cgroup_id" --cgroup-path "$fixture_cgroup" \
  --build-id "$build_id" --run-id "$run_id" --boot-id "$boot_id" \
  --repository "$repository" --revision "$revision" \
  --cgroup-path-hash "$cgroup_path_hash" --artifact "$artifact" --output "$output" >/dev/null 2>&1; then
  echo "sensor overwrote an existing evidence stream" >&2
  exit 1
fi
test "$before" = "$(sha256sum "$output")"
