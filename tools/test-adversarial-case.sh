#!/bin/sh
set -eu

object=${1:-build/out/rpf-sensor.bpf.o}
sensor=${2:-build/out/rpf-sensor}
verifier=${3:-build/out/rpf}
case_name=${RPF_ADVERSARIAL_CASE:-adversarial-vulnerable}
auth_mode=${RPF_AUTH_MODE:-intentionally-vulnerable}
case "$auth_mode" in
  intentionally-vulnerable)
    auth_expect=grant
    auth_result_pattern='granted=true reason=authorized'
    ;;
  patched)
    auth_expect=deny
    auth_result_pattern='granted=false reason=authorization_denied'
    ;;
  *)
    echo "unsupported RPF_AUTH_MODE: $auth_mode" >&2
    exit 1
    ;;
esac
evidence=build/out/$case_name-events.jsonl
graph=build/out/$case_name-graph.json
artifact=/src/build/out/$case_name-artifact.txt
credential=/src/build/out/$case_name-synthetic-credential.txt
renamed=/src/build/out/$case_name-renamed-shell
provenance=build/out/$case_name-provenance.json
bundle=build/out/$case_name-bundle
policy=lab/kernel/policy.json
callback=/src/build/out/rpf-local-connect
mock=/src/build/out/rpf-mock-server
ready=build/out/$case_name-mock.ready
auth_target=/src/build/out/rpf-authz-target
auth_proof=/src/build/out/rpf-authz-proof
auth_lab=build/out/$case_name-auth-lab
auth_ready=$auth_lab/ready
auth_result=build/out/$case_name-auth-result.txt
enter=/src/build/out/rpf-cgroup-enter
repository=https://example.test/agent-boundary
revision=1111111111111111111111111111111111111111
mock_pid=

if ! mountpoint -q /sys/kernel/tracing; then
  mount -t tracefs tracefs /sys/kernel/tracing
fi
fixture_cgroup=/sys/fs/cgroup/rpf-adversarial-test-$$
mkdir "$fixture_cgroup"
cleanup() {
  if [ -n "$mock_pid" ]; then
    kill "$mock_pid" 2>/dev/null || true
  fi
  rm -f "$ready" "$auth_ready"
  rmdir "$auth_lab" 2>/dev/null || true
  rm -f "$renamed"
  rmdir "$fixture_cgroup" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
cgroup_id=$(stat -c %i "$fixture_cgroup")
boot_id=$(cat /proc/sys/kernel/random/boot_id)
cgroup_path_hash=sha256:$(printf '%s' "$fixture_cgroup" | sha256sum | cut -d ' ' -f 1)
rm -f "$evidence" "$graph" "$artifact" "$provenance" "$auth_result"
cp /src/lab/fixtures/synthetic-credential.txt "$credential"
chown 65534:65534 "$credential"
chmod 0600 "$credential"
: >"$artifact"
chown 65534:65534 "$artifact"
chmod 0600 "$artifact"
rm -f "$ready" "$auth_ready"
rmdir "$auth_lab" 2>/dev/null || true
mkdir "$auth_lab"
chown 65534:65534 "$auth_lab"
chmod 0700 "$auth_lab"
cp /bin/sh "$renamed"
chmod 0755 "$renamed"
if [ -d "$bundle" ]; then
  rm -f "$bundle/execution-graph.json" "$bundle/evidence-manifest.json" "$bundle/runtime-trace.json"
  rmdir "$bundle"
fi

status=0
timeout --signal=INT 4 "$sensor" --object "$object" --cgroup-id "$cgroup_id" --cgroup-path "$fixture_cgroup" \
  --build-id "rpf-$case_name" --run-id "local-$case_name" --boot-id "$boot_id" \
  --repository "$repository" --revision "$revision" \
  --cgroup-path-hash "$cgroup_path_hash" --artifact "$artifact" --output "$evidence" \
  --sensitive-path "$credential" --sensitive-category synthetic_credential &
sensor_pid=$!
sleep 1
"$mock" --listen 127.0.0.1:18080 --ready-file "$ready" &
mock_pid=$!
attempt=0
while [ ! -f "$ready" ] && [ "$attempt" -lt 50 ]; do
  sleep 0.05
  attempt=$((attempt + 1))
done
if [ ! -f "$ready" ]; then
  echo "local mock did not become ready" >&2
  exit 1
fi
"$enter" --cgroup "$fixture_cgroup" -- /bin/sh -c \
  'if printf tamper >> "$1" 2>/dev/null; then exit 90; fi' sh "/src/$evidence"
identity=$("$enter" --cgroup "$fixture_cgroup" -- /bin/sh -c \
  'IFS= read -r ignored < "$1"; exec 3<> "$1"; exec 3>&-; /usr/bin/id; printf rpf-adversarial-artifact > "$2"' \
  sh "$credential" "$artifact")
test "$identity" = 'uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)'
printf '%s\n' "$identity"
"$enter" --cgroup "$fixture_cgroup" -- "$renamed" -c 'IFS= read -r ignored < "$1"' \
  sh "$credential"
"$enter" --cgroup "$fixture_cgroup" -- "$callback" --address 127.0.0.1:18080
wait "$mock_pid"
mock_pid=

"$enter" --cgroup "$fixture_cgroup" -- "$auth_target" \
  --listen 127.0.0.1:18081 --mode "$auth_mode" --ready-file "$auth_ready" &
mock_pid=$!
attempt=0
while [ ! -f "$auth_ready" ] && [ "$attempt" -lt 50 ]; do
  sleep 0.05
  attempt=$((attempt + 1))
done
test -f "$auth_ready"
"$enter" --cgroup "$fixture_cgroup" -- "$auth_proof" \
  --address 127.0.0.1:18081 --expect "$auth_expect" | tee "$auth_result"
wait "$mock_pid"
mock_pid=
wait "$sensor_pid" || status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 124 ] && [ "$status" -ne 130 ]; then
  echo "adversarial sensor exited unexpectedly: $status" >&2
  exit "$status"
fi

"$verifier" validate-events --events "$evidence"
grep -q '"operation":"file_open_sensitive"' "$evidence"
grep -q '"category":"synthetic_credential"' "$evidence"
grep -q '"path":"/usr/bin/id"' "$evidence"
grep -q '"path":"'"$renamed"'"' "$evidence"
test "$(grep -c '"operation":"file_open_sensitive"' "$evidence")" -eq 3
grep -q '"operation":"network_connect"' "$evidence"
grep -q '"destination":"127.0.0.1:18080"' "$evidence"
test "$(grep -c '"destination":"127.0.0.1:18081"' "$evidence")" -eq 1
test "$(grep -c '"path":"/src/build/out/rpf-authz-proof"' "$evidence")" -eq 2
test "$(grep -c '"path":"/src/build/out/rpf-authz-target"' "$evidence")" -eq 2
grep -q "$auth_result_pattern" "$auth_result"
if grep -q 'not-a-real-secret' "$evidence"; then
  echo "synthetic credential value leaked into evidence" >&2
  exit 1
fi
grep -q '"decode":0' "$evidence"
grep -q '"kernel_reserve":0' "$evidence"
grep -q '"uid":65534' "$evidence"
grep -q '"gid":65534' "$evidence"
correlation=$(sed -n 's/.*"kernel_correlation":\([0-9][0-9]*\).*/\1/p' "$evidence")
path_read=$(sed -n 's/.*"kernel_path_read":\([0-9][0-9]*\).*/\1/p' "$evidence")
map_update=$(sed -n 's/.*"kernel_map_update":\([0-9][0-9]*\).*/\1/p' "$evidence")
cgroup_mismatch=$(sed -n 's/.*"kernel_cgroup_mismatch":\([0-9][0-9]*\).*/\1/p' "$evidence")
test "$correlation" -eq $((path_read + map_update + cgroup_mismatch))

"$verifier" graph-events --events "$evidence" --output "$graph"
grep -q '"kind":"file_open_sensitive"' "$graph"
grep -q '"kind":"network_connect"' "$graph"
grep -q '"schema_version":"0.2"' "$graph"
grep -q '"parent_observation":"unobserved"' "$graph"
"$verifier" create-local-provenance --artifact "$artifact" --events "$evidence" \
  --repository "$repository" --revision "$revision" \
  --output "$provenance"
"$verifier" assemble --artifact "$artifact" --events "$evidence" --provenance "$provenance" \
  --policy "$policy" --output "$bundle"
decision_status=0
decision_output=$("$verifier" verify-fixture --artifact "$artifact" --events "$evidence" --provenance "$provenance" \
  --policy "$policy" --bundle "$bundle") || decision_status=$?
printf '%s\n' "$decision_output"
if [ "$decision_status" -ne 3 ]; then
  echo "synthetic credential access did not produce REJECT" >&2
  exit 1
fi
printf '%s' "$decision_output" | grep -q 'RPF-SENSITIVE-001'
printf '%s' "$decision_output" | grep -q 'RPF-EGRESS-001'
if grep -q '"kernel_correlation":0' "$evidence"; then
  grep -q '"kernel_path_read":0' "$evidence"
  grep -q '"kernel_map_update":0' "$evidence"
  grep -q '"kernel_cgroup_mismatch":0' "$evidence"
  printf '%s' "$decision_output" | grep -q '"completeness":"complete"'
else
  grep -Eq '"kernel_(path_read|map_update|cgroup_mismatch)":[1-9][0-9]*' "$evidence"
  printf '%s' "$decision_output" | grep -q 'RPF-EVIDENCE-001'
  printf '%s' "$decision_output" | grep -q '"completeness":"incomplete"'
fi
