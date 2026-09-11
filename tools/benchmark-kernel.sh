#!/bin/sh
set -eu

iterations=${RPF_BENCH_ITERATIONS:-100}
sensor=${RPF_BENCH_SENSOR:-build/out/rpf-sensor}
object=${RPF_BENCH_OBJECT:-build/out/rpf-sensor.bpf.o}
enter=/src/build/out/rpf-cgroup-enter
fixture=/src/build/out/rpf-build-fixture
artifact=/src/build/out/sensor-benchmark-artifact.txt
output=${RPF_BENCH_OUTPUT:-build/out/kernel-benchmark-events.jsonl}
if [ "$iterations" -lt 1 ]; then
  echo "RPF_BENCH_ITERATIONS must be positive" >&2
  exit 2
fi
if ! mountpoint -q /sys/kernel/tracing; then
  mount -t tracefs tracefs /sys/kernel/tracing
fi
fixture_cgroup=/sys/fs/cgroup/rpf-kernel-benchmark-$$
mkdir "$fixture_cgroup"
cleanup() {
  if [ -n "${sensor_pid:-}" ]; then
    kill -INT "$sensor_pid" 2>/dev/null || true
    wait "$sensor_pid" 2>/dev/null || true
  fi
  rm -f "$output" "$artifact"
  rmdir "$fixture_cgroup" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
cgroup_id=$(stat -c %i "$fixture_cgroup")
boot_id=$(cat /proc/sys/kernel/random/boot_id)
cgroup_path_hash=sha256:$(printf '%s' "$fixture_cgroup" | sha256sum | cut -d ' ' -f 1)
: >"$artifact"
chown 65534:65534 "$artifact"
chmod 0600 "$artifact"

start=$(date +%s%N)
i=0
while [ "$i" -lt "$iterations" ]; do
  "$enter" --cgroup "$fixture_cgroup" -- "$fixture" --artifact "$artifact" >/dev/null
  i=$((i + 1))
done
baseline_ns=$(( $(date +%s%N) - start ))

rm -f "$output"
timeout --signal=INT 10 "$sensor" --object "$object" --cgroup-id "$cgroup_id" \
  --cgroup-path "$fixture_cgroup" --build-id rpf-kernel-benchmark --run-id local-kernel-benchmark \
  --boot-id "$boot_id" --repository https://example.test/agent-boundary \
  --revision 1111111111111111111111111111111111111111 \
  --cgroup-path-hash "$cgroup_path_hash" --artifact "$artifact" --output "$output" &
sensor_pid=$!
sleep 1
start=$(date +%s%N)
i=0
while [ "$i" -lt "$iterations" ]; do
  "$enter" --cgroup "$fixture_cgroup" -- "$fixture" --artifact "$artifact" >/dev/null
  i=$((i + 1))
done
sensor_ns=$(( $(date +%s%N) - start ))
wait "$sensor_pid" || sensor_status=$?
sensor_status=${sensor_status:-0}
if [ "$sensor_status" -ne 0 ] && [ "$sensor_status" -ne 124 ] && [ "$sensor_status" -ne 130 ]; then
  echo "benchmark sensor exited unexpectedly: $sensor_status" >&2
  exit "$sensor_status"
fi
test -s "$output"
events=$(grep -c '"event_id"' "$output")
correlation=$(sed -n 's/.*"kernel_correlation":\([0-9][0-9]*\).*/\1/p' "$output")
ring=$(sed -n 's/.*"kernel_reserve":\([0-9][0-9]*\).*/\1/p' "$output")
path_read=$(sed -n 's/.*"kernel_path_read":\([0-9][0-9]*\).*/\1/p' "$output")
map_update=$(sed -n 's/.*"kernel_map_update":\([0-9][0-9]*\).*/\1/p' "$output")
cgroup_mismatch=$(sed -n 's/.*"kernel_cgroup_mismatch":\([0-9][0-9]*\).*/\1/p' "$output")
test "$correlation" -eq $((path_read + map_update + cgroup_mismatch))
test "$correlation" -eq 0
test "$ring" -eq 0
test "$events" -ge "$iterations"
overhead=$(awk -v b="$baseline_ns" -v s="$sensor_ns" 'BEGIN { if (b == 0) print "nan"; else printf "%.2f", (s-b)*100/b }')
rate=$(awk -v e="$events" -v n="$sensor_ns" 'BEGIN { if (n == 0) print "nan"; else printf "%.2f", e/(n/1000000000) }')
printf '{"iterations":%s,"baseline_ns":%s,"sensor_ns":%s,"overhead_percent":%s,"observed_events":%s,"observed_events_per_second":%s,"loss":{"ring":%s,"correlation":%s,"path_read":%s,"map_update":%s,"cgroup_mismatch":%s}}\n' \
  "$iterations" "$baseline_ns" "$sensor_ns" "$overhead" "$events" "$rate" \
  "$ring" "$correlation" "$path_read" "$map_update" "$cgroup_mismatch"
