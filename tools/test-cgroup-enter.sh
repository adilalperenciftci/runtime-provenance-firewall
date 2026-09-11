#!/bin/sh
set -eu

enter=${1:-/src/build/out/rpf-cgroup-enter}
iterations=${RPF_CREDENTIAL_STRESS_ITERATIONS:-100}
fixture_cgroup=/sys/fs/cgroup/rpf-credential-stress-$$
expected='uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)'

mkdir "$fixture_cgroup"
cleanup() {
  rmdir "$fixture_cgroup" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

iteration=0
while [ "$iteration" -lt "$iterations" ]; do
  actual=$("$enter" --cgroup "$fixture_cgroup" -- /usr/bin/id)
  if [ "$actual" != "$expected" ]; then
    printf 'unexpected credential state at iteration %s: %s\n' "$iteration" "$actual" >&2
    exit 1
  fi
  iteration=$((iteration + 1))
done
printf '{"credential_drop_iterations":%s,"valid":true}\n' "$iterations"
