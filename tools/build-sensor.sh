#!/bin/sh
set -eu

output=${1:-build/out}
mkdir -p "$output"
bpftool_bin=$(command -v bpftool || true)
if [ -z "$bpftool_bin" ] || ! "$bpftool_bin" version >/dev/null 2>&1; then
  bpftool_bin=$(find /usr/lib/linux-tools -name bpftool | sort | tail -n 1)
fi
"$bpftool_bin" btf dump file /sys/kernel/btf/vmlinux format c > "$output/vmlinux.h"
clang -g -O2 -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
  -I"$output" -I/usr/include/$(uname -m)-linux-gnu \
  -c internal/sensor/bpf/sensor.bpf.c -o "$output/rpf-sensor.bpf.o"
llvm-strip -g "$output/rpf-sensor.bpf.o"
