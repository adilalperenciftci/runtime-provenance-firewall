# Benchmarks

Benchmark claims are limited to commands and results recorded here. The microbenchmarks use a
five-event canonical fixture and therefore measure parser/correlation machinery, not kernel sensor
overhead or realistic build scale.

## Reproduction

```sh
go test ./internal/rpf -run '^$' -bench 'Benchmark(ParseEventStream|Assemble|Verify)$' \
  -benchmem -count=5
```

Record the Go version, CPU model, operating environment, fixture event/byte count, and every raw
sample. Compare distributions from the same machine; do not compare a WSL2 sample directly with a
native Linux runner. A benchmark regression gate is not enabled until variance and representative
event-stream sizes are characterized.

For a bounded kernel comparison in the privileged lab image, build the binaries first and run:

```sh
RPF_BENCH_ITERATIONS=100 ./tools/benchmark-kernel.sh
```

This runs the same fixed artifact writer in one cgroup with and without the sensor, reports paired
wall-clock nanoseconds, observed event rate, and loss causes, and refuses to emit a result if any
known event is lost. It is a micro workload dominated by process launch and cgroup entry; it is
not a representative build-overhead claim.

## Current measurement status

| Metric | Status | Reason |
| --- | --- | --- |
| canonical event parse latency/allocations | benchmark implemented | five-event fixture only |
| bundle assembly latency/allocations | benchmark implemented | cryptographic signing excluded |
| policy verification latency/allocations | benchmark implemented | local fixture profile only |
| ring-buffer event throughput/loss | not measured | requires a controlled kernel load generator |
| sensor CPU and memory overhead | not measured | no paired monitored/unmonitored harness yet |
| build-time overhead | not measured | no statistically repeated representative builds yet |
| Cosign/keyless latency | not measured | current lab uses offline keys and no transparency log |
| controlled false positives/negatives | scenario assertions only | corpus is too small for a rate claim |
| paired fixed-fixture sensor wall overhead | five recorded samples | one WSL2 host and process-launch-dominated fixture |
| fixed-fixture observed event rate | five recorded samples | 203 events/sample; not sustained-build throughput |

Measured values must not be promoted to README performance claims without the corresponding raw
results and environment metadata. Event-loss counters in functional tests establish zero observed
loss for those runs only; they are not throughput measurements.

## Recorded five-sample baseline

On 2026-09-11, five samples were run with Go 1.27.1 in the pinned lab
container on Linux `6.18.33.2-microsoft-standard-WSL2`, amd64, Intel i5-11400H. The fixture was
five events / 4,462 bytes. The table reports median and observed minimum/maximum. The complete
samples are retained in [the raw result](benchmark-results/2026-09-11-go-core.txt). This small,
single-host sample is not a regression threshold or a representative build workload.

| Operation | median ns/op | observed ns/op range | median bytes/op | median allocations/op |
| --- | ---: | ---: | ---: | ---: |
| parse event stream | 690,626 | 682,521–823,525 | 329,565 | 4,883 |
| assemble bundle | 884,598 | 874,298–913,588 | 396,163 | 5,948 |
| verify bundle | 1,868,657 | 1,847,748–1,947,445 | 820,382 | 12,265 |

Larger representative streams and repeated independent process runs are still required before
setting a regression threshold. These numbers exclude kernel collection and Cosign.

The kernel-fixture raw samples are in [the dated result](benchmark-results/2026-09-11-kernel-fixture.txt).
The median paired wall overhead in that narrow run was 9.46% with an observed range of -0.15% to
14.35%; the negative sample is retained and reflects measurement noise, not a claimed sensor speedup.
