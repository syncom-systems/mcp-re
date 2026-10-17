<!-- SPDX-License-Identifier: Apache-2.0 -->

# Replay-path CPU scheduling on a co-located host — measured effect (2026-10-16)

**Finding.** On one 32-vCPU host carrying the proxy, the load generators, the backend and the Redis
primary + 2 replicas, the drop in keep-alive throughput from 24 to 32 serving workers coincides
with CPU-scheduling delay on two threads of the replay path: the Redis primary and the proxy's
control runtime (`mcp-re-control`, which drives the replay store's Redis connections). Reserving
a physical core for each removed that delay and restored 32-worker throughput from 46.6k to
55.1k rps — the level of 24 unrestricted workers. It did **not** establish scaling beyond 24
workers: 32 isolated workers matched 24 unrestricted ones, they did not exceed them.

This is a diagnostic measurement on a co-located test host, not an SLO, not a release
qualification, and not a deployment recommendation. No product setting was changed; the
isolation was applied by the measurement harness.

## Identities

| | |
|---|---|
| product | `17d7e2497fbf` (tree `a44503425d57`), instrument SHA-256 identical to the pool-size runs |
| tooling | `dcce3dc8` — `tools/perf/lightsail` with `--isolate-replay-path` |
| host | AWS Lightsail `8xlarge_3_0`, eu-north-1a; SMT siblings measured on the host: CPU i and i+16 |
| configuration | `--replay-redis-pool-size 64`, `redis-wait-quorum:2:2000`, primary + 2 replicas, AOF everysec, keep-alive |
| run | `lightsail-iso-20261016T223614Z` (sealed evidence, held locally); runs A, B, A, B; 30/30 rungs valid |

## Arms

- **A — unrestricted** (as every earlier run), 24 and 32 serving workers.
- **B — isolated**, 32 serving workers: the Redis primary on CPU 14, `mcp-re-control` on CPU 15,
  their SMT siblings 30 and 31 left idle; everything else — 32 serving threads, the proxy's other
  threads, the replicas, generators, backend and harness — on the other 28 logical CPUs. The proxy
  pins each serving shard to the absolute CPU `core_index % online_cpus`; the 4 shards it pins to
  reserved CPUs were moved onto the shared set by the harness, the other 28 kept their pins.

## Results (keep-alive, medians of 10)

| | A24 | A32 | B32 |
|---|---:|---:|---:|
| throughput (rps) | 53,702 | 46,624 | 55,109 |
| run 1 / run 2 | 55,221 / 51,947 | 45,011 / 47,053 | 55,140 / 55,078 |
| `SET`+`WAIT` cycle per connection (ms) | 1.28 | 1.47 | 1.19 |
| replica acknowledgement lag (ms) | 0.66-0.72 | 0.57-0.74 | 0.77-0.79 |
| proxy-side replay wait (ms) | 11.0 | 14.3 | 7.4 |
| Redis primary run-queue delay (s per s) | 0.12 | 0.29 | 0.002 |
| control thread run-queue delay (s per s) | 0.12 | 0.32 | 0.001 |
| replica run-queue delay (s per s) | 0.05 | 0.05 | 0.23 |
| serving-thread run-queue delay (s per s, per thread) | 0.034 | 0.070 | 0.181 |
| runnable threads on 32 vCPUs | 31 | 29 | 38 |

Placement held during every measured window: no serving thread, replica or other proxy thread was
ever seen on a reserved CPU; the control thread ran only on CPU 15; every Redis primary thread's
mask was CPU 14 (kernel-enforced); the idle siblings were 3% and 0% busy; no thread mask changed
during a measured step.

## Reading

- Removing the scheduling delay of the Redis primary and the control thread shortened the
  `SET`+`WAIT` cycle (1.47 -> 1.19 ms) and raised 32-worker throughput 18%, although the serving
  threads had 4 fewer logical CPUs and waited 2.6x longer to run. The reduced replay-path delay
  more than compensated for the lost serving capacity.
- Both threads were isolated together; this data cannot attribute the effect to either alone.
- With isolation the host was oversubscribed (38 runnable threads on 32 vCPUs); the replicas,
  now on the shared CPUs, waited ~5x longer to run, and their acknowledgement lag was about two
  thirds of the cycle. Whether those set the remaining ceiling was not tested.
- The repeat agreement of the A24 arm (6%) was one point outside the 5% predeclared for it; the
  B32 runs agreed within 0.1%.

## Follow-up

The proxy's serving shards pin themselves to absolute CPU numbers, which ignores an
operator-provided CPU allocation (a `taskset` mask, a cgroup cpuset, reserved capacity). How the
proxy should respect operator-managed CPU allocation is tracked as a separate issue; it is not part
of v0.18.1.
