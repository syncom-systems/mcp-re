<!-- SPDX-License-Identifier: Apache-2.0 -->

# Redis replay pool size — measured effect (2026-10-16)

**Finding.** Under `redis-wait-quorum:2:2000`, each of the replay store's Redis connections
carries one pipelined `SET NX PX` + `WAIT` at a time and stays blocked until two replicas
acknowledge. With the default 8 connections, every one of them was blocked in `WAIT` nearly all
the time at 16-32 serving cores. Raising the pool (`--replay-redis-pool-size`, v0.18.1) raised
keep-alive throughput at 24 and 32 serving cores, with diminishing returns beyond 32 connections.
It did not, on its own, remove the throughput drop from 24 to 32 serving cores; that is a separate
finding ([`replay-path-cpu-scheduling-2026-10-16.md`](replay-path-cpu-scheduling-2026-10-16.md)).

This is a diagnostic measurement, not an SLO and not a release qualification. Absolute numbers
are specific to the host and differ by ~6-7% between instances of the same bundle; compare
within a run only.

## Identities

| | |
|---|---|
| product | `17d7e2497fbf` (tree `a44503425d57`), built on each host from the tagged tree; instrument SHA-256 identical across runs |
| tooling | `17d7e249` (pool 8 vs 32), `71f2ebb6` (pool 32 vs 64) — `tools/perf/lightsail` |
| host | AWS Lightsail `8xlarge_3_0` (32 vCPU = 16 cores x 2 SMT, Xeon Platinum 8488C), eu-north-1a |
| topology | everything on one host over loopback: proxy, saturation rig and generators, backend, Redis primary + 2 replicas (AOF everysec) |
| runs | `lightsail-pool-20261016T153301Z`, `lightsail-pool64-20261016T205027Z` (sealed evidence, held locally) |

## Pool 8 vs pool 32 (keep-alive, rps)

| | 16 cores | 24 cores | 32 cores |
|---|---:|---:|---:|
| pool 8 (rig verdicts, median of 6) | 43,088 | 38,832 | 33,614 |
| pool 32 (rig verdicts, median of 6) | 49,005 | 53,712 | 39,447 |
| pool 8, matched 2x256 connections (median of 6) | 47,661 | 35,521 | 29,661 |
| pool 32, matched 2x256 connections (median of 6) | 49,216 | 52,584 | 39,240 |

With pool 8, 95-99% of the 8 store connections were blocked in `WAIT` during load, with up to
7.8 KB queued behind each. With pool 32, queued bytes per connection fell to 0.1-1.8 KB. At 16
cores the proxy was CPU-bound with either pool.

The matched-load rows come from a first pass whose every "+1 generator" probe crossed the proxy's
per-signer retention bound (800,000 fresh nonces per actor per replica, `async_replay/bounds.rs`)
and failed closed; the rig mis-scored that collapse as saturation. Those rows remain valid
comparisons at a fixed 512 connections; the rig-verdict rows come from a second pass sized under
the bound. The harness now refuses such a rung as INVALID (`tools/perf/lightsail/phases.py`).

## Pool 32 vs pool 64 (keep-alive, rps, median of 15; 60/60 rungs valid)

| | 24 cores | 32 cores | 32 / 24 |
|---|---:|---:|---:|
| pool 32 | 54,759 | 43,844 | 0.80 |
| pool 64 | 57,822 | 49,379 | 0.85 |
| pool 64 / pool 32 | 1.06 | 1.13 | |

All 64 connections carried work and sat blocked in `WAIT`; queued bytes per connection halved
(1.7 -> 0.7 KB at 32 cores). But each connection's `SET`+`WAIT` cycle nearly doubled (0.78 ->
1.41 ms), so twice the connections completed only 13% more admissions: diminishing returns. The
Redis primary's run-queue delay at 32 cores (~0.3 s per s, against ~0.12 at 24) pointed at CPU
scheduling, which the follow-up isolation experiment tested.

## What this supports

- A larger pool is a real improvement where admissions queue behind `WAIT`: +38-48% at 24
  serving cores and +17-32% at 32 cores for 8 -> 32; a further +6% / +13% for 32 -> 64.
- It is not linear scaling, and it does not by itself remove the 24 -> 32-core drop on a
  co-located host.
- Every measured success carried the backend's echo; `redis-wait-quorum:2:2000` and fail-closed
  behaviour were unchanged throughout.
