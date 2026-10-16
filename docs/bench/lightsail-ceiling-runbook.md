<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE scaling and ceiling on one 32-vCPU AWS Lightsail host — runbook

**Question.** How does the released MCP-RE scale on a 32-vCPU machine, where does its
throughput stop rising, and which component stops it? An uncomfortable answer — scaling
stops at 12, 16, 20 or 24 cores — is a successful run if the evidence says why. The run
characterizes; it does not certify, and nothing here is tuned to make the curve look good.

**Not this.** Not the EKS runbook (no Kubernetes, EKS, ECR, KMS, IAM/IRSA, load balancer or
managed Redis), not a release step (release qualification asks no performance question), and
not comparable in absolute terms to any GKE, EKS, workstation or runner measurement.

Every cloud operation below needs the owner's GO for that operation. Nothing in this file is
run by a gate.

## 1. Identities — the subject and the instrument are recorded separately

| identity | value / where it comes from |
|---|---|
| release / tag | `v0.18.0`, annotated tag object `3f8de319ae08564b71259626a122d0ac3f7779f4` |
| product commit / tree | `9dab7082f7fa02dbaf6024fde9ba3556ed3ad2e2` / `79f661dd42faecdcdd1721d1af9fdcb9c5e51f9d` |
| product binaries | built ON the host from `git archive v0.18.0`; SHA-256 in `/srv/mcp-re/bin/SHA256SUMS` and `build-identity.json` |
| measurement tooling | the commit `stage_artifacts.sh` runs at (`tools/perf/lightsail` + `config/ports.toml`) |
| performance surface | the subject's own `slo_evidence_identity.performance_surface()`, computed on the host in the subject tree; the tooling tree's digest recorded beside it |
| Bazel / toolchain | the subject's `.bazelversion` (9.2.0), checksum-verified from releases.bazel.build; lockfile digests |

No worktree and no second checkout is made. `tools/perf/lightsail/stage_artifacts.sh`
writes `git archive v0.18.0` and `git archive HEAD -- tools/perf/lightsail config/ports.toml`
into `work/lightsail/<run-id>/` (git-ignored) with an `identity.json`. On the host,
`bootstrap.sh` refuses to build unless the archive carries commit `9dab7082…` AND the git tree
re-derived from the extracted files equals `79f661dd…` — so the measured binaries come from
the tagged tree byte for byte, while the orchestration is the later tooling revision. The
campaign refuses binaries whose SHA-256 differs from the build identity.

## 2. The measurement context — `aws-lightsail-32vcpu-v1`

Declared in `config/performance-surface.toml` as a new class with no anchor and no
predeclared pass threshold. Its facts are **measured, not declared**: before anything runs,
`ceiling.py` records the bundle id, architecture, online and usable vCPUs, CPU model and
flags presented to the guest, hypervisor, RAM, block devices, distribution, kernel,
clocksource, governor, SMT, THP, Redis version, Bazel, file-descriptor and ephemeral-port
limits — and stops (exit 3) unless the host is 32 online and usable vCPUs on x86_64 with
the bundle's memory (checked as ≥ 120 GiB nominal, i.e. ≥ ~112 GiB visible to the kernel,
so a "128 GB" label in either unit passes and a smaller bundle does not).
Hardware-independent correctness still applies: every canonical rep must account for all
8000 requests, and a rig row with >0.5% failures is INVALID.

## 3. Topology on the host

Everything on one instance, all traffic on loopback, nothing exposed but SSH:

- **replay tier**: a Redis primary + two replicas as plain `redis-server` processes on the
  registry ports `mcp_re_redis` / `_replica_1` / `_replica_2` (8630-8632), `appendonly yes`,
  otherwise defaults — the canonical Job sidecars' configuration. Started once, kept for the
  campaign, `WAIT 2` probed before every point, INFO/SLOWLOG/LATENCY captured around every
  point. The proxy runs `redis-wait-quorum:2:2000`.
- **instruments**: the six Bazel `-c opt` binaries, run as plain processes with absolute
  paths (no `bazel run`): `mcp-re-proxy-deploy` (the image's binary; Phase A),
  `mcp-re-proxy-ext` (the rig's flavor; Phase B), `tls_load_harness_bench`,
  `saturation_rig`, `saturation_backend`, `saturation_loadgen`.
- **limits**: open files raised to the hard limit and recorded; no kernel tuning.

## 4. Phase A — canonical cold-mTLS curve

The ADR-MCPRE-051 harness unchanged: real proxy, TLS 1.3 mTLS, RFC 9421 + RFC 9530, WAIT-2
replay tier, cold connections, concurrency 128, 8000 requests, **6 reps per point**.

- **scaling topology** (`WORKERS_PER_SHARD=1`, `--cores N`, so N = serving threads):
  N ∈ {1, 2, 4, 8, 16, 24, 32}, none skipped.
- **shipped topology** (`--cores 0 --workers-per-shard 0`, the proxy's own defaults — what
  an operator who sets nothing runs; on 32 vCPUs that resolves to 4 shards × 8 workers).

Per point: every rep's throughput, median, minimum, p50/p99/p999, successes/failures, and
`throughput(N) / (throughput(1) × N)`. The canonical client signs on its own hot path and is
thread-per-connection; if Phase A flattens where Phase B keeps rising, Phase A is
**client-limited** and is reported so — never as an MCP-RE ceiling.

## 5. Phase B — the proxy ceiling with the existing saturation rig

The rig (separate generator processes, pre-signed corpus) with its own criterion unchanged:
a row is PROXY when one more generator raises throughput by ≤ 5%, CLIENT otherwise, INVALID
over 0.5% failures.

**One analysis-driven parameter choice, stated before the run.** Adding one generator to M
raises offered load by at most 1/M; for M ≥ 20 a fully client-limited row cannot gain >5%,
so the test stops being able to say CLIENT. The criterion is kept; offered load is raised
the other way: generators are capped at **12** (each step ≥ 8.3%) and the **connections per
generator climb 256 → 512 → 1024 → 2048** (requests scaled to keep 156.25 per connection)
until the rig says PROXY. A point still CLIENT at the top rung is a floor.

Sweeps, in order:

1. **scaling, cold** — N ∈ {1, 2, 4, 8, 16, 24, 32}, `WORKERS_PER_SHARD=1`. Authoritative.
2. **repeats** — 2 more attempts at the knee, the point after it, and every N ≥ 16.
3. **scaling, keep-alive** — the same sweep without handshakes (the rig's default mode).
4. **partitioned** — N ∈ {1, 2, 4, 8, 16}, proxy pinned to CPUs `0..N-1`, rig + generators +
   backend pinned to the rest (`taskset`). Attribution evidence: the proxy cannot borrow the
   generators' CPU and vice versa.
5. **shipped topology** — `--cores 0 --workers-per-shard 0`, 3 attempts.

## 6. Telemetry — enough to explain a plateau, light enough not to cause one

Per point, around every measurement: `mpstat -P ALL 1`, `pidstat -u -r -w 1` (proxy,
harness, generators, backend, Redis), `vmstat 1`, `sar -n DEV,TCP,ETCP,SOCK 1`, `ss -s`,
`/proc/net/sockstat`, `fs/file-nr`, `netstat -s`, before/after snapshots; and a 4 Hz `/proc`
sampler attributing CPU cores, RSS, major faults and threads to proxy / client / backend /
Redis (and the hottest single Redis process), with host busy, steal, iowait, context
switches, run queue, load, TIME_WAIT. Summaries are computed over the measurement windows
only. `perf` is used only in the diagnostic pass, after the authoritative numbers exist.

## 7. Predeclared rules — how a curve is described and a plateau attributed

These describe; none is a pass/fail threshold. They are in `tools/perf/lightsail/analysis.py`
(`RULES`) and copied into every run manifest.

- **knee**: the first N whose incremental efficiency `(T(N) − T(prev)) / (T(prev) × (N/prev − 1))` < 0.5.
- **plateau**: `T(N) ≤ 1.05 × T(prev)`. **stable**: `(max − min) / median ≤ 0.10` across attempts.
- **PROXY CEILING: REACHED** — the top two sweep points are plateau points, PROXY-verdict
  and stable. **PROXY CEILING: NOT REACHED ON THIS HOST** — incremental efficiency between the
  last two points ≥ 0.5. Otherwise, or when the top of the sweep is client-limited or
  indeterminate: **CEILING ATTRIBUTION: INDETERMINATE**.
- **attribution**, first match wins: INVALID → steal ≥ 5% (HOST_SCHEDULING) → hottest Redis
  process ≥ 0.85 core (REPLAY_TIER) → backend ≥ 85% of its 6 workers (BACKEND) → TIME_WAIT ≥
  80% of the ephemeral range (OS_CONNECTION_PATH) → rig CLIENT: host ≥ 90% busy
  (INDETERMINATE) else CLIENT_LIMITED → proxy ≥ 85% of its core budget (PROXY_CPU) → host ≥
  90% busy (INDETERMINATE: co-located contention) → canonical client using the rest
  (CLIENT_LIMITED) → proxy ≤ 60% of budget (PROXY_SERIALIZATION_OR_CONTENTION) → UNEXPLAINED,
  which triggers the diagnostic pass. The proxy's budget is N under the scaling topology
  and the whole host under the shipped one.

At N = 32 under co-location the proxy can never be given all 32 cores while 12 generators
run; a top-of-sweep INDETERMINATE there is the honest answer, and the partitioned sweep is
the evidence that bounds it.

## 8. Outputs — one run directory

`manifest.json` (identities, binaries' SHA-256, envelope, plan, rules), `host/` (inventory
before and after, identity check, build identity and build log), `redis/` (tier argv, INFO
before/after, health), `phase-a/<topology>/c<N>/` (each rep's report and log, telemetry,
Redis INFO around the point), `phase-b/<sweep>/c<N>/attempt<k>/` (each rung's rig JSON and
log, telemetry), `diagnostic/`, `logs/` (campaign log, stdout, step timings), `summary.json`,
`summary.md` (the two curves, kept apart; knee; highest throughput; ceiling statement;
attribution and confidence; inconclusive points) and `SHA256SUMS` over all of it.

## 9. Before any GO

`PRE-CLOUD LOCAL READINESS: PASS` from one uninterrupted `scripts/local_gate.sh --with-kind`
on the tree that stages the run, plus `python3 tools/perf/lightsail/ceiling.py selftest`.

Then `tools/perf/lightsail/rehearse_host.sh lightsail-rehearsal-<stamp>` must end
`REHEARSAL: PASS`. It runs steps 0 and 3-7 below against a local Ubuntu 24.04 container
standing in for the instance (the blueprint's `ubuntu` user, passwordless sudo, sshd, python3,
and the rendered user-data): the same SSH and scp commands, `bootstrap.sh` with its native
`bazel build -c opt` of the staged release, `run_campaign.sh` in tmux with a shrunken sweep,
the diagnostic pass, `pack`, the download and both checksum verifications. It reaches what
the selftest's fake instruments cannot: Ubuntu 24.04's own git, the `ubuntu` login umask
(0002, under which the proxy refuses the harness's trust document as group-writable), the run
seal over files the launcher writes last, and `perf` under `perf_event_paranoid=4`. What it cannot cover: the cloud calls, and — on an arm64 Docker host —
the x86_64 compile; the instance's architecture-dependent steps (the x86_64 Bazel binary
and its digest, toolchain resolution and repository fetch for an x86_64 Linux exec platform)
are then checked by a separate emulated x86_64 container through `bazel build --nobuild`.

## 10. The execution packet (each numbered step needs the owner's GO; none has run)

Variables: `RUN_ID=lightsail-ceiling-<UTC stamp>`, `REGION=eu-north-1`, `AZ=eu-north-1a`,
`NAME=mcp-re-ceiling-$RUN_ID`, `OP=<operator-ip>/32`, `W=work/lightsail/$RUN_ID`.

**0 — local, no cloud.**
```sh
tools/perf/lightsail/stage_artifacts.sh "$RUN_ID"                  # subject + tooling archives, identity.json
ssh-keygen -t ed25519 -N '' -C "mcp-re-ceiling-$RUN_ID" -f "$W/ssh/id_ed25519"
read -r KTYPE KB64 _ < "$W/ssh/id_ed25519.pub"
python3 tools/cloud/render_cloud_config.py --template tools/perf/lightsail/cloud/user-data.sh \
  --run-id "$RUN_ID" --set SSH_KEY_TYPE="$KTYPE" --set SSH_KEY_B64="$KB64" --set RUN_ID="$RUN_ID"
python3 tools/cloud/render_cloud_config.py --template tools/perf/lightsail/cloud/firewall.json \
  --run-id "$RUN_ID" --set OPERATOR_CIDR="$OP"
```

**1 — read-only discovery (GO).** Confirms the account and resolves the exact bundle; the
bundle is chosen by its facts, never by a guessed id.
```sh
aws sts get-caller-identity
aws lightsail get-bundles --region "$REGION" --query \
  'bundles[?cpuCount==`32` && ramSizeInGb==`128` && isActive && contains(supportedPlatforms,`LINUX_UNIX`) && publicIpv4AddressCount==`1`].[bundleId,price,diskSizeInGb,transferPerMonthInGb,instanceType]'
aws lightsail get-blueprints --region "$REGION" --query 'blueprints[?blueprintId==`ubuntu_24_04`].[blueprintId,version,isActive]'
```
Expected: the general-purpose 32 vCPU / 128 GB Linux bundle with public IPv4 (published at
$884/month ≈ $1.21/hour at the time of writing; the `price` field is authoritative). If no
such bundle is active in `eu-north-1`, stop and ask — another region is a different context.

**2 — create (GO).** One instance; its system disk only; no static IP, snapshot, key pair,
load balancer, database, bucket or container service.
```sh
aws lightsail create-instances --region "$REGION" --instance-names "$NAME" \
  --availability-zone "$AZ" --blueprint-id ubuntu_24_04 --bundle-id "$BUNDLE" \
  --user-data "file://work/cloud-runs/$RUN_ID/user-data.sh" --ip-address-type ipv4 \
  --tags key=project,value=mcp-re key=run,value="$RUN_ID" key=ephemeral,value=true
aws lightsail put-instance-public-ports --region "$REGION" --instance-name "$NAME" \
  --cli-input-json "file://work/cloud-runs/$RUN_ID/firewall.json"
aws lightsail get-instance --region "$REGION" --instance-name "$NAME" \
  --query 'instance.[state.name,publicIpAddress,hardware.cpuCount,hardware.ramSizeInGb,networking.ports]'
```
The firewall replaces Lightsail's default open ports with TCP 22 from `$OP` only. Lightsail
applies no rule at create time, so the default (22 and 80 open) exists for the seconds
between `create-instances` and `put-instance-public-ports`; nothing listens on 80 and SSH
accepts only the run's key.

**3 — on the host (GO covers 3-6).**
```sh
SSH="ssh -i $W/ssh/id_ed25519 -o UserKnownHostsFile=$W/ssh/known_hosts -o StrictHostKeyChecking=accept-new ubuntu@$IP"
$SSH 'sudo install -d -o ubuntu /srv/mcp-re /srv/mcp-re/stage'
scp -i $W/ssh/id_ed25519 -o UserKnownHostsFile=$W/ssh/known_hosts \
  $W/subject.tar.gz $W/tooling.tar.gz $W/identity.json $W/SHA256SUMS ubuntu@$IP:/srv/mcp-re/stage/
$SSH 'cd /srv/mcp-re && tar -xzf stage/tooling.tar.gz && python3 /srv/mcp-re/tooling/tools/perf/lightsail/ceiling.py \
  inventory /srv/mcp-re/precheck --bundle '"$BUNDLE"' --expect-vcpus 32 --expect-arch x86_64 --expect-mem-gib 120'
```
Exit 3 = not the declared context → step 7 immediately, no measurement.

**4 — bootstrap and build (~10-20 min).** The rehearsal measured 127 s end to end on 8 arm64
cores (packages, Bazel, a cold 886-action `-c opt` build); the estimate allows for a slower
mirror and the x86_64 toolchain downloads.
`$SSH 'cd /srv/mcp-re && sudo -E bash /srv/mcp-re/tooling/tools/perf/lightsail/bootstrap.sh'` — ends
`BOOTSTRAP: PASS`, or the run stops.

**5 — campaign (~5-6 h), smoke first, inside tmux.**
```sh
$SSH "tmux new -d -s ceiling 'bash /srv/mcp-re/tooling/tools/perf/lightsail/run_campaign.sh $RUN_ID $BUNDLE'"
$SSH "tail -n 5 /srv/mcp-re/runs/$RUN_ID/logs/campaign.log"        # progress, polled
```
A replay-pool run states the pool in `CAMPAIGN_ARGS`, one pool per run directory:
`tmux new -d -s ceiling 'CAMPAIGN_ARGS="--replay-redis-pool-size 32" bash /srv/mcp-re/tooling/tools/perf/lightsail/run_campaign.sh $RUN_ID $BUNDLE'`.
Every proxy start then goes through `launchers/*.sh`, the smoke stops the run unless both
proxies state that pool, and each point's `point.json` carries `redis_queue` (the store's
connections, blocked in `WAIT`, queued bytes, from the primary).
Diagnostic pass only after `summary.json` exists, on the configuration the summary flags:
`python3 /srv/mcp-re/tooling/tools/perf/lightsail/ceiling.py diagnose /srv/mcp-re/runs/$RUN_ID --bin-dir /srv/mcp-re/bin --cores <N> --window 30`
— `perf record -g -p <proxy>` attached for the window while the rig runs unmodified (the
rig's own profiling-wrapper hook is not used: it changes how every child is torn down) —
then `python3 /srv/mcp-re/tooling/tools/perf/lightsail/ceiling.py pack /srv/mcp-re/runs/$RUN_ID`, which re-seals SHA256SUMS and rewrites the archive. perf runs through `sudo -n` (Ubuntu's `perf_event_paranoid=4` refuses an unprivileged attach); the measured processes stay unprivileged.

**6 — download and verify.**
```sh
scp ... ubuntu@$IP:/srv/mcp-re/runs/$RUN_ID.tar.gz{,.sha256} $W/results/
(cd $W/results && shasum -a 256 -c $RUN_ID.tar.gz.sha256 && tar -xzf $RUN_ID.tar.gz \
  && cd $RUN_ID && shasum -a 256 -c SHA256SUMS)
```

**7 — teardown (GO given with step 2; never deferred "in case").**
```sh
aws lightsail delete-instance --region "$REGION" --instance-name "$NAME" --force-delete-add-ons
```

**8 — verify nothing billable remains.** Each must show no `$RUN_ID` / `mcp-re` resource:
```sh
aws lightsail get-instances --region "$REGION" --query 'instances[].name'
aws lightsail get-disks --region "$REGION" --query 'disks[].name'
aws lightsail get-instance-snapshots --region "$REGION" --query 'instanceSnapshots[].name'
aws lightsail get-disk-snapshots --region "$REGION" --query 'diskSnapshots[].name'
aws lightsail get-static-ips --region "$REGION" --query 'staticIps[].name'
aws lightsail get-key-pairs --region "$REGION" --query 'keyPairs[].name'
aws lightsail get-load-balancers --region "$REGION" --query 'loadBalancers[].name'
aws lightsail get-relational-databases --region "$REGION" --query 'relationalDatabases[].name'
aws lightsail get-buckets --region "$REGION" --query 'buckets[].name'
aws lightsail get-container-services --region "$REGION" --query 'containerServices[].containerServiceName'
```

**Budget.** ≈ 6.5 h instance lifetime expected (bootstrap ≤ 20 min, campaign ~5-6 h, transfer
and teardown minutes) ≈ $8 at $1.21/h. Hard ceiling: 12 h of instance lifetime ≈ $15; past 10 h
the campaign is stopped, partial results are downloaded and the instance is deleted. Transfer
(a few hundred MB out) is inside the bundle's allowance. Expected maximum: **$20**.
