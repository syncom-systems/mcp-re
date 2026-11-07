"""Tunables and fixed identities of the physical-host admission gate.

Every value here is read from the environment once, at import, with the measured default
stated beside it. The reasoning for the thresholds lives next to each one; the protocol they
parameterise is described in `host_gate`.
"""

from __future__ import annotations

import os
from pathlib import Path

SCHEMA = "mcp-re-host-gate/v1"

OPEN, RESERVING, RESERVED, RELEASED = "OPEN", "RESERVING", "RESERVED", "RELEASED"

# Installed OUTSIDE either runner application directory on purpose: a runner self-update
# rewrites its own tree, and `config.sh remove` deletes it outright.
ROOT = Path(os.environ.get("MCP_RE_ARBITER_ROOT", "/opt/verification/runner-arbiter"))

# The narrowest read path the two kernels share. /opt is not mounted in the VM; /Users is.
MIRROR = Path(os.environ.get("MCP_RE_ARBITER_MIRROR", str(Path.home() / ".runner-arbiter")))

# Runner hooks have no built-in timeout, so an unbounded wait wedges a runner permanently
# with nothing to show an operator. Every wait is bounded; every expiry REFUSES.
ORDINARY_WAIT_S = int(os.environ.get("MCP_RE_ARBITER_ORDINARY_WAIT_S", 45 * 60))

# THE HEAVY SLOT: ONE HEAVY JOB ON THE PHYSICAL HOST AT A TIME.
#
# dev1 (matssun/code's Bazel lane) and dev1-mcp-re (every mcp-re job) each load this 48 GB
# host enough on their own. GitHub schedules them concurrently because they serve different
# repositories, and on a personal account a runner cannot be shared between repositories.
# Measured 2026-09-26: with both lanes, the fast lane and the Colima VMs running, the host
# sat at 358 MB free and 10.7 of 12 GB swap, and tests that take 12 s alone timed out at 60.
#
# A job on one of these runners takes the `heavy` kernel lock exclusively (see
# `host_locks`); the fast lane never takes it. The wait is long because the holder of the
# lock is, by construction, a live job -- a dead job's lock is gone with its holder. Six
# hours is the longest job timeout on this host (release.yml); past it the waiter refuses
# rather than wedging its runner, since runner hooks have no timeout of their own.
HEAVY_RUNNERS = frozenset(
    name.strip()
    for name in os.environ.get("MCP_RE_ARBITER_HEAVY_RUNNERS", "dev1,dev1-mcp-re").split(",")
    if name.strip())
HEAVY_WAIT_S = int(os.environ.get("MCP_RE_ARBITER_HEAVY_WAIT_S", 6 * 3600))

# HOW LONG THE HOST MAY STAY CLOSED WHILE THE OWNER DRAINS.
#
# This is not merely the owner's patience -- it is the blast radius. From the moment the
# reservation is granted, NO new ordinary job is admitted on ANY runner, which is what stops
# the queue refilling while pre-existing work finishes. So the bound is how long one
# already-running job can hold the whole machine closed to CI.
#
# It was 60 minutes, and that was measured to be too generous. On 2026-09-12 a genrule hung
# (see PR #8470) and the reservation sat behind it; the host was closed to every repository
# for the better part of an hour before the bound expired. One stalled job should not cost
# the fleet an hour.
#
# 30 minutes, because the trade is asymmetric: an SLO that gives up is re-dispatched at no
# cost to anyone, while a closed host blocks every other PR on the machine. A legitimate
# ordinary job longer than this simply means the benchmark retries later, which is the
# cheaper failure.
DRAIN_WAIT_S = int(os.environ.get("MCP_RE_ARBITER_DRAIN_WAIT_S", 30 * 60))
POLL_S = float(os.environ.get("MCP_RE_ARBITER_POLL_S", 5))

#: How often the drain re-announces what it is waiting on. It used to say so ONCE, so a
#: stalled drain looked identical to a fast one from the outside and the operator had to go
#: read the arbiter log to find out which job was holding the host.
DRAIN_ANNOUNCE_S = float(os.environ.get("MCP_RE_ARBITER_DRAIN_ANNOUNCE_S", 60))

# Quiescence. The old rule read load1 once. The failed run shows why one instantaneous
# sample cannot carry a release-grade claim:  1m=3.48 "quiet",  5m=5.73,  15m=5.61 --
# load1 had decayed while the box still worked through another runner's job. load5/load15
# hold that memory, so all three are read and the condition must HOLD across samples.
#
# THRESHOLDS ARE MEASURED, NOT PICKED. From 63 samples over 10.3 min on dev1 (14 CPUs),
# and from the failed run, as fractions of CPU count:
#
#                       load1   load5   load15
#     dev1 at rest      0.10    0.125   0.11     <- floor: 3 runner listeners + 2 colima VMs
#     dev1 at-rest max  0.23    0.17    0.14
#     THE FAILED RUN    0.25    0.41    0.40
#     threshold here    0.20    0.25    0.30
#
# Read the load1 column: the failed run's load1 was 0.25 against a floor of 0.10 and an
# ordinary at-rest peak of 0.23. load1 BARELY separates the failure from an idle box, which
# is exactly how a one-sample load1 rule declared that host quiet. load5 and load15 are the
# clauses doing the discriminating -- they exceed their thresholds by 64% and 33% -- so the
# policy is load5/load15 first and load1 only as a fast-moving corroborator.
#
# Consecutive sampling is the other half. dev1's load1 touches 0.23 at rest under ordinary
# background activity, so any single sample is noisy; requiring Q_SAMPLES consecutive quiet
# observations means ~60s of SUSTAINED quiet, which no transient satisfies.
Q_LOAD1 = float(os.environ.get("MCP_RE_ARBITER_Q_LOAD1", 0.20))
Q_LOAD5 = float(os.environ.get("MCP_RE_ARBITER_Q_LOAD5", 0.25))
Q_LOAD15 = float(os.environ.get("MCP_RE_ARBITER_Q_LOAD15", 0.30))
Q_SAMPLES = int(os.environ.get("MCP_RE_ARBITER_Q_SAMPLES", 6))
Q_INTERVAL_S = float(os.environ.get("MCP_RE_ARBITER_Q_INTERVAL_S", 10))
Q_WAIT_S = int(os.environ.get("MCP_RE_ARBITER_Q_WAIT_S", 20 * 60))

# Every runner application sharing this physical host. The owner refuses to measure unless
# each is confirmed to participate in admission.
REGISTERED_RUNNERS = (
    {"name": "dev1", "kernel": "darwin", "root": "/Users/mats/dev/actions-runner"},
    {"name": "dev1-mcp-re", "kernel": "darwin", "root": "/Users/mats/dev/actions-runner-mcp-re"},
    # matssun/code's `fast` lane (no Bazel): two runner services, 2026-09-23.
    {"name": "dev1-fast-1", "kernel": "darwin", "root": "/Users/mats/dev/actions-runner-dev1-fast-1"},
    {"name": "dev1-fast-2", "kernel": "darwin", "root": "/Users/mats/dev/actions-runner-dev1-fast-2"},
    {"name": "dev1-linux", "kernel": "linux-vm",
     "root": os.environ.get("MCP_RE_ARBITER_VM_RUNNER_HOME", "/home/mats.guest/actions-runner")},
)


# WHERE THE REFUSAL THRESHOLD COMES FROM, AND WHY IT IS NOT THE ALARM THRESHOLD.
#
# matssun/code carries LOW_SPACE_ALARM_GB = 40 in
# infrastructure/scripts/verification_store_retention.py. The two numbers describe ONE
# condition at two stages and must not be read as competing thresholds:
#
#     40 GB   ALARM    retention should reclaim now.  Jobs still run.
#     25 GB   REFUSE   too late to reclaim politely.  No job is admitted.
#
# The 15 GB between them is the operating margin -- the room the weekly retention job has to
# work in while CI keeps running. Seeing the alarm and no refusals means the band is doing
# its job; seeing refusals means it was lost.
#
# Both ends divide by 1024**3, so the numbers are directly comparable. (Both call that "GB";
# it is GiB. Kept, because agreeing with the other end matters more than the label.)
DISK_REFUSE_GB = float(os.environ.get("MCP_RE_ARBITER_DISK_REFUSE_GB", 25))

# THE RECOVERY LANE, WHICH MUST BE ADMITTED BELOW THE THRESHOLD.
#
# A capacity guard that refuses its own cure is a deadlock. The weekly retention job runs on
# this host, on this runner, through this hook, and it is the thing that makes the disk not
# full. Refusing it at exactly the moment it is needed converts a self-healing condition into
# one that requires a human at a keyboard -- which is the failure this guard exists to end,
# reintroduced by the guard itself.
#
# Identified by repository AND workflow path, for the reason `JobIdentity.is_slo` is: a title
# match would let any workflow name itself into the exemption.
RECOVERY_REPOSITORY = os.environ.get("MCP_RE_ARBITER_RECOVERY_REPOSITORY", "matssun/code")
RECOVERY_WORKFLOW = os.environ.get(
    "MCP_RE_ARBITER_RECOVERY_WORKFLOW", ".github/workflows/disk-retention.yml")


#: How often a waiting local lease repeats what it is waiting for.
LEASE_POLL_S = float(os.environ.get("MCP_RE_ARBITER_LEASE_POLL_S", 30))
