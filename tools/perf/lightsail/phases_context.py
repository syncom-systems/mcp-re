# SPDX-License-Identifier: Apache-2.0
"""What a point is measured against: the instruments, the run context, the replay tier's health."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from common import log
from redis_tier import Tier
from telemetry import Telemetry, summarize

import stage_sampler
from common import HW_CLASS, base_env, log, read_json, run_logged, write_json
from redis_tier import Tier
from telemetry import Telemetry, summarize

PASS_LINE = "test result: ok. 1 passed"
GEN_CAP = 12
LADDER = (256, 512, 1024, 2048)        # connections per generator
REQUESTS_PER_CONNECTION = 40000 / 256  # the rig's own default ratio
#: The pool the proxy opens when no `--replay-redis-pool-size` is passed.
DEFAULT_REPLAY_POOL = 8
#: Where the launcher appends each proxy's startup transcript; set per rep / rung.
STARTUP_LOG_ENV = "MCP_RE_CEILING_PROXY_LOG"
#: The proxy's per-actor retention budget (`async_replay/bounds.rs`: 1,000,000 entries per
#: replica, of which one actor may hold 800,000 under pressure). Each fresh rig nonce is
#: retained for its signature window (3600 s), so one rung's proxy refuses the rig's
#: 800,001st request — fail closed, `mcp-re.replay_cache_unavailable`.
SIGNER_RETENTION_BUDGET = 800_000
#: What a rung may send at most: the budget less a 5% margin.
RUNG_REQUEST_CEILING = SIGNER_RETENTION_BUDGET * 95 // 100


@dataclass
class Binaries:
    proxy_deploy: Path
    proxy_ext: Path
    bench: Path
    rig: Path
    backend: Path
    loadgen: Path


@dataclass
class Context:
    run_dir: Path
    bins: Binaries
    redis_url: str
    vcpus: int
    require_telemetry: bool
    tier: Tier | None = None         # for snapshots and health; None only in a selftest
    envelope: dict = field(default_factory=lambda: {"concurrency": 128, "requests": 8000, "mode": "cold"})
    ladder: tuple[int, ...] = LADDER
    gen_cap: int = GEN_CAP
    requests_per_connection: float = REQUESTS_PER_CONNECTION
    replay_pool: int | None = None   # None: the flag is omitted and the proxy's default applies
    stage_timers: bool = False       # set MCP_RE_STAGE_TIMERS for every Phase B rung
    isolation: dict | None = None    # isolation.plan(): instruments confined to its general CPUs

    def instrument_prefix(self) -> list[str]:
        """How an instrument (bench, rig and so its generators and backend) is started: under
        the isolation plan's general CPUs, or unrestricted."""
        if self.isolation is None:
            return []
        from isolation import cpulist
        return ["taskset", "-c", cpulist(self.isolation["general"])]


def snapshot_redis(ctx: Context, path: Path) -> None:
    if ctx.tier is not None:
        ctx.tier.snapshot(path)


def redis_roles(ctx: Context) -> dict[int, str]:
    """Each replay-tier process's pid -> role, for per-process telemetry."""
    if ctx.tier is None:
        return {}
    return {proc.pid: role for role, proc in ctx.tier.procs.items()}


def healthy(ctx: Context) -> bool:
    if ctx.tier is None:
        return True
    try:
        ctx.tier.wait_quorum(deadline_s=30)
        return True
    except Exception as exc:  # noqa: BLE001 — any failure here means the tier is not usable
        log(ctx.run_dir, f"replay tier NOT healthy: {exc}")
        return False


def windowed(tel: Telemetry, windows: list[list[float]], vcpus: int, name: str = "summary-windowed.json") -> dict:
    """Telemetry summarized over the measurement windows only: the gaps between reps
    (process start, presign, teardown) would otherwise dilute every average."""
    if tel.sampler is None:
        return tel.result
    inside = [s for s in tel.sampler.samples if any(a <= s["t"] <= b for a, b in windows)]
    summary = summarize(inside, vcpus)
    (tel.dir / name).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary
