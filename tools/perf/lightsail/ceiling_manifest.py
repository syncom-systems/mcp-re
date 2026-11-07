# SPDX-License-Identifier: Apache-2.0
"""What a campaign records about itself before it measures: the instruments, the envelope, the plan."""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

from analysis import RULES
from common import HW_CLASS, read_json, sha256_file, utc_now, write_json
from phases import (DEFAULT_REPLAY_POOL, RUNG_REQUEST_CEILING, SIGNER_RETENTION_BUDGET, STARTUP_LOG_ENV,
                    Binaries, proxy_launcher)
from redis_queue import config_get
from redis_tier import Tier

#: The replay-tier settings a reader of the manifest needs without the full CONFIG GET copy.
REDIS_CONFIG_KEYS = ("appendonly", "appendfsync", "save", "io-threads", "maxclients", "maxmemory",
                     "min-replicas-to-write", "repl-diskless-sync", "repl-backlog-size", "hz")

BIN_NAMES = {"proxy_deploy": "mcp-re-proxy-deploy", "proxy_ext": "mcp-re-proxy-ext",
             "bench": "tls_load_harness_bench", "rig": "saturation_rig",
             "backend": "saturation_backend", "loadgen": "saturation_loadgen"}


def binaries(bin_dir: Path) -> Binaries:
    paths = {k: (bin_dir / v).resolve() for k, v in BIN_NAMES.items()}
    missing = [str(p) for p in paths.values() if not os.access(p, os.X_OK)]
    if missing:
        raise SystemExit(f"ceiling: missing or non-executable instrument(s): {missing}")
    return Binaries(**paths)


def launchers(run_dir: Path, bins: Binaries, pool: int | None, isolation_plan: Path | None = None) -> Binaries:
    """The instruments with both proxies behind `proxy_launcher`; everything else as built."""
    out = run_dir / "launchers"
    out.mkdir(parents=True, exist_ok=True)
    return dataclasses.replace(bins, proxy_deploy=proxy_launcher(out, bins.proxy_deploy, pool, isolation_plan),
                               proxy_ext=proxy_launcher(out, bins.proxy_ext, pool, isolation_plan))


def redis_config(run_dir: Path, redis_url: str, tier: Tier | None) -> dict:
    """CONFIG GET * of every tier node reachable, written to redis/config.json; the manifest
    keeps the settings that decide durability and capacity."""
    nodes = {"primary": redis_url}
    if tier is not None:
        nodes.update({role: f"redis://127.0.0.1:{port}" for role, port in tier.ports.items() if role != "primary"})
    full = {role: config_get(url) for role, url in nodes.items()}
    write_json(run_dir / "redis" / "config.json", full)
    return {"file": "redis/config.json",
            "nodes": {role: ({k: c["config"].get(k) for k in REDIS_CONFIG_KEYS} if c["available"] else c)
                      for role, c in full.items()}}


def _replay_pool_record(pool: int | None) -> dict:
    return {"requested": pool, "expected": pool or DEFAULT_REPLAY_POOL,
            "flag": f"--replay-redis-pool-size {pool}" if pool else "omitted (the proxy's default)",
            "launchers": "launchers/*.sh — every proxy start goes through one; its startup "
                         f"transcript lands in ${STARTUP_LOG_ENV}"}


def _plan(args, sweep: tuple[int, ...]) -> dict:
    return {"sweep": sweep, "phase_a_topologies": {"scaling": "WORKERS_PER_SHARD=1, --cores N",
                                                    "shipped-auto": "--cores 0 --workers-per-shard 0 (proxy defaults)"},
            "phase_b": {"modes": args.b_modes, "repeats": args.b_repeats, "partitioned": args.partitioned,
                        "generator_cap": args.gen_cap, "connections_ladder": args.ladder,
                        "requests_per_connection": args.requests_per_connection,
                        "signer_retention_budget": SIGNER_RETENTION_BUDGET,
                        "rung_request_ceiling": RUNG_REQUEST_CEILING,
                        "requests_per_generator_cap": RUNG_REQUEST_CEILING // sum(range(2, args.gen_cap + 1)),
                        "stage_timers": args.stage_timers}}


def initial_manifest(args, bins: Binaries, sweep: tuple[int, ...], umasks: dict) -> dict:
    """The manifest written before the first measurement: identities, envelope, plan, rules."""
    identity = read_json(Path(args.identity)) if args.identity else {}
    build = read_json(Path(args.build_identity)) if args.build_identity else {}
    manifest = {
        "schema": "mcp-re-lightsail-ceiling-run/v1", "started": utc_now(), "hardware_class": HW_CLASS,
        **umasks,
        "identity": identity,
        "binaries": {k: {"path": str(getattr(bins, k)), "sha256": sha256_file(getattr(bins, k))} for k in BIN_NAMES},
        "envelope": {"concurrency": 128, "requests": 8000, "mode": "cold", "reps": args.reps,
                     "replay_tier": "redis-wait-quorum:2:2000 (primary + 2 replicas, appendonly yes, loopback)"},
        "replay_pool": _replay_pool_record(args.replay_redis_pool_size),
        "backend_success": "Phase B rungs and the rig smoke run with MCP_RE_SAT_REQUIRE_ECHO=1: a success is "
                           "a 2xx carrying the backend's echo",
        "plan": _plan(args, sweep),
        "rules": RULES,
    }
    manifest["build"] = build
    return manifest


def drifted_instruments(manifest: dict) -> list[str]:
    """Instruments whose SHA-256 differs from the build identity the bootstrap recorded."""
    built = manifest["build"].get("binaries", {})
    return [k for k, name in BIN_NAMES.items()
            if built and "sha256:" + built.get(name, "") != manifest["binaries"][k]["sha256"]]
