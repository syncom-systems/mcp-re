# SPDX-License-Identifier: Apache-2.0
"""The command line of `ceiling.py`: its arguments, and what each subcommand runs."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ceiling_campaign import campaign
from ceiling_diagnose import diagnose
from ceiling_seal import finish, pack
from common import read_json, write_json
from hostfacts import check_expected, inventory

HERE = Path(__file__).resolve().parent
SWEEP = (1, 2, 4, 8, 16, 24, 32)
REPLAY_POOL_MAX = 128
PORTS_TOML = str(HERE.parent.parent.parent / "config" / "ports.toml")


def replay_pool(value: str) -> int:
    """`--replay-redis-pool-size`, refused here outside the range the proxy admits, so a typo
    costs nothing rather than a failed smoke on a paid host."""
    try:
        pool = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be an integer, got {value!r}") from None
    if not 1 <= pool <= REPLAY_POOL_MAX:
        raise argparse.ArgumentTypeError(f"must be between 1 and {REPLAY_POOL_MAX}, got {pool}")
    return pool


def _expectations(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bundle")
    parser.add_argument("--expect-vcpus", type=int)
    parser.add_argument("--expect-arch")
    parser.add_argument("--expect-mem-gib", type=float)


def _campaign_parser(sub) -> None:
    c = sub.add_parser("campaign")
    c.add_argument("run_dir")
    c.add_argument("--bin-dir", required=True)
    c.add_argument("--identity")
    c.add_argument("--build-identity")
    c.add_argument("--ports-toml", default=PORTS_TOML)
    c.add_argument("--redis-url", help="use an operator-managed replay tier instead of starting one")
    c.add_argument("--cores", default=",".join(map(str, SWEEP)))
    c.add_argument("--reps", type=int, default=6)
    c.add_argument("--b-modes", default="cold,keepalive")
    c.add_argument("--b-repeats", type=int, default=3)
    c.add_argument("--isolate-replay-path", action="store_true",
                   help="reserve whole physical cores for the Redis primary and the proxy's control "
                        "runtime (isolation.py); everything else runs on the remaining CPUs")
    c.add_argument("--stage-timers", action="store_true",
                   help="set MCP_RE_STAGE_TIMERS for every Phase B rung: the proxy's own per-stage wall "
                        "times (replay SET+WAIT round trip, scheduler latency, replay calls in flight)")
    c.add_argument("--partitioned", default="1,2,4,8,16")
    c.add_argument("--ladder", default="256,512,1024,2048", help="rig connections per generator, climbed on CLIENT")
    c.add_argument("--gen-cap", type=int, default=12, help="rig --max-generators; keep < 20 (see phases.py)")
    c.add_argument("--requests-per-connection", type=float, default=40000 / 256)
    _expectations(c)
    c.add_argument("--require-telemetry", action="store_true")
    c.add_argument("--replay-redis-pool-size", type=replay_pool,
                   help="passed to every proxy start; omitted, the proxy's default (8) applies")


def _diagnose_parser(sub) -> None:
    d = sub.add_parser("diagnose")
    d.add_argument("run_dir")
    d.add_argument("--bin-dir", required=True)
    d.add_argument("--cores", type=int, required=True)
    d.add_argument("--workers", type=int, default=1)
    d.add_argument("--mode", default="cold")
    d.add_argument("--generators", type=int, default=8)
    d.add_argument("--connections", type=int, default=256)
    d.add_argument("--warmup", type=float, default=5.0, help="seconds after the proxy appears before sampling")
    d.add_argument("--window", type=int, default=30, help="perf record window, seconds")
    d.add_argument("--ports-toml", default=PORTS_TOML)
    d.add_argument("--replay-redis-pool-size", type=replay_pool)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ceiling.py")
    sub = parser.add_subparsers(dest="cmd", required=True)
    _campaign_parser(sub)
    i = sub.add_parser("inventory")
    i.add_argument("run_dir")
    _expectations(i)
    s = sub.add_parser("summarize")
    s.add_argument("run_dir")
    _diagnose_parser(sub)
    k = sub.add_parser("pack")
    k.add_argument("run_dir")
    sub.add_parser("selftest")
    return parser


def _inventory(args) -> int:
    facts = inventory(args.bundle)
    problems = check_expected(facts, args.expect_vcpus, args.expect_arch, args.expect_mem_gib)
    write_json(Path(args.run_dir) / "host" / "inventory.json", dict(facts, identity_problems=problems))
    print(json.dumps({"vcpus": facts["vcpus_usable"], "arch": facts["architecture"],
                      "cpu": facts["cpu_model"], "problems": problems}))
    return 3 if problems else 0


def _summarize(args) -> int:
    run_dir = Path(args.run_dir)
    vcpus = read_json(run_dir / "host" / "inventory-before.json").get("vcpus_usable") or os.cpu_count() or 1
    print(finish(run_dir, vcpus)["ceiling"]["statement"])
    return 0


def _pack(args) -> int:
    print(pack(Path(args.run_dir).resolve()))
    return 0


def _selftest(args) -> int:
    from selftest import run_all
    return run_all()


def run(args: argparse.Namespace, umasks: dict) -> int:
    """Dispatch the parsed command; `umasks` is what the campaign records about the mask."""
    if args.cmd == "campaign":
        return campaign(args, umasks)
    commands = {"inventory": _inventory, "summarize": _summarize, "diagnose": diagnose,
                "pack": _pack}
    return commands.get(args.cmd, _selftest)(args)
