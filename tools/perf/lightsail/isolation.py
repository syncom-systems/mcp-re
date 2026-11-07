# SPDX-License-Identifier: Apache-2.0
"""CPU isolation for the replay path: whole physical cores for the Redis primary and the
proxy's control runtime, everything else kept off them.

WHY A LAUNCH-TIME MASK IS NOT ENOUGH. The proxy pins each serving shard's thread to the
ABSOLUTE CPU `core_index % online_cpus` (`async_fleet/mod.rs::pin_current_thread_to_core`),
which overrides a mask it was started under; and the control runtime (`mcp-re-control`,
the one thread that drives the replay store's Redis connections) is a thread of the same
process. So the isolation is applied per THREAD after the proxy starts, by `enforce`, which
the proxy launcher runs beside every proxy it starts.

THE PLAN, from the host's own topology. Logical CPU numbers are not assumed to be
independent cores: `topology()` reads each CPU's `thread_siblings_list`, and the plan
reserves WHOLE physical cores — one for the Redis primary, one for the control thread —
running each on one logical CPU and leaving its SMT sibling idle. The general set is every
other logical CPU: serving threads, the proxy's other threads, the replicas, the rig, its
generators and backend, and the canonical bench all run there.

`enforce` sets, for every thread of the proxy, as threads appear:
  * `mcp-re-control`                       -> the control CPU;
  * a thread already confined to the general set (a serving shard pinned to a general CPU)
                                           -> left exactly as the proxy pinned it;
  * any other thread (a shard pinned to a reserved CPU, the main thread, audit, retention,
    a blocking-pool thread)                -> the whole general set.
Each change and each thread's resulting `Cpus_allowed_list` is logged.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

SYS_CPU = Path("/sys/devices/system/cpu")
CONTROL_THREAD = "mcp-re-control"


def parse_cpulist(text: str) -> list[int]:
    """`0-3,8,10-11` -> [0, 1, 2, 3, 8, 10, 11]."""
    out: list[int] = []
    for part in text.strip().split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        out.extend(range(int(lo), int(hi or lo) + 1))
    return sorted(set(out))


def cpulist(cpus: list[int]) -> str:
    return ",".join(str(c) for c in sorted(cpus))


def topology(root: Path = SYS_CPU) -> list[list[int]]:
    """Physical cores as sorted lists of their online logical CPUs, from sysfs."""
    online = parse_cpulist((root / "online").read_text())
    cores = {tuple(parse_cpulist((root / f"cpu{c}" / "topology" / "thread_siblings_list").read_text()))
             for c in online}
    return sorted((sorted(set(core) & set(online)) for core in cores), key=lambda core: core[0])


def plan(cores: list[list[int]]) -> dict:
    """Reserve the two highest-numbered physical cores: one for the Redis primary, one for
    the control thread, each on its core's first logical CPU with the sibling left idle."""
    if len(cores) < 4:
        raise ValueError(f"{len(cores)} physical cores: too few to reserve two and keep serving")
    redis_core, control_core = cores[-2], cores[-1]
    reserved = sorted(redis_core + control_core)
    general = sorted(c for core in cores for c in core if c not in reserved)
    return {"physical_cores": cores, "redis_primary": [redis_core[0]], "control": [control_core[0]],
            "reserved": reserved, "idle_siblings": sorted(redis_core[1:] + control_core[1:]),
            "general": general}


def target(comm: str, allowed: list[int], p: dict) -> list[int]:
    """The CPUs one proxy thread belongs on (see the module doc)."""
    if comm.startswith(CONTROL_THREAD):
        return p["control"]
    if allowed and set(allowed) <= set(p["general"]):
        return allowed
    return p["general"]


def allowed_of(pid: int, tid: int) -> list[int]:
    for line in Path(f"/proc/{pid}/task/{tid}/status").read_text().splitlines():
        if line.startswith("Cpus_allowed_list:"):
            return parse_cpulist(line.split(":", 1)[1])
    return []


def pin_process(pid: int, cpus: list[int]) -> list[dict]:
    """Every thread of `pid` onto `cpus` (threads created later inherit it)."""
    done = []
    for tid in sorted(int(t) for t in os.listdir(f"/proc/{pid}/task")):
        os.sched_setaffinity(tid, cpus)
        done.append({"tid": tid, "allowed": cpulist(allowed_of(pid, tid))})
    return done


class _Enforcer:
    """The state of one `enforce` run: what each thread was last seen as, and whether the
    thread set has settled and been snapshotted."""

    def __init__(self, pid: int, plan_: dict, sink, settle_s: float) -> None:
        self._pid = pid
        self._plan = plan_
        self._sink = sink
        self._settle_s = settle_s
        self._seen: dict[int, str] = {}
        self._stable_since = time.time()
        self._snapshotted = False

    def run(self) -> None:
        while os.path.exists(f"/proc/{self._pid}"):
            try:
                tids = sorted(int(t) for t in os.listdir(f"/proc/{self._pid}/task"))
            except OSError:
                break
            self._tick(tids)
            time.sleep(0.2)

    def _write(self, record: dict) -> None:
        self._sink.write(json.dumps({"t": time.time(), **record}) + "\n")
        self._sink.flush()

    def _tick(self, tids: list[int]) -> None:
        changed = any([self._visit(tid) for tid in tids])
        if changed:
            self._stable_since, self._snapshotted = time.time(), False
        elif not self._snapshotted and time.time() - self._stable_since >= self._settle_s:
            self._snapshot()
            self._snapshotted = True

    def _visit(self, tid: int) -> bool:
        """Move one thread onto its target; True when it moved or its name changed."""
        try:
            comm, moved = self._align(tid)
        except OSError:
            return False
        remembered = self._seen.get(tid) != comm
        self._seen[tid] = comm
        return moved or remembered

    def _align(self, tid: int) -> tuple[str, bool]:
        comm = Path(f"/proc/{self._pid}/task/{tid}/comm").read_text().strip()
        allowed = allowed_of(self._pid, tid)
        want = target(comm, allowed, self._plan)
        if allowed == want:
            return comm, False
        os.sched_setaffinity(tid, want)
        self._write({"tid": tid, "comm": comm, "from": cpulist(allowed), "to": cpulist(want)})
        return comm, True

    def _snapshot(self) -> None:
        self._write({"snapshot": [
            {"tid": t, "comm": c, "allowed": cpulist(allowed_of(self._pid, t))}
            for t, c in sorted(self._seen.items()) if os.path.exists(f"/proc/{self._pid}/task/{t}")]})


def enforce(pid: int, p: dict, log: Path, settle_s: float = 5.0) -> None:
    """Apply `target` to every thread of `pid` until it exits; log changes and, once the
    thread set has been stable for `settle_s`, a snapshot of every thread's mask."""
    with open(log, "a") as sink:
        _Enforcer(pid, p, sink, settle_s).run()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="isolation.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enforce")
    e.add_argument("--pid", type=int, required=True)
    e.add_argument("--plan", type=Path, required=True)
    e.add_argument("--log", type=Path, required=True)
    sub.add_parser("plan")
    args = ap.parse_args(argv)
    if args.cmd == "plan":
        print(json.dumps(plan(topology()), indent=2))
        return 0
    enforce(args.pid, json.loads(args.plan.read_text()), args.log)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
