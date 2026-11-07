"""The per-job lock holder. `host_locks` explains why it exists; this is the process.

    lock_holder.py --root R --mirror M --key K --plan {ordinary,heavy,slo}
                   --watch WORKER_PID --hook HOOK_PID --ready-fd FD
                   --bounds '{"gate_wait": s, "heavy_wait": s, "drain_wait": s}'

Structure, and why:

  * The exit watches are registered on kqueue BEFORE any lock is requested. A watched pid
    that is already gone makes registration fail, and the holder exits without taking
    anything -- so a job that died before admission can never end up holding a lock.
  * Locks are taken by a helper thread in blocking `flock` calls (`lock_holder_take`). The
    main thread never blocks on a lock: it waits in kqueue (`lock_holder_session`), so the
    moment the worker (or, before admission, the hook) exits, it wakes and ends the process
    -- even while the thread is still queued for a lock, whose pending request the kernel
    then discards.
  * Every exit is `os._exit`. The locks are released by the kernel when the process ends;
    no code path has to remember to release them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lock_holder_session import Holder, HolderConfig  # noqa: E402


def parse_config(argv: list[str] | None) -> HolderConfig:
    ap = argparse.ArgumentParser()
    for flag in ("--root", "--mirror", "--key", "--plan", "--bounds"):
        ap.add_argument(flag, required=True)
    ap.add_argument("--record", default="{}")
    for flag in ("--watch", "--hook", "--ready-fd"):
        ap.add_argument(flag, type=int, required=True)
    a = ap.parse_args(argv)
    return HolderConfig(root=Path(a.root), mirror=Path(a.mirror), key=a.key, plan=a.plan,
                        bounds=json.loads(a.bounds), record=a.record, watch=a.watch,
                        hook=a.hook, ready_fd=a.ready_fd)


def main(argv: list[str] | None = None) -> None:
    Holder(parse_config(argv)).run()


if __name__ == "__main__":
    main()
