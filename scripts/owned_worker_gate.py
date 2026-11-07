#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned-worker gate — no unreviewed direct thread spawn in production code.

WHAT THIS PROVES, exactly: no library source outside `managed_worker/mod.rs`, in any crate in
the repository (including the `sdk/python` and `sdk/typescript` native bindings), starts
an OS thread through `thread::spawn` or `thread::Builder` except in test code or at one of
the exact reviewed sites counted below. That is a syntactic check on two spellings, and
the claim stops there.

WHAT IT DOES NOT PROVE: that no detached runtime worker exists. A helper that wraps the
spawn, a type alias, a re-export, a `tokio::spawn` or `Runtime::spawn` task, or a thread
started inside a dependency all pass it untouched. Keeping the contract narrow is
deliberate — this gate is not a Rust compiler, and overstating it would be worse than
not having it, because the overstatement is what stops people looking. The real
enforcement is that runtime-owned work goes through `WorkerSet`; this gate makes the
common bypass loud.

WHY. ADR-MCPRE-056 §9: no startup phase may spawn a long-lived thread whose lifetime is
not represented by an owned value. A bare `std::thread::spawn(..)` whose `JoinHandle` is dropped outlives every
value it was conceptually part of: nothing can stop it, and nothing can observe that it
stopped. Startup had four of them — trust reload, client CRL reload, delegated key
rotation, trust-epoch poll — each looping on the caller's SIGTERM flag, which no error
path sets. A `run` that failed after the first spawn returned `Err` with threads still
reading files and minting keys.

They are now owned by `managed_worker::WorkerSet`. This gate is what keeps them that way,
because the invariant does not survive as a habit: the fourth was found by accident, days
after a survey that swept one file and concluded there were three.

Tokio tasks on the per-core serving runtimes are a different lifetime question — the
fleet owns its runtimes and joins them on drain — and are deliberately out of scope.

Run:  python3 scripts/owned_worker_gate.py
      python3 scripts/owned_worker_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _owned_worker.check import check  # noqa: E402,F401
from _owned_worker.cli import verdict  # noqa: E402
from _owned_worker.config import ALLOWED, OWNER_MODULE, REPO, SPAWN  # noqa: E402,F401
from _owned_worker.scan import crates, production_spawns  # noqa: E402,F401
from _owned_worker.selftest import selftest  # noqa: E402


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return verdict()


if __name__ == "__main__":
    sys.exit(main())
