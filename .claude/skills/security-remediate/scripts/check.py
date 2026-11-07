"""check.py — the worker's whole gate, and its journal events, in ONE call per phase.

(Invoked as `python3 check.py …`; no shebang — see reduce.py for why.)

WHY: the lane used to hand the worker its gate as prose with placeholders —
"<the nearest enclosing package src root>", "<//the/owning/tree/...>",
"<basename>" — plus four numbered steps. Each worker re-derived the paths, ran
prescan, pyright and `bazel_gate.py` as separate turns, read each output back,
then appended `fix`, `gate` and possibly `gate-failed` by hand. All of that is
mechanical, and every turn re-sent the agent's whole context.

Two phases, because a baseline is only honest if it is taken BEFORE the edit:

  pre   ensure a bazel baseline exists for every tree this file's gate will run
        (the owning tree; plus the dependents' trees at the `wide` tier). The
        worker holds the single-writer lane, so the tree is exactly "everything
        the lane has landed so far" — which is the right baseline. The previous
        instruction ("if no-baseline, run `baseline` first, then check") ran
        AFTER the edit, so any failure the edit caused was recorded as baseline
        debt and could never show up as `new-failures`.

  post  append `fix` with the worker's counts, format every touched .rs file with
        rustfmt (formatting is mechanical, so a writer is never failed for it), then run
          1. prescan over every touched file's src root — only hits naming a
             touched or related file are reported; the rest of the root is not
             this change's business
          2. Python: whole-repo pyright (`wide`/`platform`), error count vs the
             baseline, and `bazel_gate.py check` per tree.
             Rust: `rust_gate.py` — `bazel build --config=lint` over every target
             that compiles the file (plus the related files' targets above `local`),
             `bazel build --config=rustfmt` over the targets of every touched file,
             the module-size gate, the file's own unit tests in the unit-test targets
             built from those libraries, and any `--it` integration test target.
        and append `gate` (plus `gate-failed` when a gate BLAMES the change).
        Prints one verdict: new-failures > infra > no-baseline > ok. On
        new-failures the change is saved as a patch and reverted, so the next
        writer starts on a tree whose failures are its own.

  Rust `pre` stores no baseline: the lane starts on a tree `batch_gate.py`
  measured green and every writer leaves it green or reverted. It refuses when
  the file already carries uncommitted changes, which would make the diff under
  judgment more than this change.

What it does NOT do: regenerate barrels (it cannot tell whether an export
changed), or judge whether a prescan hit predates the change. Both stay with the
worker, and the prescan hits are printed for exactly that reason.

Usage:
  check.py pre  --file F --tier local|wide --store <gates> [--related a,b]
  check.py post --file F --tier local|wide --store <gates> --log <progress> \\
                --attempt A --run R --work-dir <dir> \\
                --applied N --not-applied N --tests-added N \\
                [--touched a,b] [--related a,b] [--model M] [--epoch E] \\
                [--pyright-baseline-errors 0]
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _check_cli import build_parser  # noqa: E402
from _check_gates import gate_summary  # noqa: E402,F401 — the tests import it from here
from _check_revert import format_touched as _format  # noqa: E402,F401 — the tests import it from here
from _check_revert import revert as _revert  # noqa: E402,F401 — the tests import it from here


def main() -> int:
    a = build_parser(__doc__.splitlines()[0]).parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
