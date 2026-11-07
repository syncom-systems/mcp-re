"""The argument parser: `pre` and `post`, with `post`'s extra journal and gate options."""
from __future__ import annotations

import argparse
import os

from _check_phases import cmd_post, cmd_pre

HERE = os.path.dirname(os.path.abspath(__file__))
GATE_SCRIPT = os.path.join(HERE, "bazel_gate.py")
PRESCAN_SCRIPT = os.path.join(HERE, "prescan.py")


def _add_common(p) -> None:
    p.add_argument("--file", required=True)
    p.add_argument("--tier", required=True, choices=["local", "wide", "platform"])
    p.add_argument("--store", required=True)
    p.add_argument("--related", default="", help="comma-separated importers (wide: their trees are gated too)")
    p.add_argument("--gate-script", default=GATE_SCRIPT, help=argparse.SUPPRESS)


def _add_post_only(p) -> None:
    p.add_argument("--log", required=True)
    p.add_argument("--attempt", required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--work-dir", required=True, help="where logs and prescan JSON go")
    p.add_argument("--applied", type=int, required=True)
    p.add_argument("--not-applied", type=int, required=True)
    p.add_argument("--tests-added", type=int, required=True)
    p.add_argument("--touched", default="", help="comma-separated files edited (default: --file)")
    p.add_argument("--model", default="")
    p.add_argument("--epoch", default="")
    p.add_argument("--note", default="", help="one line for the `fix` event")
    p.add_argument("--pyright-baseline-errors", type=int, default=0)
    p.add_argument("--it", default="", help="Rust: integration test targets (Bazel labels) the package named")
    p.add_argument("--keep-on-fail", action="store_true",
                   help="leave a new-failures change in the tree instead of reverting it")
    p.add_argument("--pyright-cmd", default=".venv/bin/pyright", help=argparse.SUPPRESS)
    p.add_argument("--prescan-script", default=PRESCAN_SCRIPT, help=argparse.SUPPRESS)


def build_parser(description: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=description)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("pre", cmd_pre), ("post", cmd_post)):
        p = sub.add_parser(name)
        _add_common(p)
        p.set_defaults(fn=fn)
        if name == "post":
            _add_post_only(p)
    return ap
