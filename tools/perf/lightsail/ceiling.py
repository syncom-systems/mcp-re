#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""MCP-RE scaling and ceiling experiment on one Linux host (the Lightsail 32-vCPU context).

Run on the measurement host, against binaries built from the released subject:

  ceiling.py campaign  RUN_DIR --bin-dir DIR --identity identity.json [--ports-toml F]
  ceiling.py inventory RUN_DIR [--expect-vcpus 32 --expect-arch x86_64 --expect-mem-gib 128]
  ceiling.py summarize RUN_DIR
  ceiling.py pack      RUN_DIR                            # final SHA256SUMS + RUN_DIR.tar.gz(.sha256)
  ceiling.py diagnose  RUN_DIR --bin-dir DIR --cores N   # perf pass, AFTER the authoritative run
  ceiling.py selftest                                     # local, no host, no cloud

The campaign: identity check -> replay tier up -> smoke -> Phase A (canonical cold-mTLS
harness, scaling topology 1..32, then the shipped auto topology) -> Phase B (saturation rig:
cold scaling sweep, repeats at the knee and the high-core region, keep-alive sweep, a
CPU-partitioned attribution sweep, the shipped auto topology) -> summary. Every step is
timed and logged into RUN_DIR; a failed point is recorded and the campaign continues, while a
host that is not the declared context, or a smoke that fails, stops it before the sweep.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Every file the instruments create is created under this mask. The proxy refuses a
# group-writable trust document, and an interactive Ubuntu login (the `ubuntu` user over SSH,
# then tmux) runs with umask 0002 — under that mask the harness's own trust file is refused
# and the smoke fails. The mask is part of the instrument's environment, so it is fixed here
# and recorded in the manifest next to the one inherited.
UMASK = 0o022
INHERITED_UMASK = os.umask(UMASK)
sys.path.insert(0, str(HERE))

from ceiling_cli import build_parser, run  # noqa: E402


def main(argv: list[str]) -> int:
    umasks = {"umask": f"{UMASK:04o}", "umask_inherited": f"{INHERITED_UMASK:04o}"}
    return run(build_parser().parse_args(argv), umasks)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
