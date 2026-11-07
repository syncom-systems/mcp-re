#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render a tracked cloud-configuration template to an UNTRACKED file under `work/`.

THE FAILURE CLASS. The EKS runbook told the operator to run
`sed -i "s|OPERATOR_CIDR|…|" deploy/eks/mcp-re-slo-cluster.yaml`. Three defects in one line:
it rewrites a TRACKED file in place (the run's address lands in the working tree, one
`git commit -a` from being published, and the template is gone for the next run); BSD `sed`
reads `-i "s|…|"` as a backup suffix and fails on macOS; and nothing preserves the exact file
`eksctl create` consumed, so teardown runs against whatever the file says by then.

The rule this tool enforces for every cloud configuration that needs substitution:
  * the tracked template is never modified — placeholders are `@@NAME@@` and stay there;
  * the rendered file goes to `work/cloud-runs/<run-id>/`, which git ignores, and is
    refused anywhere else;
  * an unresolved placeholder, an open-to-the-world network (`0.0.0.0/0`, `::/0`) and an
    invalid or prefix-0 `*_CIDR` value are refused;
  * a `*_CIDRS` value is a list of APPROVED SOURCE ADDRESSES — comma-separated, each one a
    single host (`/32` or `/128`), at most eight, no duplicates. Its placeholder sits inside
    one quoted JSON list element (`["@@OPERATOR_CIDRS@@"]`) and renders as one element per
    address. An operator whose traffic leaves from more than one public address lists every
    one of them; a wider range is never the answer;
  * the rendered bytes are kept, never overwritten, with a manifest recording the template
    digest, the values and the rendered digest — `--verify` re-checks them before teardown,
    so teardown provably uses the file creation used.

Run:  python3 tools/cloud/render_cloud_config.py --template T --run-id ID --set NAME=VALUE ...
      python3 tools/cloud/render_cloud_config.py --verify work/cloud-runs/ID/<file>
      python3 tools/cloud/render_cloud_config.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _cloud_render.cli import run  # noqa: E402
from _cloud_render.selftest import selftest  # noqa: E402

REPO = Path(__file__).resolve().parent.parent.parent


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    return run(argv, REPO)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
