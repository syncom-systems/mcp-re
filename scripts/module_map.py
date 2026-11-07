#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The mcp-re-proxy module map: planes, production edges, and misplaced responsibilities.

This is EVIDENCE FOR an architecture model, not the model itself. Two distinct failure
modes have already occurred and they are worth keeping apart:

  * MEASUREMENT — the scan omitted edges. Truncating a file at its first `#[cfg(test)]`
    discarded 500-900 lines of production code in fifteen files, hid three real `cli`
    dependencies, and dropped a production `SystemTime::now()` out of `boundary.clock`.
  * CLASSIFICATION — the edges were right and their meaning was wrong. `config_snapshot`
    and `runtime_state` were filed under `startup` because of where they sit rather than
    what they are, inflating "back-edges into startup" by eight.

So the workflow is: measure -> validate the measurement -> classify -> review the
classification -> plan. Never: run script -> refactor until the number falls.

Both measurement failures biased the count DOWNWARD. That is the dangerous direction
here: it makes the remaining architecture look cleaner and the work smaller than it is.
No systematic cause is claimed; the bias is recorded because it is the direction to
distrust.

Run:  python3 scripts/module_map.py            # the map
      python3 scripts/module_map.py --edges    # every production edge, with symbols
      python3 scripts/module_map.py --selftest # validate the instrument
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _module_map.cli import run  # noqa: E402
from _module_map.config import (  # noqa: E402,F401
    COMPOSITION,
    LEGITIMATE,
    MISPLACED_OWNERSHIP,
    PLANE_OF,
    PLANES,
    REPO,
    SRC,
)
from _module_map.graph import build_map, code_only, edges_for  # noqa: E402,F401
from _module_map.selftest import selftest  # noqa: E402


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return run()


if __name__ == "__main__":
    sys.exit(main())
