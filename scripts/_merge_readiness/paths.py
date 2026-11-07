# SPDX-License-Identifier: Apache-2.0
"""Where the gate reads from. Importing this module also makes the verification tooling
(`_affected`, `_evidence`, `_lanes`, `_manifest`, `_registries`) importable."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

_TOOLING = str(REPO / "tools" / "verification")
if _TOOLING not in sys.path:
    sys.path.insert(0, _TOOLING)
