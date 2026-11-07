# SPDX-License-Identifier: Apache-2.0
"""Where the committed targets live, the exit status for an unanchored report, and the
one owner of the hardware-class vocabulary."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_TARGETS = REPO_ROOT / "docs/bench/adr-051-slo-targets.json"

#: Not a regression and not a usage error — a report this gate has no anchor for.
NOT_COMPARABLE = 4

# The declared class vocabulary has ONE owner (the file that declares the measurement
# context), and this gate reads it rather than keeping a second copy that could disagree
# about which class an anchor belongs to.
sys.path.insert(0, str(REPO_ROOT / "scripts"))
