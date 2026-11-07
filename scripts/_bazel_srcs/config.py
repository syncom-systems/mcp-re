# SPDX-License-Identifier: Apache-2.0
"""Where the gate reads from: the repository root, the guard test and the committed target table."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))
sys.path.insert(0, str(REPO / "scripts"))

import _rust_targets  # noqa: E402

GUARD = Path("mcp-re-conformance") / "tests" / "audit_vocabulary_guard_test.rs"
TARGET_TABLE = Path(_rust_targets.TABLE_RELATIVE)
