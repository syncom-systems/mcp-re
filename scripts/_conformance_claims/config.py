# SPDX-License-Identifier: Apache-2.0
"""Where the claims live and the patterns that read them."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

GUIDE = "docs/conformance-guide.md"
VECTORS_ROOT = "mcp-re-conformance/tests/vectors"

# The table is delimited so prose may name a corpus or a target freely; only rows
# between the markers are claims this gate reads.
BEGIN = "<!-- conformance-categories:begin -->"
END = "<!-- conformance-categories:end -->"

# `| HTTP profile | `a/b/` | `//pkg:t`, `//pkg:u` |`
ROW = re.compile(r"^\|(?P<cells>.+)\|\s*$")
BACKTICKED = re.compile(r"`([^`]+)`")

# `nt_rust_test(\n    name = "x",\n    ...\n)` — declarations are top-level, so the
# block ends at the first `)` in column 0.
TEST_BLOCK = re.compile(r"nt_rust_test\((?P<body>.*?)\n\)", re.S)
TARGET_NAME = re.compile(r'name = "([^"]+)"')
SRCS_ENTRY = re.compile(r'"([^"]+\.rs)"')
