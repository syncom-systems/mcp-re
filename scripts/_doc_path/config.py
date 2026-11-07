# SPDX-License-Identifier: Apache-2.0
"""What the doc-path gate reads, what it excludes and how it recognises a path token."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "config" / "doc-path-debt.toml"

sys.path.insert(0, str(REPO / "tools" / "verification"))

# Each names a category of DATED RECORD, for which a dead path is correct — an audit is
# not falsified by a later deletion — except `.claude/**`, which is vendored third-party
# skill text and not this project's claim surface. `CLAUDE.md` is deliberately absent:
# it is this repository's normative standards document, so it is the single file whose
# dead path would be most expensive, and excluding it to absorb one `e.g.` token would
# buy one registry row at the cost of the file's coverage forever.
SCOPE_EXCLUDE = (
    "docs/archive/**",
    "**/archive/**",
    "CHANGELOG*",
    "work/**",
    "docs/security/**",
    "verification/**",
    "tools/verification/**",
    "docs/adr/**",
    "docs/releases/**",
    "*.lock",
    "MODULE.bazel.lock",
    ".claude/**",
)

# At least one `/`, and a known source extension. Anything without a `/`, and anything
# with an unknown extension, is not a token — that is what keeps prose out. The trailing
# lookahead is what makes the extension the END of the name rather than a substring of
# it: without it `scripts/test-aws-cloud.sh.example` yields a token for a `.sh` file that
# was never named, and the gate reports a dead path nobody wrote. A sentence-final `.`
# still ends a token, because the lookahead only refuses a dot that a name continues
# past.
TOKEN = re.compile(
    r"(?<![\w/.@-])((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+"
    r"\.(?:rs|py|sh|toml|yaml|yml|json|md|bazel|ts|tsx))(?!\.?[A-Za-z0-9_-])"
)

FENCE = re.compile(r"^\s*(?:```|~~~)\s*([A-Za-z0-9_+-]*)")
HEADING = re.compile(r"^#{1,6}\s")
SHA_ANCHOR = re.compile(r"@\s*`[0-9a-f]{7,40}`")
STRIKE = re.compile(r"~~(.+?)~~")

# A path in EXECUTABLE code is not a claim about this repository's contents: a gate's
# `--selftest` writes a synthetic crate into a temporary tree, and those paths are
# SUPPOSED not to exist here. What a source file states about this repository it states in its
# comments — the crate header, the `//!` module doc, the `# why this pin exists` above a
# dependency — so in a code file this gate reads comment lines and nothing else. A Python
# or Rust doc STRING is therefore unread; the cost is stated here rather than discovered.
CODE_SUFFIXES = (".rs", ".py", ".sh", ".ts", ".tsx")
COMMENT = re.compile(r"^\s*(?://|#|\*|/\*)")

MAX_BYTES = 2_000_000
