# SPDX-License-Identifier: Apache-2.0
"""The production view of a Rust source file, and the walk that finds the files.

The one owner of two questions every source-reading gate asks:

  * **which lines of a file are production** — every line NOT inside a test region. A region
    opens at a line whose attribute matches `^#[cfg((all()?test` and closes with the item that
    attribute introduces: at the matching close brace of a braced item, or at the `;` of an
    item with no braces (a `const`, a `use`, a type alias). Counting resumes afterwards, and a
    file may hold several regions. Braces are counted over CODE characters only, carried across
    lines: a brace inside a string, a raw string, a char literal or a comment is not a brace.
    ADR-MCPRE-061 §5.1 describes this rule; this module defines it.

  * **which files are production Rust** — every `.rs` under a root, minus build outputs,
    vendored trees, `tests/`, `benches/`, `examples/` and `build.rs`.

Each consumer then asks only its own question of the view: a count, a vocabulary, a call
site, a `mod` declaration. Two projections serve those questions. `code()` blanks comments
AND literals, for a gate whose claim is about tokens the compiler sees (`thread::spawn`,
`crate::x::Y`, `getrandom`). `without_comments()` blanks comments and KEEPS literals, for a
gate whose claim includes a header name or an error string. Both keep line structure, so a
finding still names the line it came from.

The rule is also stated in Rust by `mcp-re-test-paths/src/rust_source.rs`, for the gates that
run as Rust tests. The two decide the same fact and must not drift.

Run:  python3 tools/verification/_rust_source.py --selftest
"""

from __future__ import annotations

import sys

from _rust_source_lex import code_only  # noqa: F401 — public: the gates import it from here
from _rust_source_selftest import REGION_CASES, selftest  # noqa: F401
from _rust_source_view import TEST_ATTR, ProductionView, production_view  # noqa: F401
from _rust_source_walk import NON_PRODUCTION_DIRS, SKIP_DIRS, crate_sources  # noqa: F401

if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else 0)
