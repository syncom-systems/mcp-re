#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bazel srcs gate — every file a library's module tree reaches is in its `srcs`.

`mcp-re-proxy` hand-lists its library sources (`_PROXY_LIB_SRCS`) because three library
flavors share the list, and a hand-list drifts: `src/audit_sink.rs` landed with the
ADR-MCPS-035 audit surface and was never added, so cargo built a module Bazel could not
find and every Bazel target downstream of the proxy library failed with E0583.

The semantic-drift gate compares TARGETS, not sources, so it passed. The only thing that
caught this was a full `bazel test //...` — 30+ minutes, and per its own commit message it
"had never once completed during this audit", which is exactly how the miss survived
several rounds of review.

This is that check at one second. The build graph's `srcs` for every library target come
from the committed target table, `verification/generated/rust-targets.json`, which
`tools/verification/rust-targets --check` holds to `bazel query`. The gate walks each
library's module tree from its crate root and requires that each reached file is in that
target's `srcs`, and that each listed file exists. A glob cannot drift, so a globbing
library passes by construction; checking it costs nothing and needs no exemption rule.

Two properties are load-bearing, because each one had a silent-blindness failure mode:

- **The `srcs` are the LIBRARY target's.** A test target compiling the library's sources,
  or a `data` glob over `src/`, satisfies nothing: the table row is the library's own.
- **The module tree is rustc's.** `tools/verification/_module_tree.py` owns it: both
  file forms, `#[path]`, inline modules, and declarations read from code only. A walk
  that stops at a resolved file observes nothing after the first file-to-directory
  split, which is precisely when a hand-list starts to drift.

The second hand list is the audit-vocabulary guard's: `CRATE_SOURCE_TREES` names the
crate packages it scans, `COMPILED_SOURCE_DIRS` the directories it walks in each, and each
package's `guard_src_files` glob the files its runfiles carry. A crate package missing from
the list, a file a crate target reaches outside those directories, or one the glob leaves
out of the runfiles, is a file the guard never reads while it reports a clean scan. Each is
checked against the module tree of every crate target the build graph compiles. The
`guard_src_files` filegroup is not a Rust target, so its glob is read from `BUILD.bazel`
and matched with `workflow_reader.glob_matches`, where `**` crosses `/` as Bazel's does.

Run:  python3 scripts/bazel_srcs_gate.py
      python3 scripts/bazel_srcs_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _bazel_srcs.cli import judge  # noqa: E402
from _bazel_srcs.config import GUARD, REPO, TARGET_TABLE  # noqa: E402,F401
from _bazel_srcs.libraries import check_libraries, check_library  # noqa: E402,F401
from _bazel_srcs.selftest import selftest  # noqa: E402,F401
from _bazel_srcs.source_trees import check_source_trees  # noqa: E402,F401
from _bazel_srcs.starlark import attribute_value, balanced  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return judge()


if __name__ == "__main__":
    sys.exit(main())
