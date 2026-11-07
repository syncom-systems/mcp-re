# SPDX-License-Identifier: Apache-2.0
"""Each drift shape the gate exists to catch goes red; each managed shape stays clean.

The fixtures are gazelle diffs written by hand, so the selftest needs no Bazel.
"""

from __future__ import annotations

from _bazel_gazelle.classify import classify
from _bazel_gazelle.config import ALLOW_TRACKED_DRIFT, ALLOWLIST

HEAD = "--- a/x/BUILD.bazel\n+++ b/x/BUILD.bazel\n@@ -1,9 +1,9 @@\n"
TARGET = (
    HEAD
    + '+nt_rust_test(\n+    name = "forgotten_test",\n+    srcs = ["tests/forgotten_test.rs"],\n+)\n'
)
EDGE = HEAD + ' nt_rust_library(\n     deps = [\n+        "//mcp-re-core:mcp_re_core",\n     ],\n )\n'
REORDER = (
    HEAD
    + ' nt_rust_library(\n     deps = [\n-        "//a:a",\n         "//b:b",\n+        "//a:a",\n     ],\n )\n'
)
WHOLE_ATTR = HEAD + '+deps = [\n+    "//c:c",\n+],\n'
KEEP = HEAD + '     deps = [\n+        "//d:d",  # keep\n     ],\n'
FLAVOR = HEAD + '     deps = [\n+        "//mcp-re-host:mcp_re_host",\n     ],\n'


def _cases(tracked_name: str) -> list[tuple[str, str, bool]]:
    allowed_name = next(iter(sorted(ALLOWLIST - set(ALLOW_TRACKED_DRIFT))))
    return [
        ("a Cargo target missing from BUILD", TARGET, True),
        ("a dep edge a `use` implies and BUILD omits", EDGE, True),
        ("a reordered deps list", REORDER, False),
        ("a whole-attribute rewrite of an unmergeable form", WHOLE_ATTR, False),
        ("a `# keep` edge", KEEP, False),
        ("a plain edge beside a kept feature flavor", FLAVOR, False),
        ("an allowlisted target", TARGET.replace("forgotten_test", allowed_name), False),
        ("tracked drift", TARGET.replace("forgotten_test", tracked_name), False),
        ("an empty diff", "", False),
    ]


def _run_case(label: str, diff: str, drift: bool, tracked_name: str) -> int:
    targets, edges, hits = classify(diff)
    got = bool(targets or edges)
    ok = got == drift
    if label == "tracked drift":
        ok = ok and hits == {tracked_name}
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}: {'drift' if got else 'clean'}")
    return int(not ok)


def selftest() -> int:
    tracked_name = next(iter(sorted(ALLOW_TRACKED_DRIFT)))
    failures = sum(_run_case(*case, tracked_name) for case in _cases(tracked_name))
    if failures:
        print(f"bazel-gazelle-gate selftest: FAIL ({failures})")
        return 1
    print("bazel-gazelle-gate selftest: PASS")
    return 0
