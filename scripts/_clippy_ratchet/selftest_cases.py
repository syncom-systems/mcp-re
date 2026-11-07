# SPDX-License-Identifier: Apache-2.0
"""Selftest cases: what the comparison and the allow discipline must say about each input."""

from __future__ import annotations

from collections import Counter

BASELINE = {"crate-a::expect_used": 5}
_AT_BASE = {"crate-a::expect_used": 5}

#: (measured counts, phrase some problem must contain — None when there must be NO problem,
#: the failure to report when that is not so)
COMPARE_CASES = (
    (Counter({"crate-a::expect_used": 5}), None,
     "a crate at its baseline reported a problem"),
    (Counter({"crate-a::expect_used": 6}), "only turns one way",
     "growth past the baseline was not caught"),
    (Counter({"crate-a::expect_used": 3}), "lower the baseline",
     "an improvement did not demand a lower baseline"),
    # A lint with no baseline entry is denied at zero.
    (Counter({**_AT_BASE, "crate-b::indexing_slicing": 1}), "baseline 0",
     "an unbaselined lint occurrence was not denied at zero"),
    # unwrap_used is deny-at-zero and must be caught even though it is not in RATCHETED.
    (Counter({**_AT_BASE, "crate-b::unwrap_used": 1}), "unwrap_used",
     "unwrap_used was not denied at zero"),
    # Lints outside the adopted set are ignored, not silently counted.
    (Counter({**_AT_BASE, "crate-b::cognitive_complexity": 99}), None,
     "a lint outside the adopted set was counted"),
    # A baseline the tree no longer reaches must be lowered, not silently accepted.
    (Counter(), "lower the baseline", "a vanished baseline entry was accepted"),
)

#: (source of one `.rs` file, phrase some problem must contain — None when there must be NONE,
#: the failure to report; `{problems}` is filled with what was found)
ALLOW_CASES = (
    ("#![allow(clippy::arithmetic_side_effects)]\nfn a() {}\n", "crate- or module-wide",
     "a crate-wide allow was accepted"),
    ("#[allow(clippy::unwrap_used)]\nmod inner {}\n", "on a module",
     "a module-scoped allow was accepted"),
    ("#[allow(clippy::expect_used)]\nfn a() {}\n", "no justification",
     "an unjustified item allow was accepted"),
    ("// bounded by FreshnessWindow::verifier_accepts_until\n"
     "#[allow(clippy::expect_used)]\nfn a() {}\n", None,
     "a justified item allow was rejected: {problems}"),
    ("#[allow(clippy::expect_used)] // invariant: checked in classify()\n"
     "fn a() {}\n", None,
     "a trailing-comment justification was rejected"),
    # A lint outside the adopted set is none of this gate's business.
    ("#![allow(clippy::collapsible_if)]\nfn a() {}\n", None,
     "an unadopted lint's allow was policed"),
)

#: What the table's projection must keep: the two shipping rows of the fixture below.
PROJECTION_FIXTURE = {
    "//a:a": {"kind": "rust_library", "manual": False, "testonly": False},
    "//a:a_pre052": {"kind": "rust_library", "manual": False, "testonly": True},
    "//a:a_fault": {"kind": "rust_library", "manual": False, "testonly": True},
    "//a:cli": {"kind": "rust_binary", "manual": False, "testonly": False},
    "//a:probe": {"kind": "rust_library", "manual": True, "testonly": False},
    "//a:a_test": {"kind": "rust_test", "manual": False, "testonly": True},
    "//a:native": {"kind": "rust_shared_library", "manual": False, "testonly": False},
}
