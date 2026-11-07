# SPDX-License-Identifier: Apache-2.0
"""The files the gate compares and the facts about them it holds fixed."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
MODULE = REPO / "MODULE.bazel"
BAZEL_LOCK = REPO / "bazel" / "crates.lock"
CARGO_LOCK = REPO / "Cargo.lock"
MODULE_LOCK = REPO / "MODULE.bazel.lock"
# The synthetic package crate_universe writes into the lock to hold the specs.
SPLICE_ROOT = "direct-cargo-bazel-deps"
FIX = ("declare the change in MODULE.bazel's crate.spec, then seed bazel/crates.lock with the "
       "Cargo locks' packages (the root lock and each EXTRA_WORKSPACES lock, merged) and "
       "re-pin:\n    CARGO_BAZEL_REPIN=1 bazel mod show_extension "
       "@rules_rust//crate_universe:extension.bzl%crate\n"
       "then run one plain `bazel mod show_extension` so MODULE.bazel.lock records the repin "
       "inputs unset")

#: The crate extension's entry in MODULE.bazel.lock, and the repin-only inputs it records.
CRATE_EXTENSION = "@@rules_rust+//crate_universe:extension.bzl%crate"
REPIN_INPUTS = ("CARGO_BAZEL_REPIN", "CARGO_BAZEL_REPIN_ONLY", "REPIN")
UNSET = "\\0"

SPEC_BLOCK = re.compile(r"^crate\.spec\((.*?)^\)", re.M | re.S)

#: Separate Cargo workspaces whose crate Bazel builds, each with its own lock.
EXTRA_WORKSPACES = ("sdk/python", "sdk/typescript")

#: Specs no manifest requests, each with why the Bazel build needs it anyway. Their locked
#: packages are exempt from LOCKS for the same reason: no Cargo lock can hold them.
BAZEL_ONLY_SPECS: dict[str, str] = {
    "pyo3-introspection": "required by the rules_rust_pyo3 toolchain (//bazel/pyo3); no Rust "
                          "source names it, so no manifest requests it",
}

DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
