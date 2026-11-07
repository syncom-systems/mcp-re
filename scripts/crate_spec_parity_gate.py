# SPDX-License-Identifier: Apache-2.0
"""Crate-spec parity gate — Bazel's declared crates and the Cargo workspace agree.

Bazel resolves external crates from the `crate.spec` entries in MODULE.bazel against
`bazel/crates.lock`; it reads no Cargo file, and nothing executes Cargo. The Cargo manifests
and locks remain as the crates' published description, so the same dependency is declared
in two places, and nothing but this gate keeps them from drifting:

  * a Dependabot bump lands in `Cargo.lock` only, so without this the Bazel-built
    artifacts (the proxy image among them) would silently keep the old version;
  * a feature added to a member's Cargo.toml would reach cargo builds and not Bazel.

Two checks:

  * SPECS — every external dependency a workspace member requests appears as a
    `crate.spec` with the same version requirement, the same feature union and the same
    default-features choice, and there is no spec the workspace does not request.
    Optional dependencies are not compared: no member feature enables one in the hub
    (today only the Verus crates, which the Verus lane builds outside Bazel).
  * LOCKS — every package `bazel/crates.lock` resolves is in `Cargo.lock` at the same
    version and checksum. (The Bazel lock is a subset: it holds only what the specs reach.)

The manifests are READ, never evaluated by Cargo: each member's dependency tables (normal,
dev, build, target-specific), resolved through `workspace = true` inheritance and
`package =` renames — what `cargo metadata` reported, without running it. The Cargo
workspaces covered are the root one and each separate workspace Bazel builds a crate from
(`EXTRA_WORKSPACES`).

Delete this gate together with the last Cargo manifest.

    python3 scripts/crate_spec_parity_gate.py             # the verdict
    python3 scripts/crate_spec_parity_gate.py --selftest  # prove the verdict can be FAIL
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _crate_spec_parity.cli import verdict  # noqa: E402
from _crate_spec_parity.compare import compare, repin_inputs  # noqa: E402,F401
from _crate_spec_parity.config import (  # noqa: E402,F401
    BAZEL_LOCK,
    BAZEL_ONLY_SPECS,
    CARGO_LOCK,
    CRATE_EXTENSION,
    EXTRA_WORKSPACES,
    FIX,
    MODULE,
    MODULE_LOCK,
    REPIN_INPUTS,
    REPO,
    SPEC_BLOCK,
    SPLICE_ROOT,
    UNSET,
)
from _crate_spec_parity.manifests import cargo_locks, workspace_meta  # noqa: E402,F401
from _crate_spec_parity.selftest import selftest  # noqa: E402
from _crate_spec_parity.specs import (  # noqa: E402,F401
    bazel_only_packages,
    declared,
    locked,
    requested,
)

if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else verdict())
