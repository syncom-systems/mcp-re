#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Clippy debt ratchet — the adopted lints run over production code, and counts may only fall.

ADR-MCPRE-061 §6.4, implementing the §6.5 rulings on C-4 and C-5.

# What this gate is, and why it is a gate

Six lints are adopted (ADR-MCPRE-061 §6.5). Five of them cannot be flipped to `deny` in one
step — they have 60, 69, 27, 164 and 124 production sites — so the gate switches them on
itself, over production targets only, and holds the per-crate count against
`config/clippy-debt.toml`:

    baseline 0 for a crate/lint -> any occurrence FAILS (this is `deny` with a better message)
    count above baseline        -> FAIL
    count below baseline        -> FAIL, demanding the baseline be lowered to lock the gain
    count at baseline           -> PASS

`unwrap_used` is at **0 across all production code**, measured, so it has no debt entry and
is denied at zero by the same rule. There is nothing to ratchet.

# Why not `//bazel:workspace_lints`

Because the Rust lint lane (`bazel build --config=lint //...`) runs over every target with
warnings as errors. A policy entry at `warn` is therefore a hard error, applied to *all*
targets, which includes the thousands of `unwrap`/`expect`/indexing sites in test code that
the ruling explicitly exempts. Landing the lints that way is the "turns the build red
immediately" failure C-8 named.

Running them here, over the production library and binary flavors only, exempts test code
by construction rather than by an allowlist somebody has to maintain, and makes the
production count a number instead of a wall of warnings. Every flavor that ships is linted
— default, `async_serve`, the external backends, the auditor — and a site is counted once
however many flavors compile it.

The cost is stated rather than hidden: the lint lane does not show these lints. The gate is
where they run, and `--activation-probe` proves they run there.

# Why not a per-crate `#![allow(...)]`

A crate-level allow silences the lint for the whole crate, including code written tomorrow.
The debt becomes invisible and unbounded. A count keeps every existing site visible and
makes the 61st site an error.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _clippy_ratchet.allow import adopted_in, allow_discipline  # noqa: E402,F401
from _clippy_ratchet.cli import emit_registry, judge  # noqa: E402
from _clippy_ratchet.config import (  # noqa: E402,F401
    ADOPTED,
    LINT_FLAGS,
    RATCHETED,
    REGISTRY,
    REGISTRY_REL,
    REPO,
    SCHEMA,
    STRICT_CONF,
    STRICT_CONF_LABEL,
)
from _clippy_ratchet.measure import clippy_diagnostics, measure  # noqa: E402,F401
from _clippy_ratchet.probes import activation_probe, nesting_probe  # noqa: E402,F401
from _clippy_ratchet.registry import compare, load_registry  # noqa: E402,F401
from _clippy_ratchet.selftest import selftest  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if "--nesting-probe" in sys.argv:
        return nesting_probe()
    if "--activation-probe" in sys.argv:
        return activation_probe()
    if "--emit-registry" in sys.argv:
        return emit_registry()
    return judge()


if __name__ == "__main__":
    sys.exit(main())
