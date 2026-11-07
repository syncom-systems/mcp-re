#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lifecycle-purity gate — the state machines that are values depend on no production module.

WHAT THIS PROVES, exactly: in the production half of each module named in `TARGETS`
(every line outside a `#[cfg(test)]`-family region — NOT everything above the first one,
which discards production items below a test module), every path root and every `use` target
resolves either inside the module itself or to an explicitly allowed standard-library
path. It computes the module's external dependency set and asserts it is empty of
production modules.

WHAT IT DOES NOT PROVE: that the lifecycle is semantically pure. A future edit could take
a closure argument, read a `static`, or call a function handed in from outside, and none
of those would be seen here. Keeping the contract narrow is deliberate — overstating a
gate is worse than not having one, because the overstatement is what stops people looking.

## The property, and the two syntactic proxies it is not

The first version of this gate asserted "contains no `use` declaration". That is a
syntactic correlate of the property, not the property, and it was wrong twice within an
hour:

  * `use RuntimeEvent as E;` renames a type the file itself declares, so the transition
    match can fit the 110-pair table on a screen. It names nothing outside. The gate
    rejected it.
  * `impl std::fmt::Display for InvalidTransition` uses no `use` at all, so a `use`-based
    check saw nothing — while the module does in fact reach for the standard library.

Both directions wrong, from the same mistake: measuring the spelling instead of the
proposition. So this gate computes the dependency SET and reports what is in it.

## Why `std::fmt` is allowed and the rest of `std` is not

Formatting traits cannot introduce state, behaviour, or a decision. `std::sync::Mutex`
could. The allowlist is therefore per-path and short, and extending it is a deliberate
edit here with a reason attached — not something a new import does silently.

## WHY the property matters

ADR-MCPRE-059 Phase 2 considered extracting this module into its own pure crate so Verus
could verify it at crate granularity, and rejected it: the crate would have ~212
production lines and three consumers, all sibling modules in `mcp-re-proxy`, modelling
states that describe that same program. Reasoning in
`verification/baseline/phase2-pilot-boundary-decision.md`.

But the extraction was reaching for something real, and this gate is that something
without the crate:

    The lifecycle relation is a value. It depends on no production module, so it cannot
    acquire behaviour, and "is this transition legal?" cannot answer differently on two
    calls with the same arguments.

That is what `FleetDrained` and the terminal latches mean. A lifecycle able to consult the
outside world would be able to answer the same question two ways.

Run:  python3 scripts/lifecycle_purity_gate.py
      python3 scripts/lifecycle_purity_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _lifecycle_purity.config import (  # noqa: E402,F401
    ALLOWED_STD_PATHS,
    CHILD_MOD,
    LOCAL_DECL,
    PATH_ROOT,
    REPO_ROOT,
    TARGETS,
    USE_DECL,
)
from _lifecycle_purity.cli import judge  # noqa: E402
from _lifecycle_purity.dependencies import (  # noqa: E402,F401
    child_modules,
    external_dependencies,
    local_names,
    production_half,
)
from _lifecycle_purity.selftest import selftest  # noqa: E402,F401


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    return judge()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
