#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit-closure gate — a file adjacent in the module tree to a measured one is answered for.

`verification/policy/verification.toml` declares assurance units. A unit's `paths` list is
the source closure its ReviewFingerprint is taken over: change a file inside it and every
claim resting on that unit goes dirty. A security-bearing file in NO unit's `paths` can be
rewritten without moving any fingerprint, so the graph keeps answering FRESH over code it
never measured.

THE FAILURE CLASS, which is why this file exists rather than any single instance:

    A security-bearing file used by a declared unit must not silently leave that unit's
    measured closure.

The escape has two shapes, and in both the unit keeps a `paths` entry that still resolves,
keeps deriving a fingerprint, and keeps answering FRESH — over less code than before, with
nothing reporting the difference:

  * the file is MOVED or RENAMED;
  * code is SPLIT OUT of it into a new sibling.

The second is what happened to `mcp-re-proxy/src/signing_plane/`: `rotation.rs`,
`mint_successor.rs` and `trust_epoch_advance.rs` were carved out of a `mod.rs` that
`proxy.signing_credential_provenance` declares, and the unit went on fingerprinting the
`mod.rs` alone. It happened twice more during the r11 campaign — `async_replay/
budget_report.rs` and `audit_sink/writer.rs` — while this gate was being specified.

# Why neither neighbouring gate covers it

`scripts/bazel_srcs_gate.py` walks the same module tree, but its subject is a library
target's `srcs`. It fired on the `signing_plane` split and was satisfied the moment the new
files joined the Bazel list — which says nothing about `verification.toml`.

`tools/verification/_unit_rules.py` raises when a declared path matches nothing, so a
DELETED path is caught. That check is one-directional: declared ⇒ exists. A file that
quietly appears NEXT TO a declared one is invisible, because nothing walks from the file
system back toward the declarations. This gate is the other direction:

    exists ⇒ answered for.

# The rules

UC-1 (child)   For every declared `paths` entry that resolves to a Rust module file, every
               `mod <name>;` it declares in code must resolve to a file that is itself in
               some unit's expanded `paths`, or registered in
               `config/unit-closure-exclusions.toml`.

UC-2 (parent)  The module file that DECLARES a declared path must satisfy the same
               requirement — but only when that parent declares at least one item of its
               own (`fn`/`struct`/`enum`/`trait`/`impl`/`const`/`static`/`type`/`union`)
               outside a test region. A parent whose whole body is `mod` and `pub use` is a
               namespace and is exempt by construction: without that clause
               `config_state/mod.rs`, `authorization/mod.rs` and their kind would be dragged
               into twenty units apiece, coupling every one of those fingerprints to a
               re-export list.

UC-3 (diff)    A flagged path that is NEW since `origin/main` may not be answered with a
               register entry at all. New drift is fixed, never registered.

# What this gate does NOT claim

It cannot decide semantic ownership, and pretending it can is how a coverage gate becomes a
form to fill in. It detects an UNANSWERED question, never a wrong answer: an entry with a
plausible reason passes, and that is correct — the review is the control, the gate only
makes the review unavoidable.

It is also silent on a file with no declared neighbour at all. `admission_enforcer/` is in
no unit and neither is its parent, so no `mod` edge crosses a closure boundary. That is a
COVERAGE gap, not a drift, and no gate can close it: it needs a unit to exist first. The
gate stops the uncovered set from growing; it does not shrink it.

And it says nothing about the evidence half — a path can be declared while contributing no
`tested_symbols`. That is a different rule with a different debt shape, deliberately not
bundled here, because one red line that means two things is worth less than either.

# The register

Three states, borrowed verbatim from `config/module-size-debt.toml`, because investigation
status and disposition are separate facts:

    unreviewed              outside every closure, and nobody has looked
    reviewed-attached       looked at; belongs in a named unit; the `paths` edit is open work
    reviewed-out-of-cone    looked at; genuinely outside every unit's claim, reason written down

It is a debt register, not an exception mechanism. It may only shrink, nothing returns to
`unreviewed`, each reviewed state names a record in `docs/architecture/review-dispositions.md`,
and an entry the rules no longer flag is an error rather than a shrug.

Run:  python3 scripts/unit_closure_gate.py
      python3 scripts/unit_closure_gate.py --selftest
      python3 scripts/unit_closure_gate.py --emit-register
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _unit_closure.cli import run  # noqa: E402
from _unit_closure.config import (  # noqa: E402,F401
    ENTRY_FIELDS,
    ITEM,
    PERMITTED_TRANSITIONS,
    REGISTER,
    REGISTER_REL,
    REPO,
    REVIEWED,
    SCHEMA,
    STATUSES,
    exclusions,
)
from _unit_closure.emit import emit_register  # noqa: E402,F401
from _unit_closure.register import (  # noqa: E402,F401
    check_new_debt,
    check_register,
    check_transitions,
    empty_scope_is_failure,
    introduced_paths,
    permitted_transition,
    validate_register,
)
from _unit_closure.rules import expansion_disagreements, flag  # noqa: E402,F401
from _unit_closure.selftest import selftest  # noqa: E402
from _unit_closure.tree import (  # noqa: E402,F401
    closure,
    declares_items,
    expand,
    module_children,
    parent_module,
)


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if "--emit-register" in sys.argv:
        return emit_register()
    return run()


if __name__ == "__main__":
    sys.exit(main())
