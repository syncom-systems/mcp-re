#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Module-size ratchet — a production Rust file may not cross 200 lines, and an
already-oversized one may not grow.

ADR-MCPRE-061 §5.1 sets the threshold and §6.3 specifies this gate. It exists because
**clippy has no file-length lint at all** — `clippy::module_lines` was probed against
clippy 0.1.97 and does not exist under that or any other name, so the one architectural
threshold the project states about files had no mechanical form. A rule enforced only by
an author's judgement is a rule whose enforcement cost is paid per file, by the least
reliable available party.

This is a **ratchet, not a cliff**. The debt registry (`config/module-size-debt.toml`)
records what was already oversized at a baseline SHA. From that point:

    new file over the threshold          -> FAIL
    registered file grows                -> FAIL
    registered file shrinks              -> PASS (and the entry is updated)
    registered file reaches <= threshold -> FAIL until the entry is removed
    reviewed large unit                  -> entry carries an ADR-061 §14 `review_ref`

The last two are what stop the registry rotting into a permanent allowlist: an entry that
no longer describes reality is an error, not a shrug.

# A raised baseline is a ONE-SHOT event, and it does not authorize itself

"A registered file grows -> FAIL" was enforced against `baseline_prod_loc` and nothing
enforced anything against `baseline_prod_loc`. Raising the number in the same commit as
the growth turned the whole ratchet off for that file, silently, with no reviewer seeing
anything but a larger integer in a TOML table. **A control whose input the controlled
party may edit is not a control** — it is the same defect class as a threshold
parameterising a lint nobody switched on.

So an upward baseline transition, judged against `origin/main`, is its own event with its
own authorization. It requires ALL of:

    new_baseline > old_baseline               the trigger: an upward transition
    actual production LOC == new_baseline     no headroom; exactly the growth that happened
    status == "reviewed-exception"            only a unit a §14 census kept INTACT may grow
    growth_from_prod_loc == old_baseline      the authorization names the transition it is for
    growth_ref names a §14 record that
      contains the exact literal line
      `growth-authorization: <path> <old> -> <new>`

The fourth and fifth conditions are what make it one-shot. An authorization is written for
one exact pair of integers; once merged, `old_baseline` on `origin/main` has moved to the
new value, so the spent authorization matches no future transition and a further increase
needs a fresh §14 record naming the new pair. **A previous authorization never authorizes
a later increase**, and the new ceiling is not general permission for the file to grow.

`actual == new_baseline` is the anti-headroom condition: without it, "442 -> 600" would
buy 146 lines of unexamined future growth from one review.

# Investigation status and disposition are separate facts

An entry's `status` says what is KNOWN about a unit, and there are three states because
there are three facts to tell apart:

    unreviewed                 nobody has investigated it
    reviewed-action-required   investigated; specific architectural work identified
    reviewed-exception         investigated, and deliberately kept intact

A completed census whose disposition is "decompose first" is still a completed census. If
it were recorded as `unreviewed`, the next reader would be told nobody had looked, and
would repeat the work — so `PERMITTED_TRANSITIONS` refuses every move back toward
`unreviewed`, checked against `origin/main` on every run.

# Measuring production lines

`prod` is every line NOT inside a test region. A test region opens at an attribute matching
`^#\\[cfg\\((all\\()?test` and closes at the end of the module that attribute introduces,
tracked by brace depth; a file may contain several, and counting resumes after each one.

Two details are load-bearing because each is a count this project got wrong:

- **The wide attribute pattern**, not `^#[cfg(test)]`. A census pass matching only the
  narrow form reported `mcp-re-proxy/src/app.rs` as 1680 production lines with no tests at
  all, because its module is `#[cfg(all(test, unix))]`. Its real production half is 1037.
- **Counting RESUMES after a region closes.** "Lines before the first test module" is a
  different and wrong rule: it discards every production item below the tests. Under it
  `mcp-re-proxy/src/trust_plane.rs` measures 134 lines; it is 690.
- **A region closes with the item the attribute introduces, brace-delimited or not.** Not
  every `#[cfg(test)]` introduces a module: it is also written on a `const`, a `use` or a
  type alias, which ends at `;` and opens no braces at all. Scanning on until the first
  brace closes then swallowed the NEXT item — production code — into the test region. Four
  files were undercounted this way, `mcp-re-proxy/src/trust_plane/mod.rs` by 23 lines and
  `mcp-re-proxy/src/signing_plane/mod.rs` by 17, and both were REGISTERED, so the ratchet
  was holding a ceiling below the real size and the difference was free headroom. It is
  also a bypass anyone could reach for: a `#[cfg(test)] const` placed above an item hides
  that item from the count.

A counter that silently undercounts is worse than no counter, so every detail of the rule
is exercised by `tools/verification/_rust_source.py --selftest`, the owner of the view this
gate counts, and the rule is PRINTED on every run so prose describing it cannot drift
from it unnoticed.

# The two blindness failures this gate refuses to repeat

- **An empty scope is a failure, not an OK.** A `tests/` glob silently exempted an entire
  crate from `scripts/bazel_srcs_gate.py` for a whole campaign while it printed OK.
- **The measurement rule is printed.** A threshold whose measurement is unstated is the
  "green that measured nothing" failure applied to the gate itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

# The package sits beside this script; a caller that loads the script by path (rather than
# running it) has no other way to find it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _module_size.cli import main as judge_tree  # noqa: E402
from _module_size.config import (  # noqa: E402,F401
    ENTRY_FIELDS,
    GROWTH_FIELDS,
    PERMITTED_TRANSITIONS,
    REGISTRY,
    REGISTRY_REL,
    REPO,
    REVIEWED,
    SCHEMA,
    STATUSES,
    THRESHOLD,
)
from _module_size.emit import baseline_sha, emit_registry  # noqa: E402,F401
from _module_size.growth import (  # noqa: E402,F401
    Ledger,
    check_baseline_growth,
    file_is_unchanged,
    growth_authorization_line,
)
from _module_size.measure import (  # noqa: E402,F401
    check,
    check_transitions,
    empty_scope_is_failure,
    permitted_transition,
    production_lines,
    register,
)
from _module_size.selftest import selftest  # noqa: E402,F401
from _module_size.selftest_growth import selftest_baseline_growth  # noqa: E402,F401

import _ratchet  # noqa: E402,F401
import _registries  # noqa: E402,F401
from _rust_source import crate_sources, production_view  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return judge_tree()


if __name__ == "__main__":
    sys.exit(main())
