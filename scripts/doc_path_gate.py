#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Doc-path gate — current text may not name a path the repository does not contain.

    python3 scripts/doc_path_gate.py             # the verdict
    python3 scripts/doc_path_gate.py --selftest  # prove the verdict can be FAIL
    python3 scripts/doc_path_gate.py --emit-registry > config/doc-path-debt.toml

A census of current documentation found 49 statements naming something that does not
exist at the revision that ships them. A dead path in a guide is instruction: the reader
does not learn that the sentence is stale, they learn that they cannot find the file.

WHAT THIS GATE REACHES, AND WHAT IT DOES NOT. Stating the boundary is part of the
control, because a gate that covers one class and is described as covering the category
is the same defect one level up.

  * It reaches 26 of the 31 `NONEXISTENT_TARGET` hits that census recorded. The five it
    misses are a crate name in a string with no `/` in it; a pair of `tests/tls_test.rs`
    citations, which suffix resolution below deliberately admits; a dependency justified
    by a consumer that does not exist; and a chart comment naming a private type.
  * It reaches NONE of the 14 `FALSE_PRESENT_TENSE` hits. Every one of those names
    something that EXISTS, and the defect is what is said about it. No path resolver
    reaches them; they are found by asking of a claim *what edit to production code would
    make this sentence false?*, which is review, not a gate.
  * A symbol resolver would reach twelve more and is not built here: the sweep run for
    that census produced roughly 60% noise before hand-triage, which is a review
    instrument, not a merge-path control.

TWO FAILURE CLASSES, and the second is the one a resolver alone would miss:

  DEAD        the token resolves to nothing, anywhere.
  GITIGNORED  the token resolves ONLY to a path outside the repository — a path that is
              on the author's disk and on no one else's. Fifteen citations of a
              `work/`-local design document in shipped `config_state` source are the
              worked example, and nothing but this rule finds them.

WHAT IS READ. Every file the repository would offer to commit, minus the exclusions
below. In a DOCUMENT every line is read; in a code file (`.rs`, `.py`, `.sh`, `.ts`) only
comment lines are, because a path written by a gate's own `--selftest` into a temporary
tree is supposed not to exist here.

RESOLUTION, in order: repo-relative; relative to the referencing file's directory; then
ANY path suffix in the tree. The third is what makes the gate usable — it lets
`transport/mod.rs` resolve from a comment that does not spell the full path — and it is
also what costs the gate its teeth on the `tests/tls_test.rs` class, where a citation of
one crate's test file resolves against another's. That is a deliberate trade.

REPOSITORY SCOPE is `git ls-files --cached --others --exclude-standard`: what `git status`
would offer to commit. Tracked-only would leave a newly written document unchecked until
it was committed, and the COMPLEMENT of this set is exactly what the GITIGNORED class is
about. `tools/verification/_controls.py` owns this repository's definition of "a file of
this repository" for the control census; this gate must not drift from it, and neither
re-implements `.gitignore` parsing.

RATCHET, not a cliff. `config/doc-path-debt.toml` carries the population this gate lands
over, in the three-state shape of `config/module-size-debt.toml`. A registered count must
EQUAL the measurement, so a registered file may not grow by one token and a file whose
tokens are repaired cannot keep describing debt that has been paid.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _doc_path.config import (  # noqa: E402,F401
    CODE_SUFFIXES,
    COMMENT,
    FENCE,
    HEADING,
    MAX_BYTES,
    REGISTRY,
    REPO,
    SCOPE_EXCLUDE,
    SHA_ANCHOR,
    STRIKE,
    TOKEN,
)
from _doc_path.registry import SCHEMA, emit_registry, load_registry  # noqa: E402,F401
from _doc_path.scan import (  # noqa: E402,F401
    in_scope,
    measure,
    repository_files,
    scan_file,
    scanned_count,
)
from _doc_path.selftest import selftest  # noqa: E402,F401
from _doc_path.verdict import verdict  # noqa: E402,F401


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if "--emit-registry" in sys.argv:
        print(emit_registry(measure(REPO)), end="")
        return 0
    return verdict(REPO)


if __name__ == "__main__":
    raise SystemExit(main())
