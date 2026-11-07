#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Conformance-claims gate — an advertised category has a corpus AND a harness.

WHAT THIS PROVES, exactly: every row of the category table in
`docs/conformance-guide.md` names (a) a corpus directory that exists and carries a
`manifest.json`, and (b) at least one Bazel test target that a `BUILD.bazel`
declares as an `nt_rust_test` AND whose declaration reaches that corpus through
`data`. It also proves the reverse containment — every top-level corpus under
`mcp-re-conformance/tests/vectors/` appears as a row — and that any corpus whose
manifest publishes a `corpus_digest` has some reaching harness that recomputes it.

WHAT IT DOES NOT PROVE: that the harness makes good use of the corpus, that the
vectors specify the right behaviour, or that a passing run means the profile is
correctly implemented. It proves the two edges exist, not their quality.

WHY IT MATTERS. Conformance is executable evidence, not documentation. A category
advertised with no harness underneath it is a claim with no witness, and it reads
to an operator — or an auditor — exactly like a category that is proven. The
failure mode is silent in both directions and neither is self-announcing:

  - a corpus with no harness is never executed, so nothing goes red when the
    behaviour it specifies regresses or is removed entirely;
  - a documented category whose corpus, generator, and harness were all deleted
    keeps advertising coverage that no longer exists anywhere in the tree.

A published `corpus_digest` that no test recomputes is the same failure one level
down: as `corpus_pinning_test` puts it, a manifest carrying hashes nobody checks
is worse than no hashes, because it reads as a guarantee.

Run:  python3 scripts/conformance_claims_gate.py
      python3 scripts/conformance_claims_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _conformance_claims.check import check  # noqa: E402,F401
from _conformance_claims.cli import verdict  # noqa: E402
from _conformance_claims.config import (  # noqa: E402,F401
    BACKTICKED,
    BEGIN,
    END,
    GUIDE,
    REPO,
    ROW,
    SRCS_ENTRY,
    TARGET_NAME,
    TEST_BLOCK,
    VECTORS_ROOT,
)
from _conformance_claims.corpus import (  # noqa: E402,F401
    declared_tests,
    parse_rows,
    reaches,
    recomputes_digest,
)
from _conformance_claims.selftest import selftest  # noqa: E402


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    return verdict()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
