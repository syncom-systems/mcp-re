#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extraction-image gate — the image consumes pinned Aeneas/Charon prebuilts and builds neither.

WHAT THIS PROVES, exactly, about `verification/extraction/Dockerfile` against
`verification/policy/toolchains.lock.toml`:

  * the pair is Aeneas's own: the lock's `[aeneas].charon_pin` — the last line of
    `charon-pin` at the pinned Aeneas commit — equals `[charon].commit`;
  * each Aeneas/Charon build argument's default equals the lock: the commits, the release
    URLs (under each project's own `releases/download/<release_tag>/`), the archive digests,
    the digest of every binary the lane executes, and Charon's rustc nightly;
  * every instruction that downloads a release archive also checks it against its pinned
    digest, and every executed binary is checked against its own;
  * no instruction clones an Aeneas or Charon repository or invokes a tool that builds one
    (`git clone`, `make`, `dune`, `opam`, `cargo`), and the only fetch from those
    repositories outside a release is the `charon-pin` file at the pinned commit;
  * `CHARON_EXE` and `AENEAS_EXE` name the installed release binaries.

WHAT IT DOES NOT PROVE: anything about what a downloaded binary does, or what an upstream
command would run. It holds this definition to one route for the two tools — a pinned,
digest-checked download — and forbids the other. Whether the binaries that RUN are those
downloads is `tools/verification/extraction-image smoke`'s check, which re-digests them inside
the image and reads Charon's own statement of its commit.

WHY IT MATTERS. The previous definition built Charon and Aeneas from source; Charon's
`make build` runs Cargo. A scanner for the word `cargo` could not see that — it was behind
an upstream Makefile — so the invariant is stated as what the image may contain rather than
as a word it may not.

Run:  python3 scripts/extraction_image_gate.py
      python3 scripts/extraction_image_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "tools" / "verification"))

from _extraction_image.checks import problems  # noqa: E402,F401
from _extraction_image.cli import verdict  # noqa: E402
from _extraction_image.config import DOCKERFILE  # noqa: E402,F401
from _extraction_image.dockerfile import instructions  # noqa: E402,F401
from _extraction_image.selftest import selftest  # noqa: E402


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    return verdict()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
