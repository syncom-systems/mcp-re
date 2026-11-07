#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent RFC 9421 cross-verification of the MCP-RE HTTP-profile corpus
(ADR-MCPRE-050 no-merge gate, MCPRE-99).

This is a PINNED, THIRD-PARTY check: it reconstructs each signed fixture's
RFC 9421 signature base with its OWN parser and verifies the Ed25519 signature
with `cryptography` (a different implementation than the Rust `ed25519-dalek`
the corpus was produced with). If our signer and this external verifier disagree
on a single byte, the gate fails and the merge is blocked.

It checks BOTH directions:
  * our vectors verify externally  — every positive-signature fixture
    (request / response / bound+unbound rejection) verifies here, and h01's
    reconstructed base is byte-compared to the frozen oracle;
  * external → us                  — `external_kat.json` is produced HERE by
    `cryptography` and (in CI) fed back to the Rust verifier
    (`rfc9421_cross_verification_test.rs`); `--emit-external-kat` regenerates it.

Determinism: Ed25519 is deterministic, so byte comparison is honest.

Usage:
    python3 rfc9421_cross_verify.py [CORPUS_DIR] [--emit-external-kat]
Exit code 0 == gate passes.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _rfc9421_cross.verify import run  # noqa: E402

DEFAULT_CORPUS = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "http-profile"


def main() -> int:
    return run(sys.argv[1:], DEFAULT_CORPUS)


if __name__ == "__main__":
    raise SystemExit(main())
