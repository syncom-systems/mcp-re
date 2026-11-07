#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SCITT two-direction cross-verification against an independent implementation.

The same no-merge shape as the RFC 9421 and JOSE gates, and it exists because its
absence let a non-conforming receipt encoding ship: the receipt used the
pre-publication draft header labels (`-111`/`-222`) instead of RFC 9942 §5.2.1's `vds`
= 395 and `vdp` = 396, and every test passed. They passed because they ran our encoder
against our own decoder, which agrees with itself whatever labels it picks.

* **ours -> external** (default): every committed vector is decoded, checked against
  the RFC's literal labels, and its signatures verified by third-party code — `cbor2`
  for CBOR, `cryptography` for Ed25519/ECDSA — with the RFC 9052 §4.4 `Sig_structure`
  and the RFC 9162 fold written here from the RFC text.
* **external -> us** (`--emit-external-kat`): this script BUILDS Signed Statements and
  RFC 9942 Receipts independently, for EdDSA and ES256, together with the refusals a
  conforming verifier owes. `scitt_cross_verification_test.rs` then requires the Rust
  verifier to accept the positives and refuse each negative.

Direction 2 is the one that catches a wrong label, and it is the control that was
missing. It includes a receipt built with the draft labels specifically so a regression
to them fails here rather than silently producing bytes only MCP-RE accepts.

    pip install -r mcp-re-conformance/tools/requirements-cross-verify.txt
    python3 mcp-re-conformance/tools/scitt_cross_verify.py
    python3 mcp-re-conformance/tools/scitt_cross_verify.py --emit-external-kat
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _scitt_cross.direction1 import cross_verify  # noqa: E402
from _scitt_cross.kat import emit_external_kat  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--emit-external-kat", action="store_true",
                    help="build the external -> us corpus the Rust verifier consumes")
    args = ap.parse_args()
    return emit_external_kat() if args.emit_external_kat else cross_verify()


if __name__ == "__main__":
    sys.exit(main())
