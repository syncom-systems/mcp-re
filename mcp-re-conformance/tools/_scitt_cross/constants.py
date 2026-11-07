# SPDX-License-Identifier: Apache-2.0
"""Labels, fixed key material and corpus paths shared by both directions."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CORPUS = REPO / "mcp-re-conformance" / "tests" / "vectors" / "scitt"
EXTERNAL_KAT = CORPUS / "external_kat.json"

# RFC 9942 §5.2.1 / §8.2.2.1
VDS, VDP, INCLUSION_PROOF, RFC9162_SHA256 = 395, 396, -1, 1
# The pre-publication draft labels, present ONLY to be refused.
DRAFT_VDS, DRAFT_VDP = -111, -222
# RFC 9943 §6.1 / RFC 9597
CWT_CLAIMS, CWT_ISS, CWT_SUB, CWT_IAT = 15, 1, 2, 6
# COSE header labels and algorithms (RFC 9052 §3.1, RFC 9053).
HDR_ALG, HDR_CTY, HDR_KID = 1, 3, 4
ALG_ES256, ALG_EDDSA = -7, -8

STATEMENT_SUBJECT = "mcp-re:call-evidence"
STATEMENT_CTY = "application/mcp-re-evidence+cbor"
ISSUER_KID = "external-issuer-1"
TS_KID = "external-ts-1"
ISSUED_AT = 1_700_000_000

# Fixed key material so the emitted KAT is byte-stable and the drift guard means
# something. Test keys; they exist only in this corpus.
ISSUER_SEED = bytes([0x11]) * 32
TS_ED_SEED = bytes([0x22]) * 32
TS_EC_SCALAR = 0x33333333333333333333333333333333333333333333333333333333333333
