# SPDX-License-Identifier: Apache-2.0
"""Recorded ADR-MCPRE-068 Phase-1 claim corrections — §14.7, and what it is NOT.

A theorem's `theorem_claim` is `statement + security_consequence + scope`, so correcting any
of them moves the fingerprint and the owner's specification review goes stale. That is
correct and stays correct: `scripts/claim_surface_gate.py` refuses to publish a claim nobody
has approved in its present form, and this module does not soften that rule.

What it adds is the ability to tell two things apart that the gate could not:

    an ARBITRARY claim edit          nothing says what moved, why, or from what
    a RECORDED Phase-1 correction    a signed-off campaign ruling authorizes a class of
                                     precision and dependency corrections, and each one
                                     carries the old text, the new text, the reason from the
                                     decomposition, and the assertions that make it that
                                     class rather than a different one

The owner's ruling of 2026-09-18 is the authority, and it is narrow:

> Phase 1 already authorizes correction of a theorem statement when decomposition
> demonstrates that the old wording overstates or misdescribes what production establishes,
> **provided the accepted system promise is not weakened, removed, or materially expanded.**

## The chain, and why it starts at the owner

A correction record names `from_fingerprint` and `to_fingerprint`. A theorem's corrections
are accepted only when they form an UNBROKEN chain whose first link starts at the fingerprint
the owner's specification review actually covers, and whose last link ends at the fingerprint
the tree has now.

That is what keeps the owner's review the base of the authority rather than a thing routed
around: a correction is a recorded DELTA on a reviewed claim, and a claim with no review to
start from has nothing to correct. It is also one-shot — the next edit produces a fingerprint
no record names, and the gate refuses again.

## What is deliberately NOT changed

`derive_review_state` still returns `STALE_CLAIM`. The specification-review axis is about
whether a human read THIS text, and a correction record is not a human reading it. So:

    merge path      a recorded correction publishes            (this module)
    release path    establishment still needs the owner's review (`_review`, unchanged)

An ADR-MCPRE-059 §28.8 closure run therefore still asks for the human, which is the honest
place for that question and the reason this module may exist at all. Recording a correction
as an approval would be the single-command self-approval §14.7 exists to prevent.
"""

from __future__ import annotations

from _claim_corrections_chain import chain
from _claim_corrections_load import load_corrections
from _claim_corrections_schema import (
    AUTHORITIES,
    CORRECTABLE_COMPONENTS,
    CORRECTIONS_DIR,
    CorrectionError,
    corrections_root,
)

__all__ = [
    "AUTHORITIES",
    "CORRECTABLE_COMPONENTS",
    "CORRECTIONS_DIR",
    "CorrectionError",
    "chain",
    "corrections_root",
    "load_corrections",
]
