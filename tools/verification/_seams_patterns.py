# SPDX-License-Identifier: Apache-2.0
"""What a trusted seam LOOKS LIKE in text: the mechanism patterns, the production-line view,
the comment rule and the per-file seam line scan."""

from __future__ import annotations

import re
from pathlib import Path

from _rust_source import production_view

#: Mechanisms that move a proof obligation out of the proof and into the trusted computing
#: base. Word-bounded so `assumed_state` or `external_id` do not trip the gate.
MECHANISMS = {
    "assume": r"\bassume\b",
    "assume_specification": r"\bassume_specification\b",
    "admit": r"\badmit\b",
    "axiom": r"\baxiom\b",
    "external_body": r"\bexternal_body\b",
    "external_type_specification": r"\bexternal_type_specification\b",
    "external_fn_specification": r"\bexternal_fn_specification\b",
    "external": r"\bexternal\b",
    "uninterp": r"\buninterp\b",
    "opaque": r"\bopaque\b",
    "sorry": r"\bsorry\b",
}

#: The same question, asked of production Rust, where the bare words are ordinary English.
#: "admit only the closed set" in a comment is not a proof escape hatch, and a gate that
#: said it was would be teaching people to ignore it within a week. So the mechanisms are
#: matched in their code forms: the verus-specific spellings, and `assume`/`admit` only as
#: calls.
PRODUCTION_MECHANISMS = {
    "assume_specification": r"\bassume_specification\b",
    "external_body": r"\bexternal_body\b",
    "external_type_specification": r"\bexternal_type_specification\b",
    "external_fn_specification": r"\bexternal_fn_specification\b",
    # `external` REMOVES a function from verification entirely, which is a stronger escape
    # than `external_body`. Matched only in its two code spellings, because the bare word
    # is ordinary English and ordinary Rust.
    "external": r"verifier::external\b(?!_)|verus_verify\s*\(\s*external\s*\)",
    # An uninterpreted spec function is a trusted seam by construction: every theorem that
    # mentions it says nothing about what it computes.
    "uninterp": r"\buninterp\b",
    "opaque": r"verifier::opaque\b",
    "axiom": r"\baxiom\b",
    "sorry": r"\bsorry\b",
    # A METHOD call is not a proof escape hatch, and neither is a method DEFINITION.
    # `self.inner_async.admit()` asks the inner plane whether it will accept a request, and
    # `fn admit(&self)` is where that question is answered; Verus' `admit()` deletes a proof
    # obligation. They share a name and nothing else, and a gate that conflated them would
    # fire on ordinary serving code — the same failure the code-forms rule above exists to
    # avoid, and one that arrived twice: once when the caller entered a unit's paths, and
    # again when the definition did.
    # Path-qualified spellings (`vstd::pervasive::admit()`) are still matched: `::` is not
    # `.`, and `fn ` does not precede them.
    "assume": r"(?<!\.)(?<!fn )\bassume\s*[(!]",
    "admit": r"(?<!\.)(?<!fn )\badmit\s*[(!]",
}


def production_lines(text: str) -> list[tuple[int, str]]:
    """`(1-based line number, line)` for every line OUTSIDE a test region.

    The region is `_rust_source`'s. Why the PRODUCTION scan needs this at all: its mechanism
    list exists because the bare words are ordinary English and ordinary Rust, and a test
    region is where ordinary Rust is densest. `mcp-re-http-profile/src/replay.rs` has a test
    helper `fn admit(..)`; Verus' `admit()` deletes a proof obligation, and the two share a
    name and nothing else. A region that ships in no binary cannot weaken a proof about one,
    so the honest scope for "which escape hatches does this shipped code use" is the shipped
    code.
    """
    return list(production_view(text).lines)


#: A line comment's tail, and a whole-line block-comment body. Removed before a line is
#: searched for a mechanism.
COMMENT_TAIL = re.compile(r"//.*$")


def code_of(line: str) -> str:
    """`line` with its comment removed — what the compiler would see.

    R9-C037 / R9-C067 / R9-C068 surfaced this: the production mechanism list matches
    `\bexternal_body\b` against whole lines, so PROSE mentioning a mechanism counted as an
    escape hatch. Two real examples on `main`:

        // Class B, and it matters most here: `external_body` means Verus checks this
        //! seal is `external_body`, which makes the type OPAQUE and its postconditions …

    Under kind-level registration this was invisible — the kind was registered, so a comment
    and a real seam both read `[registered]` and were indistinguishable. It matters twice
    over now: a site census that counts comments is not a census of seams, and
    `semantic_boundary_crossings` would read a boundary file that merely DISCUSSES a
    mechanism as one the proof trusts.

    `definition_sites` below has stripped comments for exactly this reason
    since the deleted-specification repair — *"a comment cannot supply an escape-hatch
    mechanism either"*. That reasoning was applied to attribute blocks and not to the line
    scan; this is the same rule in the one place both consumers read.

    Leading `*` continuation lines of a block comment are dropped too. A `/* */` opening on
    its own line leaves nothing to match, and a mechanism written inside a multi-line block
    comment beside code on the same line is not a construction the language admits.
    """
    stripped = COMMENT_TAIL.sub("", line)
    body = stripped.strip()
    if body.startswith(("*", "/*")):
        return ""
    return stripped


def seam_lines(path: Path) -> list[tuple[int, str]]:
    """Every PRODUCTION line of `path` that carries a trusted seam, with its line number.

    Production lines only, for the reason `production_lines` gives: a region that ships in
    no binary cannot weaken a proof about one.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    out: list[tuple[int, str]] = []
    for lineno, line in production_lines(text):
        code = code_of(line)
        if any(re.search(pattern, code) for pattern in PRODUCTION_MECHANISMS.values()):
            out.append((lineno, line.strip()))
    return out


def files_with_seams(repo_root: Path, relative_paths) -> set[str]:
    """Which of `relative_paths` contain at least one trusted seam."""
    return {
        rel
        for rel in relative_paths
        if rel.endswith(".rs") and seam_lines(repo_root / rel)
    }
