# SPDX-License-Identifier: Apache-2.0
"""Vacuity at a proved symbol: a unit that claims a theorem over a function the prover was
told not to check, or whose specification has been deleted while the function stayed."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from _seams_inventory import unit_files
from _seams_patterns import COMMENT_TAIL

#: Mechanisms that, applied to the very function a unit claims to have proved, make the
#: claimed theorem vacuous or delete it. No assumption registers these at a proved symbol,
#: because there is no honest justification for one: the unit would be advertising a
#: theorem that the prover was told not to check.
VACUITY_AT_PROVED_SYMBOL = {
    "external_body": r"\bexternal_body\b",
    "external": r"verifier::external\b(?!_)|verus_verify\s*\(\s*external\s*\)",
    "external_fn_specification": r"\bexternal_fn_specification\b",
    "assume_specification": r"\bassume_specification\b",
    "opaque": r"verifier::opaque\b",
}

#: What makes an attribute block a SPECIFICATION rather than decoration.
SPECIFICATION_TEXT = re.compile(r"\bensures\b|\brequires\b")


def definition_pattern(name: str) -> re.Pattern[str]:
    """A Rust function definition, as it appears at the head of the item."""
    return re.compile(
        r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
        r"(?:default\s+|const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
        rf"fn\s+{re.escape(name)}\s*[(<]"
    )


def _bracket_balance(line: str) -> int:
    return sum(line.count(c) for c in "([{") - sum(line.count(c) for c in ")]}")


def definition_sites(lines: list[str], pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    """`(line index, ATTRIBUTE text)` for every definition `pattern` matches.

    Read forwards rather than backwards from the item. A Verus specification is a
    multi-line `#[cfg_attr(...)]` whose body is arbitrary expression text, so no
    line-shaped heuristic recognises its middle; accumulating the block from its opening
    `#[` until the brackets balance does.

    COMMENTS ARE NOT PART OF THE BLOCK, and that is the whole point of this function
    returning attribute text rather than everything above the item. They used to be
    accumulated, so `SPECIFICATION_TEXT` — the ONLY control for a deleted specification —
    matched the words `requires` or `ensures` in the doc comment above the function. A
    specification could therefore be deleted while the prose describing it stayed, and the
    gate would report the theorem present. Doc comments say what a function is supposed to
    do; the attribute is what makes the prover check it, and only the second is evidence.
    A comment cannot supply an escape-hatch mechanism either, so removing them fixes a
    false positive in the same walk.

    Comment lines still do not RESET the block: an attribute separated from its item by a
    doc comment is still that item's attribute.
    """
    sites: list[tuple[int, str]] = []
    block: list[str] = []
    depth = 0
    for index, line in enumerate(lines):
        if depth > 0:
            # Inside a multi-line attribute. A trailing `//` comment here is prose: it is
            # stripped before the text is kept and before the brackets are counted, because
            # a comment cannot close an attribute.
            code = COMMENT_TAIL.sub("", line)
            block.append(code)
            depth += _bracket_balance(code)
            continue
        stripped = line.strip()
        if stripped.startswith("#["):
            code = COMMENT_TAIL.sub("", line)
            block.append(code)
            depth = max(_bracket_balance(code), 0)
            continue
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        if pattern.match(line):
            sites.append((index, "\n".join(block)))
        block = []
    return sites

@dataclass(frozen=True)
class _Claim:
    """One theorem a unit advertises: the unit and the symbol it claims to have proved."""

    unit_id: str
    symbol: str

    @property
    def name(self) -> str:
        return self.symbol.rsplit("::", 1)[-1]


def _site_defects(claim: _Claim, where: str, block: str) -> list[str]:
    defects = [
        f"{claim.unit_id}: proved symbol {claim.symbol} is annotated "
        f"`{mechanism}` at {where}. The prover is told "
        f"not to check the function the unit claims to have "
        f"proved, so the theorem is vacuous while the symbol "
        f"still appears verified."
        for mechanism, mechanism_pattern in sorted(VACUITY_AT_PROVED_SYMBOL.items())
        if re.search(mechanism_pattern, block)
    ]
    if not SPECIFICATION_TEXT.search(block):
        defects.append(
            f"{claim.unit_id}: proved symbol {claim.symbol} at {where} "
            f"carries no `requires`/`ensures`. The specification is a "
            f"detachable attribute: deleting it leaves the function, the "
            f"crate's verified count and the prover's symbol list "
            f"unchanged, so no lane sees the theorem go."
        )
    return defects


def _symbol_defects(claim: _Claim, sources: list[Path], repo_root: Path) -> list[str]:
    pattern = definition_pattern(claim.name)
    defects: list[str] = []
    sites = 0
    for path in sources:
        lines = path.read_text(encoding="utf-8").splitlines()
        rel = path.relative_to(repo_root).as_posix()
        for index, block in definition_sites(lines, pattern):
            sites += 1
            defects += _site_defects(claim, f"{rel}:{index + 1}", block)
    if sites == 0:
        defects.append(
            f"{claim.unit_id}: proved symbol {claim.symbol} defines no function in the "
            f"unit's declared paths. A theorem the manifest advertises over source "
            f"the unit does not declare is invalidated by no change to it."
        )
    return defects


def proved_symbol_defects(verification: dict, repo_root: Path) -> list[str]:
    """Claimed theorems that no lane can distinguish from a deleted one.

    Three ways a unit advertises a theorem it does not have, none of which the prover's
    report shows: the function is not in the unit's declared paths at all, it carries an
    escape hatch that tells the prover not to check it, or its specification has simply
    been removed while the function stayed.
    """
    defects: list[str] = []
    # Expanded ONCE. `unit_files` re-globs every declared path in the repository, so calling
    # it per unit made this function quadratic in the manifest: 6 units x 381 declared .rs
    # files = 2292 full expansions, measured at 264s for a function that decides nothing
    # about any of them. A local, not a module-level cache: callers pass the manifest, and a
    # cache that outlived one call would answer for the previous manifest.
    owners_by_file = unit_files(verification, repo_root)
    ordered_files = sorted(owners_by_file)
    for unit in verification.get("unit", []):
        symbols = unit.get("proved_symbols", [])
        if not symbols:
            continue
        sources = [
            path
            for path in ordered_files
            if path.suffix == ".rs" and unit["id"] in owners_by_file[path]
        ]
        for symbol in symbols:
            defects += _symbol_defects(_Claim(unit["id"], symbol), sources, repo_root)
    return defects
