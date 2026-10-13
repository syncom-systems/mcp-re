# SPDX-License-Identifier: Apache-2.0
"""What a TRUSTED SEAM is — the single authority, shared by every consumer.

A seam is a place where a proof stops proving and starts trusting: an `uninterp` spec
function, an `external_body`, an `assume_specification`. Two questions in this repository
depend on recognising one, and they used to be answerable only inside `check-assumptions`:

  * IS EVERY SEAM REGISTERED?  — `check-assumptions`, the escape-hatch gate.
  * WHICH TRUST BOUNDARIES DOES A PROOF ACTUALLY CROSS? — `_manifest.boundary_class_violations`.

The second is why this module exists. R9-C022 asked whether six V1 units crossed
`boundary.crypto_primitives`, and the answer turns on the difference between a proof that
CONSUMES an unproved proposition beyond that boundary and one that merely COMPILES
alongside it. Only a seam distinguishes them, so the boundary rule needs the same notion of
"seam" the escape-hatch gate uses — and a second copy of these patterns would be a second
answer to what a seam is, diverging the first time one was updated.

It also owns the seam INVENTORY the escape-hatch gate and the registry cross-check both
read: `scan` and `live_sites` over the tree, `stale_sites` against the registry, the per-site
registration rule, and the vacuity rule at a proved symbol. Each takes the loaded registry
documents and the repository root it reads, so `check-assumptions` and `_registry_refs`
call one implementation rather than one hand-loading the other.

It imports nothing from this package but `_rust_source`: `_manifest` imports it.
"""

from __future__ import annotations

import re
from bisect import bisect_left
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
_COMMENT_TAIL = re.compile(r"//.*$")


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
    stripped = _COMMENT_TAIL.sub("", line)
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


#: `assume_specification[ <path> ]` names its item INSIDE the brackets, so the seam and the
#: item it trusts sit on one line. Bracket-balanced rather than non-greedy: `<[T]>::split_last`
#: contains a `]` of its own, and a non-greedy match truncates it to `<[T` — a site key that
#: silently merges two different standard-library seams.
_ASSUME_SPEC = re.compile(r"\bassume_specification\b")

#: An item declaration, in the forms Verus and Rust both use. `uninterp`, `spec`, `proof`,
#: `open`, `closed`, `tracked` and `ghost` are Verus modifiers; the rest are Rust's.
_ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:default\s+|const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+"
    r"|uninterp\s+|spec\s+|proof\s+|exec\s+|open\s+|closed\s+|tracked\s+|ghost\s+)*"
    r"(?:fn|struct|enum|union|trait|type|mod)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)

#: The block forms that QUALIFY the items inside them. `impl Trait for Type` and `impl Type`
#: both qualify by the TYPE: two `actor_id` methods in two impl blocks of one file are two
#: seams, and a key that could not tell them apart would let one registration license both.
_IMPL = re.compile(r"^\s*(?:unsafe\s+)?impl\b(?P<head>[^{]*)")
_MOD = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{")

#: String and char literals, removed before braces are counted. A `{` inside a literal does
#: not open a block, and a qualifier stack that believed it would mis-attribute every item
#: after it.
_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])'")


def _impl_type(head: str) -> str | None:
    """The TYPE an `impl` block qualifies, from the text between `impl` and `{`."""
    text = head.split(" for ")[-1] if " for " in head else head
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:<.*)?$", text.strip().rstrip("<"))
    if match:
        return match.group(1)
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)", text)
    return match.group(1) if match else None


def _brackets(text: str) -> tuple[int, int]:
    """`(square balance, brace balance)` of `text`, literals removed."""
    bare = _LITERAL.sub("", text)
    return (
        bare.count("[") - bare.count("]"),
        bare.count("{") - bare.count("}"),
    )


def declared_items(lines: list[str]) -> list[tuple[int, str]]:
    """Every item declaration in `lines`, as `(1-based line, qualified name)`, in order.

    ONE forward pass per file, and that is a correctness property rather than a speed one:
    the qualifier of an item is decided by the blocks open above it, so a per-seam walk from
    the top of the file re-derives the same stack once per seam. Over the whole scan — every
    `.rs`, `.lean` and `.v` file a unit declares plus the whole `verification/` tree — that
    is quadratic in the size of the files with the most seams, which are exactly the
    specification files.

    Braces are counted over code with comments and literals removed, and only `impl`/`mod`
    heads contribute a qualifier; every other block adds depth without a name, so
    `verus!{ ... }` and ordinary function bodies do not qualify what they contain.
    """
    items: list[tuple[int, str]] = []
    stack: list[tuple[int, str | None]] = []
    depth = 0
    for index, line in enumerate(lines):
        code = code_of(line)
        match = _ITEM.match(code)
        if match:
            qualifiers = [name for _, name in stack if name]
            items.append((index + 1, "::".join([*qualifiers, match.group("name")])))
        opened = _brackets(code)[1]
        name: str | None = None
        impl_match = _IMPL.match(code)
        mod_match = _MOD.match(code)
        if impl_match:
            name = _impl_type(impl_match.group("head"))
        elif mod_match:
            name = mod_match.group("name")
        if opened > 0:
            stack.append((depth, name))
        depth += opened
        while stack and depth <= stack[-1][0]:
            stack.pop()
    return items


def item_at(lines: list[str], lineno: int, items: list[tuple[int, str]] | None = None) -> str | None:
    """The ITEM a seam on `lineno` (1-based) sits on, qualified by its enclosing block.

    Two shapes, because Verus writes the seam two ways. `assume_specification[ X ]` names
    the trusted symbol in its own brackets and is answered from that line. Every other
    mechanism is an attribute or a modifier on a following item, so the answer is the FIRST
    declaration at or after the seam — never backwards from the item, and never a line
    number.

    A line number is what a registry must not be keyed on: adding a comment above a seam
    would move every key below it, and a registry that goes stale on formatting is one people
    regenerate without reading. The item's NAME is what the trust decision was about.

    The qualifier matters as much as the name. `mcp-re-http-profile/src/block.rs` declares
    `actor_id` twice, in `impl ActorIdentity` and in `impl ResolvedActor`; an unqualified key
    would make them one site, and registering either would license both.

    `items` is `declared_items(lines)`, passed in by a caller answering for several seams in
    one file so the pass is performed once.

    `None` where no declaration follows — a seam that cannot be named cannot be registered,
    and the gate says so rather than inventing a key.
    """
    line = code_of(lines[lineno - 1]) if 0 < lineno <= len(lines) else ""
    if _ASSUME_SPEC.search(line):
        return _assume_spec_item(lines, lineno)
    if items is None:
        items = declared_items(lines)
    index = bisect_left(items, (lineno, ""))
    return items[index][1] if index < len(items) else None


def _assume_spec_item(lines: list[str], lineno: int) -> str | None:
    """The symbol inside `assume_specification[ ... ]`, across line breaks if it wraps."""
    text = ""
    for index in range(lineno - 1, min(lineno + 8, len(lines))):
        text += code_of(lines[index])
        start = text.find("[", text.find("assume_specification"))
        if start < 0:
            continue
        depth = 0
        for offset, char in enumerate(text[start:], start=start):
            depth += (char == "[") - (char == "]")
            if depth == 0:
                return text[start + 1 : offset].strip() or None
    return None


def site_key(
    relative_path: str,
    lines: list[str],
    lineno: int,
    items: list[tuple[int, str]] | None = None,
) -> str | None:
    """`<path>#<qualified item>` — the stable identity of one trusted seam."""
    item = item_at(lines, lineno, items)
    return f"{relative_path}#{item}" if item else None


# -------------------------------------------------------------------- the seam inventory

SCANNED_SUFFIXES = {".rs", ".lean", ".v"}

#: Generated Lean is machine-owned and may legitimately contain extraction artifacts. It is
#: excluded from the token scan and covered instead by the generated-drift gate: a
#: hand-edit there is caught by regeneration mismatch, which is the stronger control.
#:
#: Reproducers are standalone crates outside the Cargo workspace, in no unit's paths and in
#: no lane's input. Nothing there can make any unit's proof pass, so a token there is not an
#: escape hatch — it is a bug report about the prover.
EXCLUDED = ("verification/lean/generated/", "verification/reproducers/")

#: One escape-hatch hit: `(path relative to the root, line, mechanism, line text, owning
#: units, site key)`.
Hit = tuple[Path, int, str, str, frozenset[str], str | None]


def unit_files(verification: dict, repo_root: Path) -> dict[Path, set[str]]:
    """Every existing file a `verification.toml` unit names -> the units that name it."""
    files: dict[Path, set[str]] = {}
    for unit in verification.get("unit", []):
        for declared in unit["paths"]:
            for path in repo_root.glob(declared):
                if path.is_file():
                    files.setdefault(path, set()).add(unit["id"])
    return files


def scan_paths(verification: dict, repo_root: Path) -> list[tuple[Path, bool, frozenset[str]]]:
    """(file, is_production, owning units) for everything in scope, in a stable order."""
    declared = unit_files(verification, repo_root)
    scoped: dict[Path, tuple[bool, frozenset[str]]] = {}
    verification_dir = repo_root / "verification"
    if verification_dir.exists():
        for path in verification_dir.rglob("*"):
            if path.is_file() and path.suffix in SCANNED_SUFFIXES:
                scoped[path] = (False, frozenset(declared.get(path, ())))
    for path, owners in declared.items():
        if path.suffix in SCANNED_SUFFIXES:
            scoped.setdefault(path, (True, frozenset(owners)))
    out = []
    for path in sorted(scoped):
        rel = path.relative_to(repo_root).as_posix()
        if any(rel.startswith(prefix) for prefix in EXCLUDED):
            continue
        is_production, owners = scoped[path]
        out.append((path, is_production, owners))
    return out


def scan(verification: dict, repo_root: Path) -> list[Hit]:
    """Every escape-hatch hit in scope: production Rust in its code forms, the rest in full."""
    hits: list[Hit] = []
    for path, is_production, owners in scan_paths(verification, repo_root):
        mechanisms = PRODUCTION_MECHANISMS if is_production else MECHANISMS
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        rel = path.relative_to(repo_root).as_posix()
        # One declaration pass per file, shared by every seam in it: the qualifier of an item
        # is decided by the blocks open above it, and re-deriving that per seam is quadratic
        # in exactly the specification files that carry the most seams.
        items = declared_items(lines)
        numbered = (
            production_lines(text)
            if is_production
            else list(enumerate(lines, start=1))
        )
        for lineno, line in numbered:
            # Comments are not code: one rule, `code_of`, for this census and for the
            # boundary rule that asks which seams a proof trusts.
            code = code_of(line)
            for name, pattern in mechanisms.items():
                if re.search(pattern, code):
                    hits.append(
                        (
                            path.relative_to(repo_root),
                            lineno,
                            name,
                            line.strip(),
                            owners,
                            site_key(rel, lines, lineno, items),
                        )
                    )
    return hits


def declared_seam_sites(assumptions: dict, repo_root: Path) -> set[str]:
    """The registered sites of `none:` assumptions whose item is declared in the tree.

    A `none:` mechanism (`trusted-seam`, `trusted-primitive`) is a premise no scanner
    pattern can see, so its site is never among the escape-hatch hits and cannot be
    confirmed live by one. It is confirmed the only way it can be: the file exists and
    declares the item the key names. A renamed or moved item stops resolving and is
    reported as stale, exactly as a Verus site is. The key is the one `site_key` derives,
    so an enum variant (not an item) is named by its enum.

    WHAT THIS ESTABLISHES, AND NOTHING MORE: that a file at the registered path declares an
    item of the registered name. It does not establish that the premise holds (a
    `trusted-seam` is by definition not checked by any code), nor that the item still does
    what the premise's justification says, nor that a renamed successor is the same seam. A
    passing site is a location, never a proof; the premise stays `assumed` or
    `external-boundary` in the registry.
    """
    declared: dict[str, set[str]] = {}
    resolved: set[str] = set()
    for entry in assumptions.get("assumption", []):
        if not entry["tool_specific_mechanism"].startswith("none:"):
            continue
        for site in map(str, entry.get("sites", [])):
            path, _, item = site.partition("#")
            if path not in declared:
                try:
                    text = (repo_root / path).read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    text = ""
                declared[path] = {name for _, name in declared_items(text.splitlines())}
            if item in declared[path]:
                resolved.add(site)
    return resolved


def live_sites(
    verification: dict, assumptions: dict, repo_root: Path, hits: list[Hit] | None = None
) -> set[str]:
    """Every seam site the tree declares: each escape-hatch hit's item, and each declared
    item a `none:` premise registers. `hits` is a `scan` the caller already ran."""
    found = scan(verification, repo_root) if hits is None else hits
    return {hit[5] for hit in found if hit[5]} | declared_seam_sites(assumptions, repo_root)


def stale_sites(assumptions: list[dict], live: set[str] | frozenset[str]) -> dict[str, list[str]]:
    """Assumption id -> the registered sites that name no seam in `live`.

    A site key is derived from the ITEM a seam sits on, so it survives formatting but not a
    rename or a deletion. An entry left pointing at a seam that no longer exists reads as
    trust the tree no longer needs.
    """
    out: dict[str, list[str]] = {}
    for entry in assumptions:
        gone = sorted({str(site) for site in entry.get("sites", [])} - set(live))
        if gone:
            out[entry["id"]] = gone
    return out


# -------------------------------------------------------------------- registration


def registered_by_unit(assumptions: dict) -> dict[str, set[tuple[str, str]]]:
    """`(mechanism kind, SITE)` pairs the registry accounts for, per unit in `scope`.

    Scope is what makes registration mean something, and the SITE is what makes it mean one
    thing. `verus:external_body` trusted inside `core.time_rfc3339` is a statement about
    that unit's trusted computing base and no other; collapsing the registry to a set of
    names would hand every unit in the repository whatever any one assumption happened to
    need. Kind-level registration inside a unit had the same defect one level down —
    R9-C037 / R9-C067 / R9-C068: `scope` names whole crates, so one entry licensed every
    present and future site of that mechanism in every file those units declare. The
    registry recorded *"this unit trusts uninterpreted spec functions"*, which is not a fact
    about any seam.

    An assumption with NO `sites` therefore registers NOTHING. That is the fail-closed
    direction and the only one available: the alternative — absent means all — is the rule
    being replaced.
    """
    out: dict[str, set[tuple[str, str]]] = {}
    for entry in assumptions.get("assumption", []):
        mechanism = entry["tool_specific_mechanism"].split(":", 1)[-1]
        sites = [str(site) for site in entry.get("sites", [])]
        for target in entry.get("scope", []):
            target = str(target)
            if target.startswith("unit://"):
                unit_id = target.removeprefix("unit://")
                out.setdefault(unit_id, set()).update((mechanism, site) for site in sites)
    return out


def is_registered(
    mechanism: str,
    site: str | None,
    owners: frozenset[str] | set[str],
    registered: dict[str, set[tuple[str, str]]],
) -> bool:
    """Is THIS SEAM registered by an assumption scoped to a unit that declares its file?

    Three conjuncts, and each one is a way registration could say more than it means: the
    MECHANISM, because trusting an uninterpreted spec function is not trusting an
    `external_body`; the UNIT, because a trusted computing base belongs to the unit whose
    proofs rest on it; and the SITE, because a seam is a place a proof stops proving, and
    the registry is a statement about places.

    A file no unit declares has no owning trusted computing base, so nothing can register a
    mechanism there — which is why the empty owner set answers no rather than yes. A seam
    whose item cannot be named (`site is None`) is likewise unregistrable: it has no
    identity to register.
    """
    if site is None:
        return False
    return any((mechanism, site) in registered.get(unit_id, set()) for unit_id in owners)


# -------------------------------------------------------------------- vacuity at a proved symbol

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
            # Inside a multi-line attribute. A trailing `//` comment here is still prose,
            # so it is stripped before the text is kept — but the brackets on the line are
            # counted from the whole line, because a comment cannot close an attribute.
            block.append(_COMMENT_TAIL.sub("", line))
            depth += _bracket_balance(line)
            continue
        stripped = line.strip()
        if stripped.startswith("#["):
            block.append(_COMMENT_TAIL.sub("", line))
            depth = max(_bracket_balance(line), 0)
            continue
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        if pattern.match(line):
            sites.append((index, "\n".join(block)))
        block = []
    return sites


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
            name = symbol.rsplit("::", 1)[-1]
            pattern = definition_pattern(name)
            sites = 0
            for path in sources:
                lines = path.read_text(encoding="utf-8").splitlines()
                rel = path.relative_to(repo_root).as_posix()
                for index, block in definition_sites(lines, pattern):
                    sites += 1
                    for mechanism, mechanism_pattern in sorted(
                        VACUITY_AT_PROVED_SYMBOL.items()
                    ):
                        if re.search(mechanism_pattern, block):
                            defects.append(
                                f"{unit['id']}: proved symbol {symbol} is annotated "
                                f"`{mechanism}` at {rel}:{index + 1}. The prover is told "
                                f"not to check the function the unit claims to have "
                                f"proved, so the theorem is vacuous while the symbol "
                                f"still appears verified."
                            )
                    if not SPECIFICATION_TEXT.search(block):
                        defects.append(
                            f"{unit['id']}: proved symbol {symbol} at {rel}:{index + 1} "
                            f"carries no `requires`/`ensures`. The specification is a "
                            f"detachable attribute: deleting it leaves the function, the "
                            f"crate's verified count and the prover's symbol list "
                            f"unchanged, so no lane sees the theorem go."
                        )
            if sites == 0:
                defects.append(
                    f"{unit['id']}: proved symbol {symbol} defines no function in the "
                    f"unit's declared paths. A theorem the manifest advertises over source "
                    f"the unit does not declare is invalidated by no change to it."
                )
    return defects
