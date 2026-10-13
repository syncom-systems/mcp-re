#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serving-product provenance gate — the ratified theorem architecture, THM-0051.

WHAT THIS PROVES, exactly, over production Rust (test regions excluded):

  1. **The serving assembly verifies once.** `handle` calls `verify_stage` exactly once and
     builds exactly one `Exchange`. Two verifications would put two products in scope and
     make "the one the pipeline holds" a question about source order.
  2. **The serving path has one verification stage.** `verify_stage` is named exactly twice
     across the subtree — its definition and that one call. None is a path that dispatches
     without verifying; more is a second product nothing sequenced.
  3. **The stage hands its product to the machine.** `verify_stage` reaches
     `progress.establish`, so the exchange learns that verification ran by the value being
     CONSUMED rather than by anyone remembering to say so.
  4. **Nothing in the proxy fabricates a verified request.** No production module of
     `mcp-re-proxy` constructs a `VerifiedMcpRequest` literal. The product enters this crate
     from `Verifier::verify_request` or not at all.
  5. **The exchange carries the product; it does not restate it.** `Exchange` has no `pub`
     field, so no consumer can be handed one assembled from parts.
  6. **The product the exchange carries is read-only from verification on.** `Exchange` holds
     it as `&'a VerifiedMcpRequest` — a shared reference, so no stage can assign a field
     through the carrier — and `handle` binds the verifier's return immutably and never
     borrows it mutably or assigns into it. This is the fact THM-0034's subject projection
     rests on: the fields are public, so only the binding keeps them as verified.

WHY THIS GATE AND NOT A TYPE. `VerifiedMcpRequest` has PUBLIC fields. It is
`#[non_exhaustive]`, so no crate but `mcp-re-http-profile` can write one by struct expression,
but any holder can assign the fields of one — which is why every verifier theorem's `scope`
says it characterizes values the operation RETURNED and not values that happen to have the
type. The obvious fix is to make the fields private, and it is not available: the Verus
obligation on `prepare_http_dispatch` reads `verified.request_block` as a FIELD so the prover
can relate the obligation to the value, and `#[verifier::external_type_specification]` refuses a
non-public field. A proved postcondition outranks a seal (`docs/dev/sealed-owners.md`), so
the seam stays open and this gate is what stands in the gap — as EVIDENCE, never as
unconstructibility. Delete it and a second product compiles.

WHAT IT DOES NOT PROVE: that the verification was correct (THM-0014/THM-0015), that the
product is not substitutable for a weaker one (THM-0047), or that a crate outside this
workspace cannot fabricate one. Its claim stops at the shape of the serving route.

Run:  python3 scripts/serving_product_provenance_gate.py
      python3 scripts/serving_product_provenance_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))

import _module_tree  # noqa: E402
from _rust_source import crate_sources, production_view  # noqa: E402
import _rust_targets  # noqa: E402

#: The serving path, read as an owner subtree: MCPRE-175 split the assembly into one module
#: per region, so a gate reading only `mod.rs` would count zero.
SERVING = "mcp-re-proxy/src/http_profile_serve"

#: The crate whose production half may not fabricate the product.
PROXY = "mcp-re-proxy/src"

PRODUCT = "VerifiedMcpRequest"
STAGE = "verify_stage"
CARRIER = "Exchange"

def signature_re(name: str) -> re.Pattern:
    return re.compile(r"fn\s+" + name + r"\s*\((?P<params>.*?)\)\s*->[^{]*\{", re.S)


def body_of(text: str, name: str) -> str | None:
    match = signature_re(name).search(text)
    if match is None:
        return None
    depth = 0
    start = match.end() - 1
    for offset in range(start, len(text)):
        if text[offset] == "{":
            depth += 1
        elif text[offset] == "}":
            depth -= 1
            if depth == 0:
                return text[start : offset + 1]
    return None


def struct_body(text: str, name: str) -> str | None:
    match = re.search(r"\bstruct\s+" + name + r"\b[^{;]*\{", text)
    if match is None:
        return None
    depth = 0
    start = match.end() - 1
    for offset in range(start, len(text)):
        if text[offset] == "{":
            depth += 1
        elif text[offset] == "}":
            depth -= 1
            if depth == 0:
                return text[start : offset + 1]
    return None


def test_only_modules(crate_roots: list[Path]) -> set[Path]:
    """Every file `crate_roots` reach only through `#[cfg(test)]`.

    Measured rather than listed. A module declared under `#[cfg(test)]` in its PARENT
    carries no attribute of its own, so a per-file scan reads all of it as production —
    `authorization/action_harness.rs` fabricates verified requests for controls, and a gate
    that missed this would report production fabrications that exist in no shipped binary.
    The parent is the authority on whether the module exists in a shipped binary, and
    `_module_tree` is the one reader of parents: a file reached by any non-test path from
    any crate root stays production.
    """
    test_only: set[Path] = set()
    production: set[Path] = set()
    for crate_root in crate_roots:
        for module in _module_tree.walk(crate_root).files:
            (test_only if module.test_only else production).add(module.path.resolve())
    return test_only - production


def shipped_files(root: Path, crate_roots: list[Path]) -> list[Path]:
    """Every `.rs` under `root` except those `crate_roots` reach only under `#[cfg(test)]`."""
    excluded = test_only_modules(crate_roots)
    return [p for p in crate_sources(root) if p.resolve() not in excluded]


def production_sources(root: Path) -> dict[str, str]:
    """Every shipped `.rs` under `root`, keyed by relative path, test regions removed."""
    prefix = root.resolve().relative_to(REPO.resolve()).as_posix() + "/"
    crate_roots = [REPO / r for r in sorted(_rust_targets.crate_roots()) if r.startswith(prefix)]
    return {
        str(p.relative_to(REPO)): production_view(p).without_comments()
        for p in shipped_files(root, crate_roots)
    }


def _selftest_test_only() -> int:
    """The exclusion itself, on the module-tree fixture: a file reached only under
    `#[cfg(test)]` is not shipped, and one a second root reaches without it stays shipped."""
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        tree = _module_tree.materialize_fixture(Path(tmp))
        src = tree / "src"
        lib = src / "lib.rs"
        shipped = {p.relative_to(src).as_posix() for p in shipped_files(src, [lib])}
        if "tests.rs" in shipped or "tests/helper.rs" in shipped:
            print(f"SELFTEST FAILED: a module reached only under #[cfg(test)] was shipped: {sorted(shipped)}")
            failures += 1
        if not {"alpha.rs", "outer/nested.rs"} <= shipped:
            print(f"SELFTEST FAILED: a production module was excluded: {sorted(shipped)}")
            failures += 1
        (src / "bin.rs").write_text('#[path = "tests.rs"]\nmod t;\n', encoding="utf-8")
        both = {p.relative_to(src).as_posix() for p in shipped_files(src, [lib, src / "bin.rs"])}
        if "tests.rs" not in both:
            print("SELFTEST FAILED: a file a second root reaches without #[cfg(test)] was excluded")
            failures += 1
    return failures


def read_subtree(sources: dict[str, str], prefix: str) -> str:
    """One subtree's production source. Each member is reduced SEPARATELY before joining —
    concatenating first would let one file's unterminated region swallow the next file's
    code, and the exactly-once counts are precisely what that would corrupt."""
    return "\n".join(t for p, t in sources.items() if p.startswith(prefix))


def check_serving(serving: str) -> list[str]:
    """(1), (2), (3), (5)."""
    problems: list[str] = []
    handle = body_of(serving, "handle")
    if handle is None:
        problems.append(f"{SERVING}: `handle` not found. The assembly is where the regions are ordered.")
    else:
        verified = len(re.findall(r"\b" + STAGE + r"\s*\(", handle))
        if verified != 1:
            problems.append(
                f"{SERVING}: `handle` calls `{STAGE}` {verified} time(s); expected exactly 1. "
                f"Two verifications put two products in scope, and which one the dispatch "
                f"holds becomes a question about source order."
            )
        carriers = len(re.findall(r"\b" + CARRIER + r"\s*\{", handle))
        if carriers != 1:
            problems.append(
                f"{SERVING}: `handle` builds {carriers} `{CARRIER}`; expected exactly 1. The "
                f"exchange is what carries the product to every stage after verification."
            )
    named = len(re.findall(r"\b" + STAGE + r"\s*\(", serving))
    if named != 2:
        problems.append(
            f"{SERVING}: names `{STAGE}` {named} time(s); expected exactly 2 (its definition "
            f"and one call). None is a serving path that dispatches without verifying; more "
            f"is a second product nothing sequenced."
        )
    stage = body_of(serving, STAGE)
    if stage is None:
        problems.append(f"{SERVING}: `{STAGE}` not found.")
    elif "progress.establish" not in stage:
        problems.append(
            f"{SERVING}: `{STAGE}` no longer hands its product to `progress.establish`. The "
            f"machine learns verification ran by the value being CONSUMED; a stage that "
            f"returned the product plainly would let the pipeline advance without it."
        )
    fields = struct_body(serving, CARRIER)
    if fields is None:
        problems.append(f"{SERVING}: `{CARRIER}` not found.")
    elif re.search(r"^\s*pub(\s|\()", fields, re.M):
        problems.append(
            f"{SERVING}: `{CARRIER}` has a `pub` field. The carrier holds borrowed products; "
            f"a public field lets a consumer be handed one assembled from parts."
        )
    if fields is not None:
        problems += check_read_only(handle, fields)
    return problems


def check_read_only(handle: str | None, fields: str) -> list[str]:
    """(6) — the carried product cannot be written after verification."""
    problems: list[str] = []
    shared = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?verified:\s*&'a\s+" + PRODUCT + r"\s*,", re.M)
    if not shared.search(fields):
        problems.append(
            f"{SERVING}: `{CARRIER}::verified` is no longer `&'a {PRODUCT}`. The product's "
            f"fields are public; only a shared borrow keeps every stage from assigning one, "
            f"and the subject THM-0034 projects is read from it."
        )
    if handle is None:
        return problems
    if not re.search(r"\blet\s+verified\s*=", handle):
        problems.append(
            f"{SERVING}: `handle` no longer binds the verifier's return as an immutable "
            f"`let verified`. A mutable binding lets the assembly rewrite the product the "
            f"exchange then carries."
        )
    writes = re.findall(r"&\s*mut\s+verified\b|\bverified(?:\.\w+)+\s*(?:[-+*/|&^]?=)(?!=)", handle)
    if writes:
        problems.append(
            f"{SERVING}: `handle` writes the verified product ({len(writes)} site(s)). What "
            f"verification returned is what every later stage must read."
        )
    return problems


def check_no_fabrication(sources: dict[str, str]) -> list[str]:
    """(4) — nothing in the proxy's production half constructs the product."""
    problems: list[str] = []
    for path, text in sources.items():
        count = len(re.findall(r"\b" + PRODUCT + r"\s*\{", text))
        if count:
            problems.append(
                f"{path}: constructs `{PRODUCT}` {count} time(s) in production. The product's "
                f"fields are public, so possession proves nothing on its own — the serving "
                f"path's claim is that it holds the one `Verifier::verify_request` returned, "
                f"and a literal built here is exactly the counterexample."
            )
    return problems


def check(repo: Path) -> tuple[list[str], int]:
    sources = production_sources(repo / PROXY)
    serving = read_subtree(sources, SERVING)
    if not serving.strip():
        raise SystemExit(f"{SERVING}: no production source found — a gate with an empty scope measures nothing")
    return check_serving(serving) + check_no_fabrication(sources), len(sources)


# --------------------------------------------------------------------------------------
# Selftest: every claim, undone, must be caught.
# --------------------------------------------------------------------------------------

def selftest() -> int:
    sources = production_sources(REPO / PROXY)
    serving = read_subtree(sources, SERVING)
    failures = 0
    cases = [
        (
            "a second verification in the assembly",
            check_serving,
            serving.replace(
                "let verified = match self.verify_stage(&http_req, now, &mut progress) {",
                "let _second = self.verify_stage(&http_req, now, &mut progress);\n"
                "        let verified = match self.verify_stage(&http_req, now, &mut progress) {",
            ),
            # The assembly count AND the subtree count both move: one edit, two claims.
            2,
        ),
        (
            "the stage no longer handing its product to the machine",
            check_serving,
            serving.replace("Ok(verified) => Ok(progress.establish(verified)),", "Ok(verified) => Ok(verified),"),
            1,
        ),
        (
            "a public field on the carrier",
            check_serving,
            serving.replace("    verified: &'a VerifiedMcpRequest,", "    pub verified: &'a VerifiedMcpRequest,"),
            1,
        ),
        (
            "the carrier holding the product mutably",
            check_serving,
            serving.replace("    verified: &'a VerifiedMcpRequest,", "    verified: &'a mut VerifiedMcpRequest,"),
            1,
        ),
        (
            "a mutable binding of the verifier's return",
            check_serving,
            serving.replace(
                "let verified = match self.verify_stage(",
                "let mut verified = match self.verify_stage(",
            ),
            1,
        ),
        (
            "an assignment into the verified product",
            check_serving,
            serving.replace(
                "let actor_id = verified.resolved_actor().actor_id();",
                "verified.audience = String::new();\n        let actor_id = verified.resolved_actor().actor_id();",
            ),
            1,
        ),
        (
            "a fabricated product in the production tree",
            check_no_fabrication,
            {**sources, "fake.rs": "fn back_door() -> VerifiedMcpRequest { VerifiedMcpRequest { floor } }"},
            1,
        ),
    ]
    for name, fn, argument, expected in cases:
        found = fn(argument)
        ok = len(found) == expected
        failures += 0 if ok else 1
        print(f"  {'ok ' if ok else 'FAIL'} {name}: {len(found)} problem(s), expected {expected}")
        if not ok:
            for problem in found:
                print(f"        {problem}")
    failures += _selftest_test_only()
    print()
    if failures:
        print(f"serving-product provenance selftest: FAIL — {failures} case(s) not caught")
        return 1
    print(f"serving-product provenance selftest: PASS — {len(cases)} case(s)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    problems, examined = check(REPO)
    if problems:
        print("serving-product provenance gate: FAILED")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(
        f"serving-product provenance gate: OK — {examined} production module(s) examined; "
        f"the serving path verifies once, hands the product to the exchange machine, and "
        f"nothing in this crate fabricates one."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
