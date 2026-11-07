# SPDX-License-Identifier: Apache-2.0
"""Every claim in the guide's table has a corpus and a harness that reaches it."""

from __future__ import annotations

import json
from pathlib import Path

from _conformance_claims.config import GUIDE, VECTORS_ROOT
from _conformance_claims.corpus import (
    Row,
    declared_tests,
    parse_rows,
    reaches,
    recomputes_digest,
)

Tests = dict[str, tuple[Path, str]]


def _harness_failures(
    row: Row, corpus_name: str, tests: Tests
) -> tuple[list[str], list[str]]:
    """Failures of the named harnesses, and the ones whose declaration reaches the corpus."""
    category, corpus, targets = row
    failures: list[str] = []
    reaching: list[str] = []
    for target in targets:
        declaration = tests.get(target)
        if declaration is None:
            failures.append(
                f"{category!r}: harness {target} is not declared as an "
                "nt_rust_test in any BUILD.bazel"
            )
        elif reaches(declaration[1], corpus_name):
            reaching.append(target)
    if not reaching:
        failures.append(
            f"{category!r}: no declared harness reaches '{corpus}' through data — "
            "a target that never sees the corpus does not execute it"
        )
    return failures, reaching


def _digest_failures(
    category: str, manifest: Path, reaching: list[str], tests: Tests
) -> list[str]:
    digest = json.loads(manifest.read_text(encoding="utf-8")).get("corpus_digest")
    if digest is None or any(recomputes_digest(*tests[t]) for t in reaching):
        return []
    return [
        f"{category!r}: manifest.json publishes a corpus_digest that no "
        "harness reaching this corpus recomputes — a hash nobody checks "
        "reads as a guarantee"
    ]


def _row_failures(root: Path, tests: Tests, row: Row) -> tuple[list[str], str | None]:
    """Failures of one claim, and the corpus name when the claim is advertised."""
    category, corpus, targets = row
    corpus_dir = root / corpus
    manifest = corpus_dir / "manifest.json"
    if not corpus_dir.is_dir():
        return [f"{category!r}: corpus directory '{corpus}' does not exist"], None
    if not manifest.is_file():
        return [f"{category!r}: corpus '{corpus}' has no manifest.json"], None
    if not targets:
        return [f"{category!r}: names no harness target"], corpus_dir.name
    failures, reaching = _harness_failures(row, corpus_dir.name, tests)
    failures += _digest_failures(category, manifest, reaching, tests)
    return failures, corpus_dir.name


def _unadvertised(root: Path, advertised: set[str]) -> list[str]:
    vectors_root = root / VECTORS_ROOT
    if not vectors_root.is_dir():
        return []
    return [
        f"{VECTORS_ROOT}/{child.name}: a corpus with a manifest that the "
        "guide's category table does not advertise — add a row, or remove "
        "the corpus if nothing claims it"
        for child in sorted(vectors_root.iterdir())
        if (child / "manifest.json").is_file() and child.name not in advertised
    ]


def check(root: Path) -> list[str]:
    guide = root / GUIDE
    if not guide.is_file():
        return [f"{GUIDE}: not found"]
    rows, failures = parse_rows(guide.read_text(encoding="utf-8"))
    if failures:
        return failures
    tests = declared_tests(root)
    advertised: set[str] = set()
    for row in rows:
        row_failures, name = _row_failures(root, tests, row)
        failures += row_failures
        if name is not None:
            advertised.add(name)
    return failures + _unadvertised(root, advertised)
