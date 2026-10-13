#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The SEP-2322 `input_required` discriminator must be open-coded in ONE place.

`mcp-re-conformance/tests/mcp_2026_07_28_alignment_test.rs` pins the discriminator's
VALUE, so a rename in the final SEP-2322 text fails a test rather than shipping. But
that guard only protects readers that classify through the shared helper. The literal
had been open-coded in five places — the client core, chain reconstruction, the proxy's
open-leg recorder, and both SDK bindings — each walking the JSON its own way, and three
of them collapsing a malformed non-terminal reply to "terminal". A rename would have
failed the value guard while leaving every one of those readers silently treating
continuations as terminal: exactly the outcome the guard exists to prevent.

This gate pins the structural precondition that makes the value guard meaningful. It is
a text scan because that is the only thing that can detect a SIXTH copy being added — a
type system cannot notice a string that nobody imported.

It lives here rather than in the Rust suite for two reasons: `sdk/` is not Bazel-
addressable, so a hermetic test cannot see the SDK bindings at all; and a whole-tree scan
is what the other repo gates in this directory already do.

Exit 0 clean, 1 on a violation. `--selftest` runs the scan over a temporary tree.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

#: The one shipped source file that may contain the literal.
CANONICAL = "mcp-re-http-profile/src/result_class.rs"

#: Files that legitimately carry the value as DATA rather than as a classification:
#: the spec-alignment guard that pins it, and the inner test backend that MINTS an
#: elicitation. Every entry needs a reason.
DATA_ONLY = {
    # Pins the discriminator's value against the final spec text — it must name it.
    "mcp-re-conformance/tests/mcp_2026_07_28_alignment_test.rs",
    # A test MCP backend that emits an elicitation; the value is payload it produces.
    "tools/fastmcp_inner_backend.py",
    # This gate itself: it cannot search for a literal without naming it.
    "scripts/discriminator_gate.py",
}

SOURCE_SUFFIXES = {".rs", ".ts", ".py"}

#: Not shipped source: build outputs, VCS, vendored third-party trees, the audit
#: workspace, and archived docs.
PRUNE_EXACT = {
    "target",
    ".git",
    "node_modules",
    "bazel-out",
    "work",
    "docs",
    "site-packages",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
}
PRUNE_PREFIX = ("bazel-", ".venv")

#: Test corpora and fixtures carry the value as recorded data.
FIXTURE_MARKERS = ("/tests/", "/test/", "/vectors/", "/fixtures/")

LITERAL = '"input_required"'


def iter_sources(root: Path = REPO):
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            name = entry.name
            if entry.is_dir():
                if name in PRUNE_EXACT or name.startswith(PRUNE_PREFIX):
                    continue
                stack.append(entry)
                continue
            if entry.suffix in SOURCE_SUFFIXES:
                yield entry


def scan(root: Path = REPO) -> tuple[bool, list[str]]:
    """`(canonical copy found, offenders)` for the tree under `root`."""
    offenders: list[str] = []
    found_canonical = False

    for path in iter_sources(root):
        rel = path.relative_to(root).as_posix()
        is_fixture = any(marker in f"/{rel}" for marker in FIXTURE_MARKERS)
        if is_fixture and rel != CANONICAL and rel not in DATA_ONLY:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            continue
        if LITERAL not in text:
            continue
        if rel == CANONICAL:
            found_canonical = True
        elif rel not in DATA_ONLY:
            offenders.append(rel)
    return found_canonical, offenders


def selftest() -> int:
    """A sixth open-coded copy and a missing canonical copy each go red, in a temp tree."""
    import tempfile

    canonical = f"pub const INPUT_REQUIRED: &str = {LITERAL};\n"
    cases = [
        ("only the canonical copy", {CANONICAL: canonical}, True, []),
        (
            "a copy open-coded in shipped source",
            {CANONICAL: canonical, "mcp-re-proxy/src/open_leg.rs": f"if kind == {LITERAL} {{}}\n"},
            True,
            ["mcp-re-proxy/src/open_leg.rs"],
        ),
        (
            "a copy in an SDK binding",
            {CANONICAL: canonical, "sdk/typescript/src/transport.ts": f"x === {LITERAL}\n"},
            True,
            ["sdk/typescript/src/transport.ts"],
        ),
        (
            "the literal in a test fixture",
            {CANONICAL: canonical, "mcp-re-proxy/tests/fixture.rs": f"let k = {LITERAL};\n"},
            True,
            [],
        ),
        ("the canonical copy removed", {"mcp-re-proxy/src/lib.rs": "fn f() {}\n"}, False, []),
    ]
    failures = 0
    for label, files, want_canonical, want_offenders in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, text in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            got_canonical, got_offenders = scan(root)
        ok = got_canonical == want_canonical and sorted(got_offenders) == want_offenders
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}: canonical={got_canonical} offenders={got_offenders}")
        failures += not ok
    if failures:
        print(f"discriminator gate selftest: FAIL ({failures})")
        return 1
    print("discriminator gate selftest: PASS")
    return 0


def main() -> int:
    found_canonical, offenders = scan()

    if not found_canonical:
        print(
            f"discriminator gate: FAIL — the canonical discriminator is missing from {CANONICAL}",
            file=sys.stderr,
        )
        return 1

    if offenders:
        print(
            "discriminator gate: FAIL — the SEP-2322 discriminator is open-coded outside\n"
            f"  {CANONICAL}, so the value drift guard does not cover these readers:",
            file=sys.stderr,
        )
        for rel in sorted(offenders):
            print(f"    - {rel}", file=sys.stderr)
        print(
            "\n  Classify through mcp_re_http_profile::result_class instead. A doc comment\n"
            "  restating the literal counts: it is one more copy to drift.",
            file=sys.stderr,
        )
        return 1

    print(f"discriminator gate: OK — the SEP-2322 discriminator lives only in {CANONICAL}")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main())
