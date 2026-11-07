# SPDX-License-Identifier: Apache-2.0
"""The gate's selftest: static reachability, doctest items and every comparison outcome."""

from __future__ import annotations

from dataclasses import dataclass

from _test_inventory.collect import doctest_items
from _test_inventory.compare import compare
from _test_inventory.static import static_gaps

DOCTEST_LOG = (
    "test a/src/lib.rs - (line 35) - compile ... ok\n"
    "test a/src/lib.rs - Item (line 9) ... ok\n"
    "test a/src/m.rs - m::Other::new (line 4) - compile fail ... ok\n"
)


@dataclass
class Control:
    project: str
    identity: str
    carrier: str = "f.rs"
    line: int = 1


def _static_failures() -> list[str]:
    failures = []
    files = {"a/src/lib.rs": "#[test]\nfn x() {}\n", "a/tests/orphan.rs": "#[tokio::test]\nasync fn y() {}\n",
             "a/src/plain.rs": "fn z() {}\n"}
    gaps = static_gaps(files, {"a/src/lib.rs"})
    if len(gaps) != 1 or "a/tests/orphan.rs" not in gaps[0]:
        failures.append(f"static: an unreached test file must be the one gap, got {gaps}")
    if static_gaps(files, {"a/src/lib.rs", "a/tests/orphan.rs"}):
        failures.append("static: a reached file is not a gap")
    return failures


def _doctest_failures() -> list[str]:
    if doctest_items(DOCTEST_LOG) != ["", "Item", "m::Other::new"]:
        return [f"doctest items: a crate-level doctest must be the empty item, got {doctest_items(DOCTEST_LOG)}"]
    return []


def _inventory() -> dict:
    return {
        "binaries": [
            {"label": "//a:unit", "package": "a", "root": "a/src/lib.rs", "manual": False, "tests": ["m::tests::x"]},
            {"label": "//a:it", "package": "a", "root": "a/tests/t.rs", "manual": False, "tests": ["y"]},
        ],
        "doctests": [{"label": "//a:doc", "package": "a", "items": ["Item"]}],
    }


def _comparison_cases() -> list[tuple[str, dict, dict, str | None]]:
    inventory = _inventory()
    unit, integration = inventory["binaries"]
    manual_only = {**inventory, "binaries": [unit, {**integration, "manual": True}]}
    return [
        ("every reachable test is listed", inventory, {}, None),
        ("a test compiled out of every flavor",
         {**inventory, "binaries": [unit, {**integration, "tests": []}]}, {}, "in no Bazel test binary"),
        ("a test only a manual target lists", manual_only, {}, "only in a `manual` target"),
        ("an allowed manual-only test passes", manual_only, {"a tests/t.rs#*": "LANE: x"}, None),
        ("a same-named test under another root does not count",
         {**inventory, "binaries": [{**unit, "tests": ["m::tests::x", "y"]}]}, {}, "`a tests/t.rs#y`"),
        ("a stale allow entry fails", inventory, {"b *": "LANE: x"}, "matches no gap"),
        ("nothing listed", {"binaries": [], "doctests": []}, {}, "comparing nothing"),
    ]


def _comparison_failures(cases: list[tuple[str, dict, dict, str | None]]) -> list[str]:
    controls = [Control("a", "src/lib.rs#m::tests::x"), Control("a", "tests/t.rs#y"), Control("a", "doc#Item")]
    failures = []
    for label, inv, allowed, expect in cases:
        problems, _ = compare(inv, controls, allowed)
        text = "\n".join(problems)
        if expect is None and problems:
            failures.append(f"{label}: reported {problems}")
        if expect is not None and expect not in text:
            failures.append(f"{label}: expected {expect!r}, got {problems}")
    return failures


def selftest() -> int:
    cases = _comparison_cases()
    failures = _static_failures() + _doctest_failures() + _comparison_failures(cases)
    if failures:
        print("test-inventory gate selftest: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"test-inventory gate selftest: PASS ({len(cases) + 2} cases)")
    return 0
