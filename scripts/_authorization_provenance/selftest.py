# SPDX-License-Identifier: Apache-2.0
"""The gate's selftest: every claim, undone, must be caught."""

from __future__ import annotations

from _authorization_provenance.authority import check_authority
from _authorization_provenance.config import AUTHORITY_DIR, REPO
from _authorization_provenance.rusttext import body_of
from _authorization_provenance.selftest_cases import AuthorityCase, TextCase, authority_cases, text_cases
from _authorization_provenance.sources import authority_sources

GENERIC = "pub(super) async fn admit_request<'a>(ex: &mut X<'a>) -> R<'a> { go() }"


class Tally:
    """Counts the failed cases of one selftest run."""

    def __init__(self) -> None:
        self.failures = 0

    def failed(self, count: int = 1) -> None:
        self.failures += count


def _collision_cases(tally: Tally, sources: dict[str, str]) -> None:
    """THE GATE'S OWN DEFECT, pinned. Keying the source map by BASENAME silently collapsed
    `authorization/mod.rs` and `authorization/pdp/mod.rs` into one entry, so the gate
    examined a strict subset of the authority it claimed to cover — and said nothing. The
    extension that exposed it is exactly the kind that will happen again."""
    by_name: dict[str, list[str]] = {}
    for path in sources:
        by_name.setdefault(path.rsplit("/", 1)[-1], []).append(path)
    collisions = {n: p for n, p in by_name.items() if len(p) > 1}
    if not collisions:
        print(
            "  FAIL basename collision: the authority no longer contains two same-named "
            "modules, so this control is measuring nothing. Point it at a real pair."
        )
        tally.failed()
        return
    for name, paths in sorted(collisions.items()):
        missing = [p for p in paths if p not in sources]
        if missing:
            tally.failed()
        print(
            f"  {'ok ' if not missing else 'FAIL'} basename collision: all {len(paths)} `{name}` files are "
            f"examined ({', '.join(sorted(paths))})"
        )


def _baseline_case(tally: Tally, sources: dict[str, str]) -> None:
    clean = check_authority(sources)
    if not clean:
        print("  ok  baseline: the live authority is clean")
        return
    print("  FAIL baseline: the live tree already has problems")
    for problem in clean:
        print(f"        {problem}")
    tally.failed()


def _report(tally: Tally, name: str, found: list[str], expected: int) -> None:
    ok = len(found) == expected
    if not ok:
        tally.failed()
    print(f"  {'ok ' if ok else 'FAIL'} {name}: {len(found)} problem(s), expected {expected}")
    if not ok:
        for problem in found:
            print(f"        {problem}")


def _run_authority_cases(tally: Tally, sources: dict[str, str], cases: list[AuthorityCase]) -> None:
    for case in cases:
        _report(tally, case.name, check_authority(case.apply(sources)), case.expected)


def _run_text_cases(tally: Tally, cases: list[TextCase]) -> None:
    for case in cases:
        _report(tally, case.name, case.check(case.text), case.expected)


def _generic_case(tally: Tally) -> None:
    """A function with a lifetime or generic parameter list is still found: the region
    assembly is `admit_request<'a>`, and a matcher that wanted `(` straight after the name
    reported it missing."""
    found = body_of(GENERIC, "admit_request") == "{ go() }"
    if not found:
        tally.failed()
    print(f"  {'ok ' if found else 'FAIL'} a function with a lifetime parameter list is found")


def selftest() -> int:
    tally = Tally()
    sources = authority_sources(REPO / AUTHORITY_DIR)
    print("authorization-provenance selftest")
    _collision_cases(tally, sources)
    _baseline_case(tally, sources)
    cases = authority_cases()
    _run_authority_cases(tally, sources, cases)
    texts = text_cases(sources)
    _run_text_cases(tally, texts)
    _generic_case(tally)
    print(
        f"\nauthorization-provenance selftest: "
        f"{'PASS' if tally.failures == 0 else 'FAIL'} — {len(cases) + len(texts) + 3} case(s)"
    )
    return 1 if tally.failures else 0
