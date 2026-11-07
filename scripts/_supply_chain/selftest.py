# SPDX-License-Identifier: Apache-2.0
"""Every check asserted in BOTH directions: a check that always fails passes the failing half,
and one that never fires passes the passing half."""

from __future__ import annotations

import tempfile
import tomllib
from pathlib import Path

from _supply_chain.checks import (
    advisory,
    affected,
    check_advisories,
    check_bans,
    check_licenses,
    check_policy_keys,
    check_sources,
)
from _supply_chain.config import POLICY
from _supply_chain.graph import lock_packages, resolve_edges
from _supply_chain.index import index_path
from _supply_chain.selftest_cases import (
    ADVISORY_CASES,
    ADVISORY_DOC,
    LICENSE_ALLOW,
    LICENSE_CASES,
    LOCK,
    MATCH_CASES,
    WILDCARD_SPEC,
)
from _supply_chain.semver import matches
from _supply_chain.spdx import license_allowed


class _Expect:
    """Collects every departure from what a check must say."""

    def __init__(self) -> None:
        self.failures: list[str] = []

    def __call__(self, what: str, got: object, want: object) -> None:
        if got != want:
            self.failures.append(f"{what}: got {got!r}, want {want!r}")


def _expect_matching(expect: _Expect) -> None:
    for req, version, want in MATCH_CASES:
        expect(f"matches({req!r}, {version!r})", matches(req, version), want)
    for expr, want in LICENSE_CASES:
        expect(f"license_allowed({expr!r})", license_allowed(expr, LICENSE_ALLOW), want)


def _expect_bans(expect: _Expect) -> None:
    packages = lock_packages(LOCK)
    edges = resolve_edges(packages)
    expect("resolve_edges(unambiguous)", edges[("top", "1.0.0")], [("digest", "0.11.0"), ("ocsp", "0.2.1")])
    graph = [("ocsp", "0.2.1"), ("top", "1.0.0"), ("digest", "0.10.7"), ("digest", "0.11.0")]
    bans: dict = {"deny-multiple-versions": ["digest"], "deny-wildcard-specs": True}
    expect("bans without skip-tree", len(check_bans(graph, edges, bans, "")[0]), 1)
    bans["skip-tree"] = [{"name": "ocsp", "version": "0.2.1", "depth": 1}]
    expect("bans with skip-tree", check_bans(graph, edges, bans, "")[0], [])
    bans["skip-tree"] = [{"name": "ocsp", "version": "0.2.1", "depth": 0}]
    expect("skip-tree depth is bounded", len(check_bans(graph, edges, bans, "")[0]), 1)
    expect("wildcard spec", len(check_bans([], {}, bans, WILDCARD_SPEC)[0]), 1)
    expect("pinned spec", check_bans([], {}, bans, WILDCARD_SPEC.replace('"*"', '"1"'))[0], [])


def _expect_sources_and_licenses(expect: _Expect) -> None:
    packages = lock_packages(LOCK)
    expect("sources: registry", check_sources([("top", "1.0.0")], packages, ["R"]), [])
    expect("sources: git", len(check_sources([("gitdep", "0.1.0")], packages, ["R"])), 1)
    expect("licenses: allowed", check_licenses([("top", "1.0.0")], {"top-1.0.0": "MIT"}, LICENSE_ALLOW), [])
    expect("licenses: denied", len(check_licenses([("top", "1.0.0")], {"top-1.0.0": "GPL-3.0"}, LICENSE_ALLOW)), 1)
    expect("licenses: none", len(check_licenses([("top", "1.0.0")], {"top-1.0.0": ""}, LICENSE_ALLOW)), 1)


def _expect_advisories(expect: _Expect) -> None:
    expect("advisory: affected", affected(advisory(ADVISORY_DOC % ""), "1.0.0"), True)
    expect("advisory: patched", affected(advisory(ADVISORY_DOC % ""), "1.0.1"), False)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "crates" / "top").mkdir(parents=True)
        page = root / "crates" / "top" / "RUSTSEC-0000-0001.md"
        for extra, want, ignore in ADVISORY_CASES:
            page.write_text(ADVISORY_DOC % extra)
            expect(f"check_advisories({extra or 'vulnerability'}, ignore={sorted(ignore)})",
                   len(check_advisories([("top", "1.0.0")], root, ignore)), want)
        page.write_text("# RUSTSEC-0000-0001\n\nNo front matter.\n")
        expect("check_advisories(unreadable)",
               [p.split(" names ")[0] for p in check_advisories([("top", "1.0.0")], root, set())],
               ["ADVISORIES: crates/top/RUSTSEC-0000-0001.md"])


def _expect_index_and_policy(expect: _Expect) -> None:
    expect("index_path(a)", index_path("a"), "1/a")
    expect("index_path(abc)", index_path("abc"), "3/a/abc")
    expect("index_path(Serde)", index_path("Serde"), "se/rd/serde")
    expect("policy: unknown key", len(check_policy_keys({"bans": {"multiple-versions": "warn"}})), 1)
    expect("policy: the committed file", check_policy_keys(tomllib.loads(POLICY.read_text())), [])


def selftest() -> int:
    expect = _Expect()
    _expect_matching(expect)
    _expect_bans(expect)
    _expect_sources_and_licenses(expect)
    _expect_advisories(expect)
    _expect_index_and_policy(expect)
    if expect.failures:
        print("supply-chain gate selftest: FAIL")
        for failure in expect.failures:
            print(f"  - {failure}")
        return 1
    print("supply-chain gate selftest: PASS")
    return 0
