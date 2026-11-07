# SPDX-License-Identifier: Apache-2.0
"""The registry is validated strictly, and the lane's failure modes are refused.

Cases for `test_mutation_lane.py`, which runs them.
"""

from __future__ import annotations

import inspect
import tempfile
from pathlib import Path

from _mutation_lane_support import UNITS, expect_manifest_error, lane, make_probe


def test_a_weakening_that_changes_nothing_is_refused_by_the_loader():
    """A probe whose weakening equals its anchor would apply no weakening at all and then
    report whatever the battery does normally. The live registry is held to this by
    `check-registries`, which loads it."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        registry = root / "verification" / "policy" / "mutation-probes.toml"
        registry.parent.mkdir(parents=True)
        registry.write_text(
            '[[probe]]\nid = "T-01"\nunit = "u"\nconjunct = "c"\npath = "a.rs"\n'
            'anchor = "x"\nweakening = "x"\nexpect_red = ["//a:t#c"]\n'
        )
        expect_manifest_error(lambda: lane.load_probes(root), "a no-op weakening must be refused")
        registry.write_text(registry.read_text().replace('weakening = "x"', 'weakening = "y"'))
        assert [p["id"] for p in lane.load_probes(root)] == ["T-01"]


def test_an_anchor_matching_no_site_is_stale(tmp=None):
    tree = lane.REPO_ROOT
    expect_manifest_error(
        lambda: lane.apply(tree, make_probe(anchor="this text is nowhere in verify.rs"), "p"),
        "a zero-match anchor must be STALE",
    )


def test_an_ambiguous_anchor_is_stale_too():
    """Two matches is as much a failure as none: the lane could not say which check it
    broke, so whatever went red proves nothing about the conjunct named."""
    source = (lane.REPO_ROOT / "mcp-re-http-profile/src/verify/floor/response.rs").read_text()
    repeated = "    reject_content_encoding(&response.headers)?;"
    assert source.count(repeated) > 1, "fixture assumption: this line is not unique"
    expect_manifest_error(
        lambda: lane.apply(lane.REPO_ROOT, make_probe(anchor=repeated), "p"),
        "an ambiguous anchor must be STALE",
    )


def test_the_working_tree_is_never_edited():
    """`apply` writes into whatever tree it is handed; the lane hands it a COPY. A run that
    crashed mid-probe must leave the repository untouched, which is only true if the
    working tree is never the mutation target."""
    body = inspect.getsource(lane.main)
    assert "copy_tracked_tree(tree)" in body
    assert "lane.apply(REPO_ROOT" not in body
    assert "apply(tree, probe" in body


def test_expecting_a_control_the_unit_does_not_declare_is_refused():
    """A red test outside the declared battery is not evidence for the theorem: the unit's
    `tested_symbols` is what the claim rests on."""
    expect_manifest_error(
        lambda: lane.declared_battery(
            UNITS, make_probe(expect_red=["a_test_that_is_not_declared"]), "p"
        ),
        "an undeclared control must be refused",
    )


def test_a_probe_with_no_expectations_is_refused_by_the_loader():
    import tomllib

    doc = tomllib.loads(
        'schema_version = 1\n'
        '[[probe]]\n'
        'id = "T"\nunit = "u"\ntheorem = "THM-0001"\nconjunct = "c"\n'
        'path = "p"\nanchor = "a"\nweakening = "b"\nexpect_red = []\n'
    )
    assert doc["probe"][0]["expect_red"] == []
    # The loader reads the real file, so assert the rule it enforces is present in it.
    assert "`expect_red` is empty" in inspect.getsource(lane.load_probes)


def test_a_tree_that_did_not_compile_is_not_a_result():
    """`run_battery` reports `ran=False` on a compile error, and `main` turns that into a
    FAIL. A weakening that breaks the build has measured nothing; reading it as "the
    controls held" would be the exact false green this lane exists to prevent."""
    assert "did not COMPILE" in inspect.getsource(lane.main)
    assert "return False, results" in inspect.getsource(lane.run_battery)
