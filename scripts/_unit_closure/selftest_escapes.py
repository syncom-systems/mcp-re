"""Selftest properties P1-P4, P10 and P11: what the module-tree rules flag, and what not."""

from __future__ import annotations

from _unit_closure.selftest_support import NAMESPACE, Verdicts, problems_of, unit


def p1_split_escape(v: Verdicts) -> None:
    """The split escape, the shape that shipped three times."""
    p = problems_of(
        {
            "c/src/lib.rs": "pub mod sp;\n",
            "c/src/sp/mod.rs": "mod rotation;\npub fn advance() {}\n",
            "c/src/sp/rotation.rs": "pub fn rotate() {}\n",
        },
        [unit("u.sp", "c/src/sp/mod.rs")],
        {},
    )
    v.case("P1 split escape", p, "c/src/sp/rotation.rs")
    v.case("P1 names the unit", p, "u.sp")


def p2_rename_escape(v: Verdicts) -> None:
    """The rename escape: the `paths` entry was updated, the extraction was not."""
    p = problems_of(
        {
            "c/src/lib.rs": "pub mod a;\n",
            "c/src/a/mod.rs": "mod new;\n",
            "c/src/a/new.rs": "mod extracted;\npub fn decide() {}\n",
            "c/src/a/new/extracted.rs": "pub fn also_decides() {}\n",
        },
        [unit("u.a", "c/src/a/mod.rs", "c/src/a/new.rs")],
        {},
    )
    v.case("P2 rename escape", p, "c/src/a/new/extracted.rs")


def p3_parent_escape(v: Verdicts) -> None:
    """The parent escape: a deciding parent outside every closure."""
    decider = {
        "c/src/lib.rs": "pub mod b;\n",
        "c/src/b/mod.rs": "mod child;\npub fn decide() -> bool { true }\n",
        "c/src/b/child.rs": "pub fn helper() {}\n",
    }
    p = problems_of(decider, [unit("u.b", "c/src/b/child.rs")], {})
    v.case("P3 parent escape", p, "UC-2")
    v.case("P3 names the parent", p, "c/src/b/mod.rs")


def p4_namespace_exemption(v: Verdicts) -> None:
    """A namespace parent is not an escape."""
    p = problems_of(
        {"c/src/lib.rs": "pub mod b;\n", "c/src/b/mod.rs": NAMESPACE, "c/src/b/child.rs": ""},
        [unit("u.b", "c/src/b/child.rs")],
        {},
    )
    v.case("P4 namespace exemption", p, None)


def p10_non_code_mod(v: Verdicts) -> None:
    """A `mod` in a comment or a string is not a declaration."""
    p = problems_of(
        {
            "c/src/lib.rs": "pub mod b;\n",
            "c/src/b/mod.rs": '// mod ghost;\nfn f() { let s = "mod ghost;"; }\nmod child;\n',
            "c/src/b/child.rs": "",
        },
        [unit("u.b", "c/src/b/mod.rs", "c/src/b/child.rs")],
        {},
    )
    v.case("P10 non-code mod is not a declaration", p, None)


def p11_both_module_forms(v: Verdicts) -> None:
    """Both module forms resolve."""
    for shape, files in (
        ("file form", {"c/src/x/a.rs": ""}),
        ("directory form", {"c/src/x/a/mod.rs": ""}),
    ):
        p = problems_of(
            {"c/src/lib.rs": "pub mod x;\n", "c/src/x/mod.rs": "mod a;\n", **files},
            [unit("u.x", "c/src/x/mod.rs")],
            {},
        )
        v.case(f"P11 {shape}", p, "UC-1")


ALL = (
    p1_split_escape,
    p2_rename_escape,
    p3_parent_escape,
    p4_namespace_exemption,
    p10_non_code_mod,
    p11_both_module_forms,
)
