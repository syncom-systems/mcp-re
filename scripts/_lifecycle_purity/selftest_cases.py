# SPDX-License-Identifier: Apache-2.0
"""The selftest's scenarios: `(source, should_fail, label)`, in both directions the gate once got wrong."""

from __future__ import annotations

Case = tuple[str, bool, str]


def import_cases() -> list[Case]:
    return [
        ("use std::sync::Arc;\npub enum S { A }\n", True, "a std import outside the allowlist"),
        ("use tokio::runtime::Runtime;\n", True, "an external-crate import"),
        ("pub use crate::app::Thing;\n", True, "a pub use of a production module"),
        ("fn f() { crate::app::helper(); }\n", True, "a crate:: path with no use"),
        (
            "pub struct E;\nimpl std::fmt::Display for E { }\n",
            False,
            "an std::fmt impl, which needs no use and is allowlisted",
        ),
        (
            "pub struct E;\nfn f() { let _: std::sync::Mutex<u8>; }\n",
            True,
            "a std path OUTSIDE the allowlist, reached with no use",
        ),
    ]


def alias_cases() -> list[Case]:
    return [
        (
            "pub enum RuntimeEvent { A }\nuse RuntimeEvent as E;\nfn f() { let _ = E::A; }\n",
            False,
            "a self-alias of a type this file declares",
        ),
        (
            # The shape the real file uses, and the one an earlier regex missed: a `use`
            # indented on its own line inside a function body. It was reported as an
            # external dependency on `E`, because the alias was never recognised as local.
            "pub enum RuntimeEvent { A }\nfn f() {\n    use RuntimeEvent as E;\n    let _ = E::A;\n}\n",
            False,
            "an indented self-alias on its own line inside a body",
        ),
        (
            "pub enum S { A }\nfn f() {\n    use tokio::sync::Mutex;\n}\n",
            True,
            "an indented external import on its own line inside a body",
        ),
        (
            "pub enum RuntimeEvent { A }\nuse tokio as E;\nfn f() { let _ = E::A; }\n",
            True,
            "an import wearing a short alias",
        ),
        (
            "pub enum S { A }\nuse S::*;\nfn f() { let _ = A; }\n",
            False,
            "a glob over the file's own enum",
        ),
    ]


def region_cases() -> list[Case]:
    return [
        (
            "//! Docs mentioning crate::app are fine.\n"
            "// use std::sync::Arc; in a comment is fine\n"
            "pub enum S { A }\n",
            False,
            "prose and commented-out code",
        ),
        (
            "pub enum S { A }\n#[cfg(test)]\nmod tests { use super::*; use tokio; }\n",
            False,
            "the test module, which is out of scope",
        ),
        (
            # The control the truncating form could not pass. Rust puts no constraint on
            # where a test module sits, so a scan that stopped at the first `#[cfg(test)]`
            # reported a clean pass over every line below it.
            "pub enum S { A }\n#[cfg(test)]\nmod tests { use super::*; }\n"
            "fn later() { let _: tokio::sync::Mutex<u8>; }\n",
            True,
            "an external dependency BELOW the test module",
        ),
        (
            # And the shape that made truncation worst in practice: the attribute the scan
            # stopped at was an inline helper, not the test module at all.
            "pub enum S { A }\n#[cfg(test)]\nfn helper() {}\n"
            "fn later() { let _: tokio::sync::Mutex<u8>; }\n",
            True,
            "an external dependency below an INLINE #[cfg(test)] helper",
        ),
        (
            "pub enum S { A }\n#[cfg(all(test, unix))]\nmod tests { use tokio; }\n"
            "pub enum T { B }\n",
            False,
            "the wide #[cfg(all(test, ...))] attribute also opens a region",
        ),
        (
            "pub enum S { A }\n#[cfg(test)]\nuse tokio::sync::Mutex;\npub enum T { B }\n",
            False,
            "an attributed `use ...;` is a one-line region",
        ),
    ]


def child_module_path_cases() -> list[Case]:
    return [
        (
            "pub(crate) mod publication;\npub enum S { A }\nfn f(_: publication::P) {}\n",
            False,
            "a path into a child module the file declares",
        ),
        (
            "pub enum S { A }\nfn f(_: publication::P) {}\n",
            True,
            "a path into a module the file does NOT declare",
        ),
    ]


def module_cases() -> list[Case]:
    return import_cases() + alias_cases() + region_cases() + child_module_path_cases()


def child_cases() -> list[Case]:
    """Checked as a child file, where `super` is the parent."""
    return [
        ("use super::ServedSuccess;\npub struct P(pub(super) ServedSuccess);\n", False,
         "a child reaching its parent through super"),
        ("use super::S;\nuse tokio::sync::Mutex;\n", True,
         "a child importing what its parent may not"),
    ]
