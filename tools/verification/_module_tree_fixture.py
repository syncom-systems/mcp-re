# SPDX-License-Identifier: Apache-2.0
"""The one fixture tree every module-resolution self-test reads, what `walk` must give for
each of its roots, and the writer that materialises it."""

from __future__ import annotations

from pathlib import Path

#: The one fixture tree every module-resolution self-test reads: both file forms, a
#: `#[path]` from a mod-rs and from a non-mod-rs file, a `#[path]` file's own children, an
#: inline module holding a file module, a test-only module and its child, a commented-out,
#: block-commented, raw-string and char-literal-adjacent `mod`, an unresolved declaration,
#: and a crate root not named `lib.rs`/`main.rs`.
FIXTURE: dict[str, str] = {
    "src/lib.rs": (
        "pub mod alpha;\n"
        "mod beta;\n"
        "// mod ghost_line;\n"
        "/* outer /* inner */\nmod ghost_block;\n*/\n"
        'const F: &str = r#"\nmod ghost_raw;\n"#;\n'
        "const Q: char = '\"';\n"
        '#[path = "elsewhere/gamma_impl.rs"]\n'
        "mod gamma;\n"
        "pub mod outer {\n"
        "    pub mod nested;\n"
        "    mod inline_only {}\n"
        "}\n"
        "#[cfg(test)]\n"
        "mod tests;\n"
        "mod missing;\n"
    ),
    "src/alpha.rs": 'pub mod deep;\n#[path = "pathed.rs"]\nmod pathed;\n',
    "src/alpha/deep.rs": "",
    "src/pathed.rs": "",
    "src/beta/mod.rs": "mod child;\n",
    "src/beta/child.rs": "",
    "src/elsewhere/gamma_impl.rs": "mod sibling;\n",
    "src/elsewhere/sibling.rs": "",
    "src/outer/nested.rs": "",
    "src/tests.rs": "mod helper;\n",
    "src/tests/helper.rs": "",
    "src/ghost_line.rs": "",
    "src/ghost_block.rs": "",
    "src/ghost_raw.rs": "",
    "tests/suite_test.rs": "mod common;\n",
    "tests/common/mod.rs": "",
}

#: What `walk` must give for each fixture root: module path -> (file, test_only).
FIXTURE_TREES: dict[str, dict[tuple[str, ...], tuple[str, bool]]] = {
    "src/lib.rs": {
        (): ("src/lib.rs", False),
        ("alpha",): ("src/alpha.rs", False),
        ("alpha", "deep"): ("src/alpha/deep.rs", False),
        ("alpha", "pathed"): ("src/pathed.rs", False),
        ("beta",): ("src/beta/mod.rs", False),
        ("beta", "child"): ("src/beta/child.rs", False),
        ("gamma",): ("src/elsewhere/gamma_impl.rs", False),
        ("gamma", "sibling"): ("src/elsewhere/sibling.rs", False),
        ("outer", "nested"): ("src/outer/nested.rs", False),
        ("tests",): ("src/tests.rs", True),
        ("tests", "helper"): ("src/tests/helper.rs", True),
    },
    "tests/suite_test.rs": {
        (): ("tests/suite_test.rs", False),
        ("common",): ("tests/common/mod.rs", False),
    },
}


def materialize_fixture(directory: Path, files: dict[str, str] | None = None) -> Path:
    """Write the fixture tree (or `files`) under `directory` and return it."""
    for rel, content in (FIXTURE if files is None else files).items():
        path = directory / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return directory
