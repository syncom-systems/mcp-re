# SPDX-License-Identifier: Apache-2.0
"""Selftest cases — Python and Rust sources: argv lists, shell strings, doc-comment commands, `Command::new`."""

from __future__ import annotations

#: (path, file text, whether the gate must report a hit)
SOURCE_CASES: tuple[tuple[str, str, bool], ...] = (
    ("tools/x.py", 'subprocess.run(["cargo", "test"])\n', True),
    ("tools/x.py", 'argv = [charon, "cargo", "--preset=aeneas"]\n', True),
    ("mcp-re-x/tests/t.rs", '//! cargo test -p mcp-re-x --test t\n', True),
    ("tools/x.py", '"""\nBy hand:\n    cargo test -p x --test y\n"""\n', True),
    ("tools/x.py", '"""\nthe crate name in a cargo test command is not run\n"""\n', False),
    ("mcp-re-x/tests/t.rs", '//! the `test-fixtures` cargo feature, off by default\n', False),
    ("mcp-re-x/tests/t.rs", 'let v = env!("CARGO_MANIFEST_DIR");\n', False),
    ("tools/x.py", 'os.system("cargo build --release")\n', True),
    ("tools/x.py", 'S = """\nset -e\n"$CHARON_EXE" cargo --preset=aeneas\n"""\nrun(["docker", "run", img, "bash", "-c", S])\n', True),
    ("tools/x.py", 'S = "cargo test --workspace"\nsubprocess.run(S, shell=True)\n', True),
    ("tools/x.py", 'S = "cargo is not run here"\nprint(S)\n', False),
    ("tools/x.py", 'RULES = (("cargo", re.compile("x")),)\n', False),
    ("verification/extraction/Dockerfile", "ENV CARGO_HOME=/opt/cargo \\\n", False),
    ("tools/x.py", 'print("cargo test-target gate: OK")\n', False),
    ("tools/x.py", 'names = ["cargo_test_target_gate.py"]\n', False),
    ("x/src/lib.rs", 'let c = Command::new("cargo").arg("build");\n', True),
    ("x/src/lib.rs", 'let c = Command::new(env!("CARGO"));\n', True),
    ("x/src/lib.rs", "// Command::new(\"cargo\") would be wrong here\n", False),
)
