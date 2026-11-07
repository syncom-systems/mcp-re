# SPDX-License-Identifier: Apache-2.0
"""Selftest cases — shell rules: what is a command word, and what only mentions one."""

from __future__ import annotations

#: (path, file text, whether the gate must report a hit)
SHELL_CASES: tuple[tuple[str, str, bool], ...] = (
    ("scripts/a.sh", "cargo test --workspace\n", True),
    ("scripts/a.sh", "  foo && cargo build -p x\n", True),
    ("scripts/a.sh", "timeout 60 cargo clippy\n", True),
    ("scripts/a.sh", "rustup run 1.99.1 cargo fmt\n", True),
    ("scripts/a.sh", '"${CARGO:-cargo}" build\n', True),
    ("scripts/a.sh", "/opt/v/cargo-verus verify -p x\n", True),
    ("scripts/a.sh", "RUSTFLAGS=x cargo build\n", True),
    ("scripts/a.sh", "# cargo test is gone\n", False),
    ("scripts/a.sh", 'echo "run cargo test yourself"\n', False),
    ("scripts/a.sh", "bazel test //... # not cargo test\n", False),
    ("scripts/a.sh", "CARGO_BAZEL_REPIN=1 bazel mod show_extension x\n", False),
    ("scripts/a.sh", "ls ~/.cargo/bin\n", False),
)
