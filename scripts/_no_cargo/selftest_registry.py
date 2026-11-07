# SPDX-License-Identifier: Apache-2.0
"""Selftest cases — TOML registries, maintained command documents, history, and Dockerfiles."""

from __future__ import annotations

#: (path, file text, whether the gate must report a hit)
REGISTRY_AND_DOC_CASES: tuple[tuple[str, str, bool], ...] = (
    ("verification/policy/m.toml", '[[m]]\nprotocol = ["cargo", "test"]\n', True),
    ("verification/policy/m.toml", '[[m]]\nprotocol = ["bazel", "test"]\n', False),
    ("CLAUDE.md", "text\n```sh\ncargo clippy -- -D warnings\n```\n", True),
    ("CLAUDE.md", "Run `cargo clippy -- -D warnings` after every edit.\n", True),
    ("docs/dev/x.md", "- `cargo`: the structural-gates job\n", False),
    ("docs/quickstart-local.md", "```sh\ncargo test -p x\n```\n", True),
    ("deploy/compose/README.md", "```sh\ncargo build\n```\n", True),
    ("CLAUDE.md", "The `Cargo.toml` manifests describe crates.\n```sh\nbazel test //x\n```\n", False),
    ("docs/security/r7.log", "cargo test\n", False),
    ("verification/reviews/p.md", "```sh\ncargo test\n```\n", False),
    ("deploy/docker/Dockerfile", "RUN cargo build --release\n", True),
)
