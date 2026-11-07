# SPDX-License-Identifier: Apache-2.0
"""Selftest cases — workflow steps, package.json scripts and pyproject build backends."""

from __future__ import annotations

#: (path, file text, whether the gate must report a hit)
WORKFLOW_AND_MANIFEST_CASES: tuple[tuple[str, str, bool], ...] = (
    (".github/workflows/x.yml", "jobs:\n  a:\n    steps:\n      - run: rustup show && cargo --version\n", True),
    (".github/workflows/x.yml", "jobs:\n  a:\n    steps:\n      - uses: EmbarkStudios/cargo-deny-action@v1\n", True),
    (".github/workflows/x.yml", "jobs:\n  a:\n    name: cargo build + test (1.99.1)\n    steps:\n      - run: true\n", False),
    (".github/workflows/x.yml", "jobs:\n  a:\n    steps:\n      - run: |\n          bazel build //x \\\n            && cargo test\n", True),
    (".github/workflows/x.yml", "jobs:\n  a:\n    steps:\n      - run: |\n          # cargo test is gone\n          bazel test //x\n", False),
    (".github/workflows/x.yml", "x: &anchor 1\n", True),
    ("sdk/typescript/package.json", '{"scripts": {"b": "napi build --platform"}}', True),
    ("sdk/typescript/package.json", '{"scripts": {"b": "node scripts/build-native.mjs"}}', False),
    ("sdk/python/pyproject.toml", '[build-system]\nbuild-backend = "maturin"\n', True),
)
