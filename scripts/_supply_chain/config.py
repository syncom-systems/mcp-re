# SPDX-License-Identifier: Apache-2.0
"""Where the policy, the lock and the build graph come from, and what the policy may say."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / "config" / "supply-chain.toml"
LOCK = REPO / "bazel" / "crates.lock"
MODULE = REPO / "MODULE.bazel"
HUB = "crates_mcp_re__"
INDEX = "https://index.crates.io"
POLICY_KEYS = {
    "sources": {"allow-registry"},
    "advisories": {"ignore"},
    "licenses": {"allow"},
    "bans": {"deny-multiple-versions", "deny-wildcard-specs", "skip-tree"},
}
DENIED_CLASSES = {None, "unmaintained", "unsound"}
