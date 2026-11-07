# SPDX-License-Identifier: Apache-2.0
"""Paths, event sets, caps and the negative-control path tables of the verification-trigger gate."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
WORKFLOWS = REPO / ".github" / "workflows"

sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tools" / "verification"))

import _registries  # noqa: E402

COMPLETE_EVENTS = {"schedule", "workflow_dispatch"}
PROBE_EVENTS = {"pull_request", "schedule", "workflow_dispatch"}
PROBE_MAX_TIMEOUT_MINUTES = 30
PROBE_MAX_UNITS = 20

#: What the negative controls change. Each is a path a complete run must not start on, from
#: either a pull request or a push to main.
CONTROL_PATHS = (
    "MODULE.bazel",
    "MODULE.bazel.lock",
    "bazel/crates.lock",
    "Cargo.lock",
    _registries.relative("toolchains"),
    _registries.relative("verification"),
    "tools/verification/verify",
    "scripts/install_pinned_verus.py",
    "mcp-re-core/src/lib.rs",
    ".github/workflows/verification.yml",
)

#: Paths where a bounded probe may start but `select-units` must defer, because the platform
#: that computes the scope is itself what changed.
PLATFORM_PATHS = (
    "tools/verification/_manifest.py",
    "tools/verification/verify-mutations",
    ".github/workflows/mutation-probe.yml",
)
