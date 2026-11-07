# SPDX-License-Identifier: Apache-2.0
"""The adopted lint set, the register it is held against, and the flags that switch the lints on."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REGISTRY_REL = "config/clippy-debt.toml"
REGISTRY = REPO / REGISTRY_REL

# The register readers and the build-graph projection live beside the verification tools.
sys.path.insert(0, str(REPO / "tools" / "verification"))
import _ratchet  # noqa: E402

#: The register's shape: one count per crate and lint, keyed `crate::lint`.
SCHEMA = _ratchet.Schema(
    table="debt",
    key=lambda entry: f"{entry['crate']}::{entry['lint']}",
    required=frozenset({"crate", "lint", "count"}),
    fields=frozenset({"crate", "lint", "count"}),
)

# The ADR-MCPRE-061 §6 thresholds, kept OUT of the repository's `/.clippy.toml`.
# `clippy::excessive_nesting` is warn-by-default with a default threshold of 5, so a value
# in the root config is enforced immediately by every `--all-targets -- -D warnings` lane —
# 164 production sites plus test code, red on the first commit. Handing the aspect this
# directory's `.clippy.toml` confines the strict thresholds to this gate's production lane.
STRICT_CONF = REPO / "config" / "clippy-strict"

# The adopted lint set (ADR-MCPRE-061 §6.5, C-4 and C-5). THIS is what switches them on:
# they are allow-by-default and deliberately absent from `[workspace.lints.clippy]`, because
# every clippy lane in this repo runs `--all-targets -- -D warnings` and a workspace entry
# would turn thousands of existing TEST-code occurrences into hard errors on one commit.
# The ruling exempts test code; running the lints here, over production flavors only,
# exempts it by construction rather than by an allowlist somebody has to maintain.
ADOPTED = (
    "unwrap_used",              # measured at 0 production sites -> denied at zero
    "expect_used",              # 60  -> ratcheted
    "indexing_slicing",         # 69  -> ratcheted
    "too_many_lines",           # 27  -> ratcheted
    "excessive_nesting",        # 164 -> ratcheted
    "arithmetic_side_effects",  # 124 -> ratcheted
    # ADR-MCPRE-061 Amendment 1 §3, Group B. Zero PRODUCTION sites in both the default
    # and the full CI feature lane, but NOT zero in test code — so these cannot be a
    # crate-level `#![deny]` the way the Group A lints are (that would be red under
    # every `--all-targets` lane). This gate's production-only measurement is exactly
    # the mechanism the §6.4 ruling built for that case, so they land here and are
    # denied at zero. They carry no debt entry, for the same reason `unwrap_used` does
    # not: there is nothing to pay off.
    "panic_in_result_fn",       # 0 -> denied at zero
    "exit",                     # 0 -> denied at zero
    "create_dir",               # 0 -> denied at zero
    "assertions_on_result_states",  # 0 -> denied at zero
    "partial_pub_fields",       # 0 -> denied at zero
)

# The lints carrying a debt baseline. Every ADOPTED lint NOT listed here is denied at
# zero — it has no entry in the registry because it has nothing to pay off, and the
# first occurrence fails the gate.
RATCHETED = (
    "expect_used",
    "indexing_slicing",
    "too_many_lines",
    "excessive_nesting",
    "arithmetic_side_effects",
)

# Deliberately NOT adopted; see §6.5.
#   cognitive_complexity — 7 sites, 6 already reported by too_many_lines, and the 7th only
#   because that lint is locally allowed there. Zero independent signal.

LINT_FLAGS = [f"-W clippy::{lint}".split()[i] for lint in ADOPTED for i in (0, 1)]

#: The Bazel label of the strict thresholds, handed to the clippy aspect. Every clippy run in
#: this gate uses it with LINT_FLAGS, so a probe cannot vouch for a configuration the
#: measurement did not use.
STRICT_CONF_LABEL = "//config/clippy-strict:.clippy.toml"

ALLOW_INNER = re.compile(r"#!\[allow\(([^)]*)\)\]")
ALLOW_OUTER = re.compile(r"#\[allow\(([^)]*)\)\]")
# `arithmetic-side-effects-allowed*` exempts whole TYPES from the lint everywhere.
CONF_EXEMPTION = re.compile(r"^\s*arithmetic-side-effects-allowed[a-z-]*\s*=")
