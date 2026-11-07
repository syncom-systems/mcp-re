# SPDX-License-Identifier: Apache-2.0
"""Where the declaration and the records live, and the vocabulary the identity is built from."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SURFACE_TOML = REPO / "config" / "performance-surface.toml"
#: Where a developer's records live when nothing else is configured: inside the checkout.
#: See evidence_store() for naming a durable store outside it.
LOCAL_STORE = REPO / ".verification" / "slo"

#: The one authority naming the durable store. Named consistently with the existing
#: MCP_RE_LOADGEN_HW_CLASS convention in this file.
STORE_ENV = "MCP_RE_SLO_EVIDENCE_STORE"
BASELINE = REPO / "docs" / "bench" / "adr-051-baseline-local.json"
TARGETS = REPO / "docs" / "bench" / "adr-051-slo-targets.json"
SCHEMA = "mcp-re-slo-evidence/v1"

REUSE, REMEASURE = 0, 10

#: The surface sections, in the order they are folded. Named explicitly so that adding a
#: section to the TOML without adding it here cannot silently leave inputs unfingerprinted.
SECTIONS = ("source", "build_configuration", "harness", "envelope", "images")

#: The keys every `[[context.class]]` entry must carry. Named rather than inferred so that
#: a half-written entry fails here instead of at the gate that reads the missing key.
CLASS_KEYS = ("name", "kind", "slo_declarable", "regression_anchor", "github_actions_runner")
