# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the lane's own false-green catalogue.

`test_mutation_lane.py` runs the cases; they live in `_mutation_lane_cases_*.py` and share
the loaded lane tool, the registered units and the two helpers below.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from _load_tool import load_tool  # noqa: E402
from _manifest import ManifestError, load_verification  # noqa: E402

lane = load_tool("verify-mutations", "verify_mutations_lane")

UNITS = {unit["id"]: unit for unit in load_verification().get("unit", [])}


def make_probe(**overrides):
    probe = {
        "id": "T-01",
        "unit": "http_profile.request_floor_result",
        "theorem": "THM-0014",
        "conjunct": "a conjunct",
        "path": "mcp-re-http-profile/src/verify.rs",
        "anchor": "x",
        "weakening": "y",
        "expect_red": ["body_tamper_fails_closed"],
    }
    probe.update(overrides)
    return probe


def expect_manifest_error(fn, message: str):
    try:
        fn()
    except ManifestError:
        return
    raise AssertionError(message)
