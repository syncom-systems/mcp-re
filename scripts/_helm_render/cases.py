# SPDX-License-Identifier: Apache-2.0
"""The case matrices, assembled in the order the gate runs them."""

from __future__ import annotations

from _helm_render.cases_admission import ADMISSION_CASES
from _helm_render.cases_argv_custody import CUSTODY_ARGV_CASES
from _helm_render.cases_argv_flags import FLAG_ARGV_CASES
from _helm_render.cases_drain import DRAIN_CASES
from _helm_render.cases_guards import GUARD_CASES
from _helm_render.cases_manifest import MANIFEST_CASES

CASES: list[tuple[str, dict, bool, str]] = [*GUARD_CASES, *ADMISSION_CASES, *DRAIN_CASES]
ARGV_CASES: list[tuple[str, dict, list[tuple[str, str]], list[str]]] = [
    *FLAG_ARGV_CASES,
    *CUSTODY_ARGV_CASES,
]

__all__ = ["ARGV_CASES", "CASES", "MANIFEST_CASES"]
