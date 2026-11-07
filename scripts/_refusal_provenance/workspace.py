# SPDX-License-Identifier: Apache-2.0
"""Clause 5, whole-workspace: PolicyError has no route into the Core taxonomy.

12c rides along on the SAME walk. Both are whole-workspace absence claims, and walking the
tree twice to ask two questions about each file made the selftest — twenty fixtures, each a
full pass — the slowest thing in the local gate.
"""

from __future__ import annotations

import re

from _refusal_provenance.config import SERVED_JSON, SERVED_RESPONSE_OWNER
from _refusal_provenance.sources import read, workspace_rust_files

POLICY_CONVERSION = r"impl\s+From<&?\s*(mcp_re_policy::)?PolicyError>\s+for\s+McpReError"
POLICY_IN_CORE_ARM = r"RefusalCause::Core\(\s*[A-Za-z_:]*[Pp]olicy"


def _file_problems(rel: str, src: str) -> list[str]:
    problems: list[str] = []
    if re.search(POLICY_CONVERSION, src):
        problems.append(f"{rel}: a PolicyError -> McpReError conversion exists")
    if re.search(POLICY_IN_CORE_ARM, src):
        problems.append(f"{rel}: a PolicyError is being placed in the Core arm")
    return problems


def workspace_scan(overrides: dict[str, str] | None) -> tuple[list[str], set[str]]:
    """The conversion problems of every shipped file, and the files that call the served mint."""
    problems: list[str] = []
    transport_callers: set[str] = set()
    for rel in workspace_rust_files():
        try:
            src = read(rel, overrides)
        except (OSError, UnicodeDecodeError):
            continue
        problems += _file_problems(rel, src)
        if SERVED_JSON in src and rel != SERVED_RESPONSE_OWNER:
            transport_callers.add(rel)
    return problems, transport_callers
