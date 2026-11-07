# SPDX-License-Identifier: Apache-2.0
"""The gate registry, `config/gates.toml`: one row per script.

The registry says which scripts are gates, where each runs, whether it has a `--selftest`
of its own, and why a script is not a control or not on the merge path. Its consumers:

  * `scripts/merge_path_gate.py` checks `local_gate.sh` and the workflows against the rows
    (`stages`, `ci`) and takes its exemptions from `off_merge_path`;
  * `_controls.gate_controls` takes the census's gate population from it: every
    `scripts/*.py|*.sh` except a row marked `not_a_control`.

This module reads and validates the rows, and checks what can be checked from the files
alone: that every script has a row, that every row names a file, that `selftest`
matches the script's own argument handling, and that a control with no selftest says why.
The checks against `local_gate.sh` and the workflows need the workflow reader and live in
the merge-path gate.

Run:  python3 tools/verification/_gates.py --selftest
"""

from __future__ import annotations

import sys

from _gates_problems import SELFTEST, has_selftest, problems, selftest_problems
from _gates_registry import (
    FIELDS,
    REGISTRY,
    REPO,
    REQUIRED,
    SCRIPTS,
    SUFFIXES,
    Gate,
    RegistryError,
    load,
    not_controls,
    parse,
    population,
)
from _gates_selftest import selftest

__all__ = [
    "FIELDS",
    "REGISTRY",
    "REPO",
    "REQUIRED",
    "SCRIPTS",
    "SELFTEST",
    "SUFFIXES",
    "Gate",
    "RegistryError",
    "has_selftest",
    "load",
    "not_controls",
    "parse",
    "population",
    "problems",
    "selftest",
    "selftest_problems",
]

if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else 0)
