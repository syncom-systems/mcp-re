# SPDX-License-Identifier: Apache-2.0
"""What the files alone show the registry gets wrong: a script with no row, a row with no
file, a `selftest` flag its script contradicts, a control with no selftest and no stated
reason."""

from __future__ import annotations

import re
from pathlib import Path

from _gates_registry import REGISTRY, REPO, SCRIPTS, Gate, population

#: A script that handles `--selftest` itself: the argument quoted as a literal, or a shell
#: `case` arm. An unquoted `--selftest` is an argument the script passes to ANOTHER program,
#: which is how `local_gate.sh` names it on every gate it runs.
SELFTEST = re.compile(r"[\"']--selftest[\"']|--selftest\)")


def has_selftest(text: str) -> bool:
    return bool(SELFTEST.search(text))


def problems(rows: dict[str, Gate], root: Path = REPO) -> list[str]:
    """What the files alone show the registry gets wrong."""
    found: list[str] = []
    for path in sorted(population(root) - rows.keys()):
        found.append(
            f"{path} has no row in {REGISTRY}. Every script under {SCRIPTS}/ is listed, so a "
            f"new one states whether it is a control and where it runs; add its row."
        )
    for path, gate in sorted(rows.items()):
        file = root / path
        if not file.is_file():
            found.append(f"{REGISTRY} has a row for {path}, which does not exist. Remove the row.")
            continue
        if not path.startswith(f"{SCRIPTS}/") and not gate.off_merge_path:
            found.append(
                f"{path} is outside {SCRIPTS}/ and carries no `off_merge_path`; a row outside "
                f"the population exists only to record that exemption."
            )
        actual = has_selftest(file.read_text(encoding="utf-8"))
        if actual != gate.selftest:
            found.append(
                f"{path}: `selftest = {str(gate.selftest).lower()}` but the script "
                f"{'handles' if actual else 'does not handle'} a `--selftest` argument of its own."
            )
        found.extend(selftest_problems(gate))
    return found


def _is_dead_exemption(gate: Gate) -> bool:
    return bool(gate.selftest_exempt) and bool(gate.selftest or gate.not_a_control)


def _is_unexplained_control(gate: Gate) -> bool:
    return not (gate.selftest or gate.not_a_control or gate.selftest_exempt)


def selftest_problems(gate: Gate) -> list[str]:
    """A control with no selftest must say why; an exemption must exempt something.

    A gate whose only proof is that someone read it goes permissive with one edit and
    nothing notices, so a row that is a control and has no `--selftest` fails unless it
    carries `selftest_exempt` with the reason. A row that is not a control needs none.
    """
    if _is_dead_exemption(gate):
        why = "has a selftest" if gate.selftest else "is not a control"
        return [
            f"{gate.path} carries `selftest_exempt` and {why}. A dead exemption is a claim "
            f"about nothing; remove it."
        ]
    if _is_unexplained_control(gate):
        return [
            f"{gate.path} is a control with no `--selftest` and no `selftest_exempt`. Give it "
            f"a selftest that injects the defect it exists to catch and proves red, or record "
            f"in its row why it cannot have one."
        ]
    return []
