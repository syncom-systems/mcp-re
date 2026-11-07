# SPDX-License-Identifier: Apache-2.0
"""Selftest: the DEFINED population of entry points, asserted against a real temporary tree
rather than a stub, because the definition IS a filesystem property — a stub would only
prove this test and the code agree about a sentence, and the sentence is the thing under
test."""

from __future__ import annotations

import stat
import tempfile
from pathlib import Path

from _merge_path.config import ENTRY_ROOT, REPO
from _merge_path.defects import EntryReach, entry_point_defects
from _merge_path.extract import names_in
from _merge_path.reach import dispatched_entry_points, entry_points
from _merge_path.selftest_support import expect
from workflow_reader import shell_commands

_CONTROL = f"{ENTRY_ROOT}/a-control"

#: `(unconditional, dispatched, exempt, label)`: each way an entry point is reached.
_REACHED = [
    ({_CONTROL}, set(), {}, "named by an unconditional workflow"),
    (set(), {_CONTROL}, {}, "dispatched by the lane catalogue"),
    (set(), set(), {_CONTROL: "decides nothing"}, "exempt with a reason"),
]

_EXEC_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def _build_tree(root: Path) -> Path:
    directory = root / ENTRY_ROOT
    directory.mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    for name in ("a-control", "_a_module.py", "not-a-control"):
        (directory / name).write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    for name in ("a-control", "_a_module.py"):
        path = directory / name
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return directory


def _check_definition(root: Path, directory: Path) -> None:
    found = entry_points(root)
    expect(found == {_CONTROL}, f"the population is {found!r}")
    # The EXECUTE BIT is the discriminator, not the name. Take it away and the same
    # filename leaves the population; that is what makes the census complete by
    # construction rather than by a convention someone has to remember.
    control = directory / "a-control"
    control.chmod(control.stat().st_mode & ~_EXEC_BITS)
    expect(not entry_points(root), "a non-executable file stayed in the population")
    control.chmod(control.stat().st_mode | stat.S_IXUSR)
    # A directory with no entry points must FAIL the caller, not read as agreement —
    # asserted through the same accessor the caller uses.
    expect(not entry_points(root / "nowhere"), "a missing root produced a population")


def _check_entry_point_verdicts() -> None:
    orphaned = entry_point_defects({_CONTROL}, EntryReach(set(), set()), {})
    expect(
        any("reached by no unconditional workflow" in d for d in orphaned),
        f"an unreached entry point passed: {orphaned}",
    )
    for unconditional, dispatched, exempt, label in _REACHED:
        expect(
            not entry_point_defects({_CONTROL}, EntryReach(unconditional, dispatched), exempt),
            f"refused an entry point {label}",
        )
    # Filtered-only is its own message: the remedy differs.
    filtered = entry_point_defects({_CONTROL}, EntryReach(set(), set(), {_CONTROL}), {})
    expect(
        any("`paths:`-filtered" in d for d in filtered),
        f"a filtered-only entry point read as unreached: {filtered}",
    )
    # A dead exemption is a claim about nothing.
    dead = entry_point_defects(set(), EntryReach(set(), set()), {f"{ENTRY_ROOT}/gone": "removed"})
    expect(any("dead exemption" in d for d in dead), f"a dead entry exemption passed: {dead}")


def _check_unreadable_dispatcher(root: Path) -> None:
    """An unreadable dispatcher is ONE defect naming its cause, never nine orphans."""
    _, problem = dispatched_entry_points(root)
    expect(problem is not None, "a tree with no lane catalogue reported a readable LANES table")
    expect(
        bool(entry_point_defects(set(), EntryReach(set(), set(), set(), problem), {})),
        "an unreadable dispatcher produced no defect",
    )


def _check_real_tree() -> None:
    """The real dispatcher must be readable HERE, or the check above proves only that a
    missing file is missing; and the coverage matcher must see an EXTENSIONLESS entry
    point, the shape `scripts_in` is structurally unable to match."""
    lanes, problem = dispatched_entry_points(REPO)
    expect(
        problem is None and bool(lanes),
        f"this tree's lane catalogue could not be read: {problem}",
    )
    expect(
        names_in(shell_commands("./tools/verification/verify-tests")) == {f"{ENTRY_ROOT}/verify-tests"},
        "the coverage matcher cannot see an extensionless entry point",
    )


def check() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _check_definition(root, _build_tree(root))
        _check_entry_point_verdicts()
        _check_unreadable_dispatcher(root)
    _check_real_tree()
