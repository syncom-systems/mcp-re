# SPDX-License-Identifier: Apache-2.0
"""The fingerprint's read set: every file the fingerprint opens is named by it, and nothing is read beside the source-tree seam."""

from __future__ import annotations

from pathlib import Path
import sys

import _tree
from _assumptions import load_assumptions
from _manifest import load_verification
from _toolchain_lock import load_toolchains
from _measured_inputs_support import (
    ASSUMPTIONS,
    DOC,
    HERE,
    TOOLCHAINS,
    UNITS,
    measure,
    perturbed_fingerprints,
)


def unit_read_sets() -> dict[str, frozenset[str]]:
    from _fingerprint import Registries
    from _fingerprint import fingerprint_read_set

    return {
        unit_id: fingerprint_read_set(unit, Registries(DOC, TOOLCHAINS, ASSUMPTIONS))
        for unit_id, unit in UNITS.items()
    }


#: One listing of what git tracks, reused by every observing tree below.
TRACKED = _tree.WorkingTree()


class ObservingTree(_tree.WorkingTree):
    """The checkout, noting every file read through it. It memoizes nothing, so a value a
    previous unit derived is read again and observed again."""

    def __init__(self) -> None:
        super().__init__()
        self.read_paths: set[str] = set()

    def read(self, rel: str) -> bytes:
        self.read_paths.add(rel)
        return super().read(rel)

    def memo(self, key, compute):
        return compute()

    def tracked(self) -> frozenset[str]:
        return _tree.WorkingTree.tracked(TRACKED)


def test_the_read_set_holds_every_file_the_fingerprint_opens():
    """The trigger gate requires a workflow filter for every path in the read set, so a
    file the fingerprint reads and the read set omits is a change that moves the evidence
    and re-runs nothing. Observed at the source-tree seam: every read the fingerprint makes
    goes through `_tree.current()`, and each one must be in that unit's read set. That no
    read goes AROUND the seam is the next test's proposition.

    A file the fingerprint never reads cannot move it by its bytes; what it can do by
    EXISTING — appearing under a declared glob — reaches the read set as a tracked file on
    the very change that adds it."""
    import _fingerprint

    missing: dict[str, list[str]] = {}
    observed = 0
    for unit_id, unit in UNITS.items():
        observer = ObservingTree()
        with _tree.reading(observer):
            read_set = _fingerprint.fingerprint_read_set(
                unit, _fingerprint.Registries(DOC, TOOLCHAINS, ASSUMPTIONS)
            )
        observed += len(observer.read_paths)
        if observer.read_paths - read_set:
            missing[unit_id] = sorted(observer.read_paths - read_set)
    assert observed, "nothing was observed reading a file — the seam measured nothing"
    assert not missing, f"read by the fingerprint but absent from its read set: {missing}"


def test_the_fingerprint_reads_nothing_beside_its_tree():
    """Every byte a fingerprint depends on comes through the source-tree seam.

    The seam's observations are only as complete as the seam: a reader that resolved a path
    against the checkout directly would be invisible to the test above and would make
    `select-units` measure the base commit with HEAD's bytes. So the tools are copied to a
    scratch root that holds NOTHING else, and every unit is fingerprinted there over the
    commit tree of HEAD. A read that bypasses the tree finds no file under that root and
    the run fails or diverges; equal fingerprints mean every read went through the seam."""
    import json
    import shutil
    import subprocess
    import tempfile

    import _fingerprint
    from _manifest import REPO_ROOT as ROOT

    script = (
        "import json, sys\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from pathlib import Path\n"
        "import _tree\n"
        "from _fingerprint import Registries, fingerprint_unit\n"
        "from _manifest import load_verification\n"
        "from _assumptions import load_assumptions\n"
        "from _toolchain_lock import load_toolchains\n"
        "tree = _tree.CommitTree('HEAD', Path(sys.argv[2]))\n"
        "with _tree.reading(tree):\n"
        "    doc = load_verification(tree_checks=False)\n"
        "    tc, asm = load_toolchains(), load_assumptions(tree_checks=False)\n"
        "    print(json.dumps({u['id']: fingerprint_unit(u, Registries(doc, tc, asm))['fingerprint']\n"
        "                      for u in doc['unit']}))\n"
    )
    with tempfile.TemporaryDirectory(prefix="mcp-re-seam-") as scratch:
        tools = Path(scratch) / "tools" / "verification"
        shutil.copytree(HERE, tools, ignore=shutil.ignore_patterns("__pycache__"))
        proc = subprocess.run(
            [sys.executable, "-c", script, str(tools), str(ROOT)],
            cwd=scratch, capture_output=True, text=True,
        )
    assert proc.returncode == 0, f"the scratch run read beside its tree: {proc.stderr[-2000:]}"
    beside = json.loads(proc.stdout)

    tree = _tree.CommitTree("HEAD", ROOT)
    with _tree.reading(tree):
        doc = load_verification(tree_checks=False)
        toolchains, assumptions = load_toolchains(), load_assumptions(tree_checks=False)
        here = {
            unit["id"]: _fingerprint.fingerprint_unit(
                unit, _fingerprint.Registries(doc, toolchains, assumptions)
            )["fingerprint"]
            for unit in doc["unit"]
        }
    tree.close()
    assert here, "no unit was fingerprinted — the comparison compared nothing"
    differ = sorted(unit_id for unit_id in here if beside.get(unit_id) != here[unit_id])
    assert not differ, f"fingerprinted differently with nothing beside the tree: {differ[:10]}"


def test_a_gate_control_is_in_its_units_read_set_and_moves_its_fingerprint():
    """The case the read set was built for: four gate-control scripts were digested into
    their units' fingerprints and absent from the trigger set, so editing one moved the
    evidence and re-ran nothing. Both halves, on every declared gate control: it moves the
    fingerprint, and the read set names it."""
    declaring = {
        unit_id: [str(path) for path in unit["gate_controls"]]
        for unit_id, unit in UNITS.items()
        if unit.get("gate_controls")
    }
    assert declaring, "no unit declares gate_controls — the population this test is about"
    read_sets = unit_read_sets()
    for unit_id, scripts in declaring.items():
        for script in scripts:
            assert script in read_sets[unit_id], f"{script} missing from {unit_id}'s read set"
            before = measure(UNITS[unit_id])["fingerprint"]
            after = perturbed_fingerprints(script, [unit_id])[unit_id]
            assert after != before, f"perturbing {script} did not move {unit_id}"


def test_an_untracked_project_input_alternative_is_not_a_required_input():
    """A project-input list names alternatives a project may not use — `poetry.lock` beside
    `uv.lock`. Requiring a trigger for one absent from the tree would demand a filter naming
    nothing, which the trigger gate's liveness clause refuses: two rules contradicting each
    other. Every such name in the read set must be one git tracks."""
    from _ecosystems import ECOSYSTEMS
    from _fingerprint import _tracked_files

    names = {name for eco in ECOSYSTEMS for name in eco.project_inputs}
    tracked = _tracked_files()
    seen = 0
    for unit_id, paths in unit_read_sets().items():
        for path in paths:
            if path.rsplit("/", 1)[-1] in names:
                seen += 1
                assert path in tracked, f"{unit_id} requires untracked alternative {path}"
    assert seen, "no project input reached any read set — the population this test is about"
