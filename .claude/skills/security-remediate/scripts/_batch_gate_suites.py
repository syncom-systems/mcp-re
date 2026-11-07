"""The gate lists a batch runs: the structural set, the self-test suites, the merge-path gates."""
from __future__ import annotations

import os
import re
import sys

import workflow_reader
from _batch_gate_run import run, tail

RATCHET = "scripts/clippy_ratchet_gate.py"
# Gates whose size-only failures are recorded, not blocking, during a remediation run.
SIZE_GATES = {"scripts/module_size_gate.py", RATCHET}
STRUCTURAL = [
    [RATCHET],
    ["scripts/module_size_gate.py"],
    ["scripts/bazel_srcs_gate.py"],
    ["scripts/unit_closure_gate.py"],
    ["scripts/verification_trigger_gate.py"],
    ["tools/verification/test_mutation_lane.py"],
    # ADR-MCPRE-069: every test a fix adds is a control the census must see claimed or
    # dispositioned. `finalize.py` holds a file whose own controls are not; these two are
    # the batch's whole-tree answer — the residue ratchet at its closure state, and the
    # registry's own consistency (orphan rows, missing records, stale selectors).
    ["scripts/control_census_gate.py"],
    ["tools/verification/control-census", "--gate"],
]

VERIFICATION_SUITES = "tools/verification"

#: The merge-path workflow whose Python gates the batch gate also runs.
CI_WORKFLOW = ".github/workflows/pre-merge.yml"

#: CI invocations the batch gate does NOT run: the clippy ratchet and its compile probes
#: (authorized only at an integration boundary, and STRUCTURAL already carries the ratchet),
#: and the workspace-lints probe, which compiles a crate of its own.
CI_EXCLUDED = {
    ("scripts/clippy_ratchet_gate.py",),
    ("scripts/clippy_ratchet_gate.py", "--activation-probe"),
    ("scripts/clippy_ratchet_gate.py", "--nesting-probe"),
    ("scripts/clippy_ratchet_gate.py", "--selftest"),
    ("scripts/workspace_lints_gate.py", "--probe"),
}

#: A flag that takes no value; an invocation carrying any other argument is the workflow's to
#: parameterize.
_BARE_FLAG = re.compile(r"^--[a-z-]+$")


def structural_suites() -> set[str]:
    """The self-test suites STRUCTURAL already runs, by file name."""
    return {os.path.basename(cmd[0]) for cmd in STRUCTURAL
            if os.path.dirname(cmd[0]) == VERIFICATION_SUITES}


def verification_suites(work_dir: str, root: str = VERIFICATION_SUITES,
                        already: set[str] | None = None) -> dict:
    """Every `test_*.py` self-test suite under `root`, each run once, as one gate result.

    A suite in `already` (by default the ones STRUCTURAL runs) is not run twice. No suite
    found is `infra`, not `ok`: an empty set would be a green that measured nothing.
    """
    already = structural_suites() if already is None else already
    suites = sorted(f for f in os.listdir(root) if f.startswith("test_") and f.endswith(".py")
                    and f not in already) if os.path.isdir(root) else []
    if not suites:
        return {"gate": root + "/test_*.py", "verdict": "infra", "why": "no suite found"}
    failed = []
    for suite in suites:
        log = os.path.join(work_dir, "batch-verification-%s.log" % suite)
        if run([sys.executable, os.path.join(root, suite)], log):
            failed.append({"suite": suite, "log": log, "tail": tail(log)})
    return {"gate": root + "/test_*.py", "suites": len(suites),
            "verdict": "new-failures" if failed else "ok",
            **({"failed": failed} if failed else {})}


def _is_gate_invocation(invocation) -> bool:
    python = invocation.interpreter in ("python3", "python")
    direct = invocation.interpreter is None and invocation.program.startswith("tools/verification/")
    return (python and invocation.program.startswith(("scripts/", "tools/"))) or direct


def _bare_gates(commands) -> list[tuple[str, ...]]:
    return [(inv.program, *inv.args)
            for command in commands for inv in command.invocations()
            if _is_gate_invocation(inv) and all(_BARE_FLAG.match(arg) for arg in inv.args)]


def ci_gates(workflow: str = CI_WORKFLOW) -> list[tuple[str, ...]]:
    """Every Python gate invocation in `workflow` that takes only bare flags, in file
    order and once each. An invocation whose flag takes a value (`--base <sha>`) is the
    workflow's to parameterize and is left out, and so is anything in CI_EXCLUDED.

    A gate is a Python file run as `python3 <path>`, or a `tools/verification` executable
    run directly (`tools/verification/rust-targets --check`); every executable there is a
    Python script, so both forms run under this interpreter. The workflow is read through
    `scripts/workflow_reader.py`, so a commented-out invocation is not one, and a gate in a
    `&&` chain or on a continued line is."""
    if not os.path.isfile(workflow):
        return []
    with open(workflow, encoding="utf-8") as fh:
        commands = workflow_reader.parse(fh.read(), workflow).commands()
    seen: list[tuple[str, ...]] = []
    for cmd in _bare_gates(commands):
        if cmd not in seen and cmd not in CI_EXCLUDED:
            seen.append(cmd)
    return seen


def merge_path_gates(work_dir: str, workflow: str = CI_WORKFLOW,
                     already: set[tuple[str, ...]] | None = None) -> dict:
    """Every gate `ci_gates` finds, each run once, as one gate result.

    The merge path runs these on every push, and a batch gate that ran only its own subset
    let a red one sit unseen through many batches. A gate STRUCTURAL already runs is not
    run twice. No gate found is `infra`, not `ok`."""
    already = {tuple(cmd) for cmd in STRUCTURAL} if already is None else already
    gates = [cmd for cmd in ci_gates(workflow) if cmd not in already]
    if not gates:
        return {"gate": workflow, "verdict": "infra", "why": "no gate invocation found"}
    failed = []
    for cmd in gates:
        name = "-".join(os.path.basename(part) for part in cmd)
        log = os.path.join(work_dir, "batch-ci-%s.log" % name)
        if run([sys.executable, *cmd], log):
            failed.append({"gate": " ".join(cmd), "log": log, "tail": tail(log)})
    return {"gate": workflow, "gates": len(gates),
            "verdict": "new-failures" if failed else "ok",
            **({"failed": failed} if failed else {})}
