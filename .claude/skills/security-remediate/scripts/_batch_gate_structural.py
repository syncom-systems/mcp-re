"""One result per structural gate, including the size-only failures that are recorded, not blocking."""
from __future__ import annotations

import os
import subprocess
import sys

import size_debt
from _batch_gate_run import run, tail
from _batch_gate_suites import RATCHET, SIZE_GATES, STRUCTURAL


def _size_debt_verdict(cmd: list[str], log: str) -> tuple[str, list]:
    """`size-debt` when the failure is only size growth, else `new-failures`."""
    soft, debt = size_debt.classify(cmd[0], open(log, encoding="utf-8", errors="replace").read())
    if not soft:
        return "new-failures", []
    # Recorded, not blocking (size_debt.py); a row no writer registered — a hand
    # commit — joins the register under HEAD.
    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    size_debt.register_rows(debt, head)
    return "size-debt", debt


def _structural_result(cmd: list[str], work_dir: str) -> dict:
    log = os.path.join(work_dir, "batch-%s.log" % os.path.basename(cmd[0]))
    rc = run([sys.executable, *cmd], log)
    verdict, debt = ("ok" if rc == 0 else "new-failures"), []
    if rc and cmd[0] in SIZE_GATES:
        verdict, debt = _size_debt_verdict(cmd, log)
    return {"gate": cmd[0], "verdict": verdict, "log": log,
            **({} if rc == 0 else {"tail": tail(log)}),
            **({"debt": debt} if verdict == "size-debt" else {})}


def structural_results(work_dir: str, no_clippy_ratchet: bool) -> list[dict]:
    results = []
    for cmd in STRUCTURAL:
        if no_clippy_ratchet and cmd[0] == RATCHET:
            results.append({"gate": cmd[0], "verdict": "skipped",
                            "why": "--no-clippy-ratchet: run at the batch/integration checkpoint"})
        elif not os.path.isfile(cmd[0]):
            results.append({"gate": cmd[0], "verdict": "infra", "why": "missing"})
        else:
            results.append(_structural_result(cmd, work_dir))
    return results
