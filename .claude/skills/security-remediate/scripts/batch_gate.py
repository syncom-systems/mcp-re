"""batch_gate.py — the gate that runs once per batch, not once per file.

The per-file gate (`check.py post`) is what can be attributed to one writer:
the targets that compile the file, its own tests, the module-size ratchet. What it
leaves out is the work that costs minutes and says the same thing whether it runs
after one fix or after six: the whole-workspace clippy ratchet, the structural
gates, and the touched closure — every Rust target that depends on a touched file,
linted under `--config=lint`, and every test target in it. Running those per file would
serialize the writer lane behind them; running them per batch costs one run, and
the per-file commits make a failure bisectable to the file that caused it.

Run it BEFORE the first batch of a run (`--files` empty): the lane's attribution
rests on starting from a tree measured green. Run it AFTER each batch with the
files the batch touched.

It also runs every `tools/verification/test_*.py` self-test suite once. They read the
registry and pin measured facts about it — premise totals, the controls each record states —
so a registry-only change moves them while no Rust target notices; they are not per-file
work, and leaving them out let two suites stay red under a green batch gate.

And it runs every Python gate the merge-path workflow (`.github/workflows/ci.yml`) invokes
with bare flags, read from the workflow so the two lists cannot drift. A hand-picked subset
let six merge-path gates go red across many green batches.

Two lanes are left to the pre-handover gate (`scripts/local_gate.sh`) and are NOT
claimed here: `bazel test //...` (the only lane that runs the `async_serve` drain
tests) and the SLO lane.

The whole-workspace clippy ratchet is the one long run here, and it is authorized at an
integration boundary — after a batch, before a PR is opened or updated, or on the
owner's ask — never merely because a run started. `--no-clippy-ratchet` omits it for a
single-file (`--top 1`) run, and the result reports it as `skipped`, so the omission is
never read as a pass. A change that touches lint configuration, the ratchet machinery or
shared compiler settings is a reason to stop and ask for the ratchet instead.

Usage:
  batch_gate.py [--files a,b] [--no-clippy-ratchet] --work-dir DIR
Exit 0 green, 1 a gate failed, 2 a gate could not run.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "scripts"))
from _batch_gate_closure import closure_results  # noqa: E402
from _batch_gate_structural import structural_results  # noqa: E402
from _batch_gate_suites import (  # noqa: E402,F401 — the tests and callers read these from here
    ci_gates, merge_path_gates, structural_suites as _structural_suites, verification_suites)


def _worst(results: list[dict]) -> str:
    verdicts = {r["verdict"] for r in results}
    return "new-failures" if "new-failures" in verdicts else "infra" if "infra" in verdicts else "ok"


def main() -> int:
    ap = argparse.ArgumentParser(description="once-per-batch gate")
    ap.add_argument("--files", default="", help="files the batch touched, comma-separated")
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--no-clippy-ratchet", action="store_true",
                    help="omit the workspace clippy ratchet (single-file run); reported as skipped")
    a = ap.parse_args()
    os.makedirs(a.work_dir, exist_ok=True)
    results = structural_results(a.work_dir, a.no_clippy_ratchet)
    results.append(verification_suites(a.work_dir))
    results.append(merge_path_gates(a.work_dir))
    files = [f.strip() for f in a.files.split(",") if f.strip()]
    results += closure_results(files, a.work_dir)

    worst = _worst(results)
    skipped = [r["gate"] for r in results if r["verdict"] == "skipped"]
    debt = [d for r in results for d in r.get("debt", [])]
    print(json.dumps({"verdict": worst, "skipped": skipped, "size_debt": debt,
                      "gates": results}, indent=1))
    return {"ok": 0, "new-failures": 1}.get(worst, 2)


if __name__ == "__main__":
    sys.exit(main())
