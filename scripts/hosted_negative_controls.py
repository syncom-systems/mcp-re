#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for the hosted verification lanes, run in a disposable CI checkout.

Each control applies one hostile edit to the tree, runs the production lane, and requires the
lane to REFUSE for the stated reason. A lane that stays green over a tampered prover, a false
proof, or an absent record is the failure this exists to catch; it is also the only evidence
that the hosted run propagates a red result rather than reporting success from a runner that
measured nothing.

Edits are made in place and reverted with `git checkout` after every control, so it must be
run in a throwaway checkout. Evidence goes to a scratch directory, never the run's own.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "verification/policy/toolchains.lock.toml"
PROOF = ROOT / "mcp-re-core/src/verus_proofs.rs"


def run(argv: list[str], evidence: Path) -> tuple[int, str]:
    env = dict(os.environ, MCP_RE_EVIDENCE_DIR=str(evidence))
    proc = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout + proc.stderr


def revert(*paths: Path) -> None:
    subprocess.run(["git", "checkout", "--", *[str(p) for p in paths]], cwd=ROOT, check=True)


def expect_refusal(name: str, code: int, output: str, needles: list[str]) -> bool:
    missing = [n for n in needles if n not in output]
    if code == 0 or missing:
        print(f"NEGATIVE CONTROL FAILED: {name}: exit {code}, missing {missing}")
        print(output[-3000:])
        return False
    print(f"negative control ok: {name} (exit {code})")
    return True


def tampered_linux_prover(scratch: Path) -> bool:
    text = LOCK.read_text()
    marker = "[verus_linux_x86_64.binaries]"
    head, tail = text.split(marker)
    old = 'rust_verify = "sha256:4'
    if old not in tail:
        print("the Linux rust_verify digest no longer starts with 4; update this control")
        return False
    LOCK.write_text(head + marker + tail.replace(old, 'rust_verify = "sha256:5', 1))
    try:
        code, out = run(["tools/verification/verify-verus"], scratch / "tamper")
    finally:
        revert(LOCK)
    return expect_refusal(
        "a tampered Linux prover digest", code, out, ["rust_verify identity mismatch", "VERDICT: FAIL"]
    )


def false_proof(scratch: Path) -> bool:
    text = PROOF.read_text()
    if "DAYS_IN_MONTH@[i] <= 31," not in text:
        print("the proof this control falsifies has moved; update this control")
        return False
    PROOF.write_text(text.replace("DAYS_IN_MONTH@[i] <= 31,", "DAYS_IN_MONTH@[i] <= 30,", 1))
    try:
        code, out = run(["tools/verification/verify-verus"], scratch / "false-proof")
    finally:
        revert(PROOF)
    return expect_refusal("a false Verus proof", code, out, ["VERDICT: FAIL"])


def absent_evidence(scratch: Path) -> bool:
    empty = scratch / "empty"
    empty.mkdir()
    code, out = run(["tools/verification/verify", "--aggregate", "--gate"], empty)
    return expect_refusal("an aggregate over no records", code, out, [])


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        results = [tampered_linux_prover(scratch), false_proof(scratch), absent_evidence(scratch)]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
