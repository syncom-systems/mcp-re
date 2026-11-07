"""The two phases: `pre` (baselines, before the edit) and `post` (gates, after it)."""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass

import bazel_gate
import progress
import rust_gate
import size_debt
import writer_patch
from _check_gates import bazel, gate_summary, prescan, pyright
from _check_revert import format_touched, revert
from _check_support import dirty, ids, run_json, trees_for

# Worst first. `no-baseline` outranks `ok` because an unmeasured tree is not a pass.
RANK = {"new-failures": 0, "infra": 1, "no-baseline": 2, "size-debt": 3, "ok": 4, "not-run": 5}


def _baseline_row(a, tree: str) -> dict:
    # The store layout is `bazel_gate`'s contract; ask it rather than restate it.
    bpath = bazel_gate._store_path(a.store, tree, "baseline")
    if os.path.exists(bpath):
        return {"tree": tree, "baseline": "exists", "path": bpath}
    rc, doc, err = run_json([sys.executable, a.gate_script, "baseline", "--tree", tree,
                             "--store", a.store])
    ok = rc == 0 and os.path.exists(bpath)
    return {"tree": tree, "baseline": "captured" if ok else "FAILED", "exit": rc,
            "failing": doc.get("failing"), "total": doc.get("total"),
            "infra_suspected": doc.get("infra_suspected"),
            **({"stderr_tail": err} if not ok else {})}


def cmd_pre(a) -> int:
    # The tree this writer starts from, so its own diff — and nothing an earlier writer
    # left uncommitted — is what a red gate reverts and what finalize commits.
    writer_patch.snapshot(a.store, a.file)
    if a.file.endswith(".rs"):
        # No stored baseline for Rust: the lane starts on a tree batch_gate.py
        # measured green and every writer leaves it green or reverted. What `pre`
        # must establish is that the diff `post` judges will be this change alone.
        before = dirty([a.file])
        print(json.dumps({"phase": "pre", "lang": "rust", "dirty_before_edit": before}, indent=1))
        return 1 if before else 0
    rows = [_baseline_row(a, t) for t in trees_for(a)]
    print(json.dumps({"phase": "pre", "trees": rows}, indent=1))
    return 0 if all(r["baseline"] != "FAILED" for r in rows) else 1


@dataclass(frozen=True)
class _Post:
    """One `post` call: its arguments, the touched and related files, the journal fields."""
    a: argparse.Namespace
    touched: list
    related: list
    common: dict

    def append(self, event: str, counts: str, note: str) -> None:
        progress.cmd_append(argparse.Namespace(**self.common, event=event, counts=counts, note=note))


def _journal_fields(a) -> dict:
    return dict(log=a.log, file=a.file, role="worker", attempt=a.attempt, run=a.run,
                epoch=a.epoch, tier="", model=a.model, work_ids="", escalation_ids="",
                finding_ids="", ruling="", reject_causes="", evidence_ref="")


def _gate_parts(post: _Post) -> list[dict]:
    a = post.a
    if a.file.endswith(".rs"):
        edit = rust_gate.Edit(a.file, post.related if a.tier != "local" else [], post.touched)
        return rust_gate.gate(edit, ids(a.it), a.work_dir)
    parts: list[dict] = []
    if a.tier != "local":
        parts.append(dict(pyright(a), gate="pyright"))
    return parts + [dict(bazel(a, t), gate="bazel") for t in trees_for(a)]


def _verdict(parts: list[dict]) -> str:
    return min((p["verdict"] for p in parts), key=lambda v: RANK.get(v, 1)) if parts else "not-run"


def _on_new_failures(post: _Post, note: str, raw_exit: int) -> str | None:
    """The reviewer is skipped on a red tree, so the worker owns the terminal
    event. Emitting nothing here is how two tick-1 files were reported lost."""
    a = post.a
    reverted = None
    if not a.keep_on_fail:
        reverted = revert(post.touched, a.work_dir, a.store, a.file)
        note += "; reverted, patch %s" % reverted
    post.append("gate-failed", "exit=%d" % raw_exit, "new-failures: " + note)
    return reverted


def _gate_note(parts: list[dict], pre: dict) -> str:
    return "; ".join(gate_summary(p) for p in parts) + "; prescan %s" % (
        pre["state"] if pre["state"] == "clean" else "%d hit(s)" % len(pre["hits"]))


def cmd_post(a) -> int:
    os.makedirs(a.work_dir, exist_ok=True)
    post = _Post(a, ids(a.touched) or [a.file], ids(a.related), _journal_fields(a))
    post.append("fix", "applied=%d,not_applied=%d,tests_added=%d"
                % (a.applied, a.not_applied, a.tests_added), a.note or "")

    format_touched(post.touched)
    writer_patch.capture(a.store, a.file, post.touched)
    pre = prescan(a, post.touched, post.related)
    parts = _gate_parts(post)
    verdict = _verdict(parts)
    raw_exit = max((p.get("exit") or 0 for p in parts), default=0)
    record = [r for p in parts for r in p.get("record", [])]
    if record:
        # Not blocking: every oversized file this writer touched, grown or not, joins the
        # structural-debt register when (and only if) the change is committed.
        size_debt.record(a.work_dir, a.file, record)

    note = _gate_note(parts, pre)
    post.append("gate", "exit=%d" % raw_exit, note)
    reverted = _on_new_failures(post, note, raw_exit) if verdict == "new-failures" else None

    print(json.dumps({"phase": "post", "gate_verdict": verdict, "gate_exit": raw_exit,
                      "gates": parts, "prescan": pre,
                      "terminal_event": "gate-failed" if verdict == "new-failures" else None,
                      "reverted_patch": reverted},
                     indent=1))
    return 0
