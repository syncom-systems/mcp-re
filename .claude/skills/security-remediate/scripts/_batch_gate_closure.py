"""The touched closure: every Rust target that depends on a touched file, linted, tested and format-checked."""
from __future__ import annotations

import os

import rust_gate
from _batch_gate_run import run, tail


def _closure_targets(files: list[str]) -> tuple[list[str], list[str]] | None:
    """(Rust targets, non-manual test targets) in the reverse-dependency closure of `files`,
    or None when none of them belongs to a Bazel package."""
    labels = [lbl for lbl in (rust_gate.file_label(f) for f in files) if lbl]
    if not labels:
        return None
    closure = "rdeps(//..., set(%s))" % " ".join(labels)
    rust = rust_gate.query('kind("^(%s) rule$", %s)' % (rust_gate.RUST_RULES, closure))
    tests = rust_gate.query('kind(".*_test rule$", %s) except attr(tags, "\\bmanual\\b", //...)'
                            % closure)
    return rust, tests


def _closure_result(name: str, targets: list[str], cmd: list[str], ctx: tuple[str, list[str]]) -> dict:
    work_dir, files = ctx
    if not targets:
        return {"gate": name, "verdict": "infra",
                "why": "the closure of %s holds no such target" % ", ".join(files)}
    log = os.path.join(work_dir, "batch-%s.log" % name.split()[0])
    rc = run(rust_gate.bazel() + cmd + targets, log)
    return {"gate": name, "targets": len(targets),
            "verdict": "ok" if rc == 0 else "new-failures", "log": log,
            **({} if rc == 0 else {"tail": tail(log)})}


def closure_results(files: list[str], work_dir: str) -> list[dict]:
    targets = _closure_targets(files)
    if targets is None:
        return []
    rust, tests = targets
    ctx = (work_dir, files)
    results = [
        _closure_result("lint the touched closure", rust,
                        ["build", "--config=lint", "--keep_going"], ctx),
        _closure_result("test the touched closure", tests,
                        ["test", "--test_output=errors", "--keep_going"], ctx)]
    # The merge path's format lane is a Bazel build, which `merge_path_gates` does not
    # read; the closure's lint targets are the ones whose sources it formats.
    if rust:
        results.append({"gate": "format the touched closure", "targets": len(rust),
                        **rust_gate._rustfmt(rust, files, os.path.join(work_dir, "batch-format.log"))})
    return results
