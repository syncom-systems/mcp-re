"""Turning a Bazel run's exit status and output into a gate part: the verdict logic, with no I/O."""
from __future__ import annotations

import os
import re

_DIAGNOSTIC = re.compile(r"^error(?:\[E\d+\])?: ", re.M)
# libtest's "running N tests", and stdlib unittest's "Ran N tests in" for a `py_test` lane.
RUNNING = re.compile(r"^(?:running|Ran) (\d+) tests?(?: in .*)?$", re.M)
_FAILED_TEST = re.compile(r"^---- (\S+) stdout ----$", re.M)
INLINE_TEST = re.compile(r"#\[(?:tokio::)?test\b")
_FMT_DIFF = re.compile(r"^Diff in (\S+?\.rs):\d+:$", re.M)
_FMT_PARSE = re.compile(r"^\s*--> (\S+?\.rs):\d+:\d+$", re.M)


def lint_verdict(rc: int, out: str, log: str) -> dict:
    errors = [ln for ln in out.splitlines() if _DIAGNOSTIC.match(ln)][:15]
    if rc == 0:
        return {"verdict": "ok", "exit": rc, "log": log}
    if errors:
        return {"verdict": "new-failures", "exit": rc, "log": log, "errors_head": errors}
    return {"verdict": "infra", "exit": rc, "log": log,
            "why": "the lint build failed without a diagnostic — analysis, fetch or toolchain"}


def _relative(p: str) -> str:
    return os.path.relpath(p) if os.path.isabs(p) else p


def rustfmt_verdict(rc: int, out: str, touched: list[str], log: str) -> dict:
    if rc == 0:
        return {"verdict": "ok", "exit": rc, "log": log}
    diffs = sorted({_relative(p) for p in _FMT_DIFF.findall(out)})
    unparsable = sorted({_relative(p) for p in _FMT_PARSE.findall(out)} & set(touched))
    if unparsable:
        return {"verdict": "new-failures", "exit": rc, "log": log, "unformatted": unparsable,
                "why": "rustfmt cannot parse a touched file"}
    mine = [p for p in diffs if p in set(touched)]
    if mine:
        return {"verdict": "new-failures", "exit": rc, "log": log, "unformatted": mine}
    if diffs:
        return {"verdict": "infra", "exit": rc, "log": log, "unformatted": diffs,
                "why": "rustfmt diffs only in untouched files — the lane did not start formatted"}
    return {"verdict": "infra", "exit": rc, "log": log,
            "why": "the rustfmt build failed without a diff — analysis, fetch or toolchain"}


def _failed_run(rc: int, log: str, failed: list, compile_error: bool) -> dict:
    """A non-zero `bazel test`: blame the change when a test failed or the code did not compile."""
    if failed or compile_error:
        return {"verdict": "new-failures", "exit": rc, "log": log, "failed": failed[:15],
                "compile_error": compile_error and not failed}
    return {"verdict": "infra", "exit": rc, "log": log,
            "why": "bazel test failed before any test ran"}


def tests_verdict(rc: int, out: str, logs: dict, log: str) -> dict:
    if rc != 0:
        failed = [name for text in logs.values() for name in _FAILED_TEST.findall(text)]
        return _failed_run(rc, log, failed, bool(_DIAGNOSTIC.search(out)))
    ran = sum(int(n) for text in logs.values() for n in RUNNING.findall(text))
    if ran == 0:
        return {"verdict": "infra", "exit": rc, "log": log,
                "why": "0 tests ran — this selection measured nothing"}
    return {"verdict": "ok", "exit": rc, "log": log, "ran": ran}
