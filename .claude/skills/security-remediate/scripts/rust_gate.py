"""Rust gate for one file's fix, on Bazel targets: lint every target that compiles the file,
then run the tests that exercise it — never the whole graph.

(Invoked as `python3 rust_gate.py …`, or imported by `check.py` and `batch_gate.py`.)

Bazel is the Rust build authority, so "every lane that compiles the file" is read from the
build graph rather than reconstructed: each flavor of a library is its own target with its
own `crate_features`, and the targets that list the file in their `srcs` are exactly the
configurations it is compiled in.

  lint    `bazel build --config=lint` over the targets that compile the file or any file
          the writer touched (and, at the `wide` tier, those that compile the related
          files), plus the unit-test targets built from the file's own: clippy under the
          workspace lint policy, warnings as errors.
  format  `bazel build --config=rustfmt` over the targets that compile the touched files —
          the rustfmt lane, scoped. A diff in a touched file is the writer's; a diff only in
          files nobody touched means the lane did not start on a formatted tree (`infra`).
  size    `scripts/module_size_gate.py` — seconds, whole tree.
  registry  unit closure, verification-trigger filters, mutation anchors — seconds each.
  tests   the `rust_test` targets whose `crate` is a library that compiles the file (its
          own unit tests), filtered to the file's module path, plus every integration test
          target the package named (`--it`, Bazel labels).

The verdict rests on the lane invariant, not on a stored baseline: the writer lane starts on
a tree `batch_gate.py` measured green, and every writer leaves it green or reverted.

Verdicts: `new-failures` (a lint, a compile error, a failed test), `infra` (Bazel could not
judge: analysis failed, or no test ran), `size-debt` (the only problem is size growth, which
a remediation run records and does not block on — `size_debt.py`), `ok`.

Usage:
  rust_gate.py --file F [--related a,b] [--touched a,b] [--it //pkg:target,...] --work-dir DIR
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rust_resolver import RustResolver  # noqa: E402
from _rust_gate_checks import registry_part, size_part  # noqa: E402
from _rust_gate_verdicts import (  # noqa: E402
    INLINE_TEST, lint_verdict, rustfmt_verdict, tests_verdict)

SIZE_GATE = "scripts/module_size_gate.py"
# Seconds each, whole tree, and attributable under the lane invariant: a new module that
# joins no unit, a fingerprint input no CI filter triggers on, a mutation anchor the change
# made stale. Writers kept leaving these for the batch gate.
REGISTRY_GATES = ("scripts/unit_closure_gate.py", "scripts/verification_trigger_gate.py",
                  "tools/verification/test_mutation_lane.py", "scripts/control_census_gate.py",
                  # The census itself, which also checks a new proposition's own fields (its
                  # consequence class): the census GATE checks dispositions only.
                  "tools/verification/control-census --gate")
# A Rust source whose tests are not Rust: the PyO3 binding is a `rust_shared_library` no
# `rust_test` compiles, and the lane that exercises the extension it builds is a `py_test`.
# Its tests run as this file's integration targets.
EXTENSION_LANES = {"sdk/python/": ("//sdk/python:core_lane_test",)}
RUST_RULES = "rust_library|rust_binary|rust_test|rust_shared_library|rust_static_library|rust_proc_macro"


def bazel() -> list[str]:
    """The Bazel launcher. A seam so the gate's verdict logic can be tested without one."""
    return ["bazel"]


def _slug(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]


def _run(cmd: list[str], log: str) -> tuple[int, str]:
    with open(log, "w", encoding="utf-8") as fh:
        p = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT)
    return p.returncode, open(log, encoding="utf-8", errors="replace").read()


def package_of(path: str) -> str | None:
    """The Bazel package that owns `path`: the nearest directory holding a BUILD file."""
    d = os.path.dirname(path)
    while True:
        if any(os.path.isfile(os.path.join(d or ".", b)) for b in ("BUILD.bazel", "BUILD")):
            return d
        if not d:
            return None
        d = os.path.dirname(d)


def file_label(path: str) -> str | None:
    pkg = package_of(path)
    if pkg is None:
        return None
    return "//%s:%s" % (pkg, os.path.relpath(path, pkg or "."))


def query(expr: str) -> list[str]:
    p = subprocess.run(bazel() + ["query", "--output=label", "--keep_going", expr],
                       capture_output=True, text=True)
    return sorted(line for line in p.stdout.splitlines() if line.startswith("//"))


def compiling_targets(files: list[str]) -> list[str]:
    """Every first-party Rust target that lists one of `files` in its sources."""
    labels = [lbl for lbl in (file_label(f) for f in files) if lbl]
    if not labels:
        return []
    return query('kind("^(%s) rule$", rdeps(//..., set(%s), 1))' % (RUST_RULES, " ".join(labels)))


def unit_test_targets(targets: list[str]) -> list[str]:
    """The `rust_test` targets that compile one of `targets`' crates with its unit tests,
    and any test target among `targets` itself."""
    libs = [t for t in targets]
    if not libs:
        return []
    crate_tests = query('attr(crate, "^(%s)$", kind("^rust_test rule$", //...))'
                        % "|".join(re.escape(t) for t in libs))
    own_tests = query('kind("^rust_test rule$", set(%s))' % " ".join(libs))
    manual = set(query('attr(tags, "\\bmanual\\b", set(%s))'
                       % " ".join(sorted(set(crate_tests + own_tests)) or ["//:none"])))
    return sorted(set(crate_tests + own_tests) - manual)


def _lint(targets: list[str], log: str) -> dict:
    rc, out = _run(bazel() + ["build", "--config=lint", "--keep_going", *targets], log)
    return lint_verdict(rc, out, log)


def _rustfmt(targets: list[str], touched: list[str], log: str) -> dict:
    # Only the format checks: the config adds them to the default output groups, which
    # would also compile the targets and report a compile error as a format failure.
    rc, out = _run(bazel() + ["build", "--config=rustfmt", "--output_groups=rustfmt_checks",
                              "--keep_going", *targets], log)
    return rustfmt_verdict(rc, out, touched, log)


def _testlog(label: str) -> str:
    pkg, name = label[2:].split(":", 1)
    path = os.path.join("bazel-testlogs", pkg, name, "test.log")
    return open(path, encoding="utf-8", errors="replace").read() if os.path.isfile(path) else ""


def _test(targets: list[str], filt: str | list[str], log: str) -> dict:
    cmd = bazel() + ["test", "--test_output=errors", "--keep_going", *targets]
    # libtest runs a test that matches ANY of its filters.
    for f in [filt] if isinstance(filt, str) else filt:
        if f:
            cmd.append("--test_arg=" + f)
    rc, out = _run(cmd, log)
    return tests_verdict(rc, out, {t: _testlog(t) for t in targets}, log)


@dataclass(frozen=True)
class Edit:
    """The file a writer changed, the files that bind to it, and every file it touched."""
    file: str
    related: list = field(default_factory=list)
    touched: list | None = None


@dataclass(frozen=True)
class _Plan:
    """What one file's gate runs: its sources, the targets that compile them, the unit tests."""
    file: str
    edited: list
    sources: list
    own: list
    touched_targets: list
    lint_scope: list
    units: list
    work_dir: str

    @property
    def tag(self) -> str:
        return _slug(self.file)

    def log(self, stem: str) -> str:
        return os.path.join(self.work_dir, "%s-%s.log" % (stem, self.tag))


def _plan(edit: Edit, work_dir: str) -> _Plan | None:
    file = edit.file
    own = compiling_targets([file])
    if not own:
        return None
    edited = sorted({f for f in (edit.touched or []) + [file] if f.endswith(".rs")})
    touched_targets = compiling_targets([f for f in edited if f != file])
    lint_scope = sorted(set(own + touched_targets + compiling_targets(edit.related)))
    # Unit tests of every touched source file, not only the edited one: a writer's new test
    # often lives in a neighbouring module, and a filter on this file's module skips it.
    sources = [f for f in edited
               if not {"tests", "benches", "examples"} & set(f.split("/"))]
    units = unit_test_targets(sorted(set(own + compiling_targets(
        [f for f in sources if f != file]))))
    return _Plan(file, edited, sources, own, touched_targets, lint_scope, units, work_dir)


def _build_parts(plan: _Plan) -> list[dict]:
    """clippy under the workspace lint policy, then the scoped rustfmt lane."""
    clippy = dict(_lint(sorted(set(plan.lint_scope + plan.units)), plan.log("lint")),
                  gate="clippy", targets=plan.lint_scope)
    fmt_scope = sorted(set(plan.own + plan.touched_targets))
    fmt = dict(_rustfmt(fmt_scope, plan.edited, plan.log("fmt")),
               gate="rustfmt", targets=fmt_scope)
    return [clippy, fmt]


def _size_part(plan: _Plan) -> dict:
    rc, out = _run([sys.executable, SIZE_GATE], plan.log("size"))
    return size_part(rc, out, plan.edited)


def _registry_parts(plan: _Plan) -> list[dict]:
    parts = []
    for gate_cmd in REGISTRY_GATES:
        script, *args = gate_cmd.split()
        if not os.path.isfile(script):
            continue
        rc, out = _run([sys.executable, script, *args], plan.log(os.path.basename(script)))
        parts.append(registry_part(script, rc, out))
    return parts


def _run_units(plan: _Plan, filters: list[str]) -> dict:
    if not plan.units:
        return {"gate": "test", "target": "unit", "verdict": "infra",
                "why": "no unit-test target compiles %s's crate" % plan.file}
    return dict(_test(plan.units, filters, plan.log("test-unit")),
                gate="test", target="unit", targets=plan.units, filter=filters)


def _nothing_ran(part: dict, plan: _Plan) -> bool:
    ran_nothing = "0 tests ran" in part.get("why", "") or not plan.units
    return part["verdict"] == "infra" and ran_nothing


def _excuse_without_own_tests(part: dict, plan: _Plan) -> dict:
    """A selection that ran nothing is not a failure of a file that has no tests of its own."""
    has_own = INLINE_TEST.search(open(plan.file, encoding="utf-8", errors="replace").read())
    if _nothing_ran(part, plan) and not has_own:
        part["verdict"] = "ok"
        part["note"] = "the file has no unit tests of its own"
    return part


def _unit_part(plan: _Plan, r: RustResolver) -> dict:
    mods = sorted({"::".join(r.module_path(f)) for f in plan.sources})
    # A crate root has the empty module path, which selects every test in the target.
    filters = [] if "" in mods else [m + "::" for m in mods]
    return _excuse_without_own_tests(_run_units(plan, filters), plan)


def _integration_part(plan: _Plan, its: list[str]) -> dict | None:
    lanes = sorted(set(its) | {lane for prefix, lanes in EXTENSION_LANES.items()
                               if plan.file.startswith(prefix) for lane in lanes})
    if not lanes:
        return None
    return dict(_test(lanes, "", plan.log("test-it")),
                gate="test", target="integration", targets=lanes)


def gate(edit: Edit, its: list[str], work_dir: str,
         resolver: RustResolver | None = None) -> list[dict]:
    r = resolver or RustResolver(".")
    plan = _plan(edit, work_dir)
    if plan is None:
        return [{"gate": "targets", "verdict": "infra",
                 "why": "%s is compiled by no Rust target in the build graph" % edit.file}]
    parts = _build_parts(plan) + [_size_part(plan)] + _registry_parts(plan)
    if any(p["verdict"] == "new-failures" for p in parts):
        return parts          # a tree that does not compile has no test result to add
    parts.append(_unit_part(plan, r))
    integration = _integration_part(plan, its)
    return parts + [integration] if integration else parts


def main() -> int:
    ap = argparse.ArgumentParser(description="Bazel Rust gate for one file's fix")
    ap.add_argument("--file", required=True)
    ap.add_argument("--related", default="")
    ap.add_argument("--touched", default="", help="comma-separated files edited (default: --file)")
    ap.add_argument("--it", default="", help="integration test targets (Bazel labels), comma-separated")
    ap.add_argument("--work-dir", required=True)
    a = ap.parse_args()
    os.makedirs(a.work_dir, exist_ok=True)
    ids = lambda s: [x.strip() for x in s.split(",") if x.strip()]  # noqa: E731
    edit = Edit(a.file, ids(a.related), ids(a.touched))
    print(json.dumps(gate(edit, ids(a.it), a.work_dir), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
