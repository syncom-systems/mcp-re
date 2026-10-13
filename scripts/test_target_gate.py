#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test-target gate — a named test lane must name a target that exists, and a filter
must name a module that target holds.

WHAT THIS PROVES, exactly: every literal Bazel label a `bazel test` command in the CI
workflows or the repository scripts names is a test target of the build graph, and every
`--test_arg=<module>::` filter beside it names a module the target's crate root declares.
Non-literal labels (`"$BENCH"`) are skipped — there is nothing static to check.

The build graph is read from `verification/generated/rust-targets.json`, whose freshness
`tools/verification/rust-targets --check` holds to `bazel query`, so this gate runs where
no Bazel server does. The verification manifest's selectors are checked by the manifest
loader itself (`_manifest.valid_target`), not here.

WHAT IT DOES NOT PROVE: that the lane runs the tests its step name claims beyond the
module, or that the named test inside the module exists. `scripts/run_test_lane.sh`
refuses a lane that ran zero tests; `scripts/slo_invocation_gate.py` covers the SLO lane.

WHY IT MATTERS. Renaming or merging a test target breaks every table that names it, and
the tables are not in one place: the security traceability manifest, the guard tables,
the verification manifest, and — the one nothing catalogued — the named release-gate
steps in the workflows. Consolidating thirteen proxy test binaries once silently pointed
four release-gate lanes at names that no longer existed. A label that names nothing fails
its lane loudly; a module filter that names nothing selects ZERO tests and exits 0, which
is the failure that reads as a pass.

Run:  python3 scripts/test_target_gate.py
      python3 scripts/test_target_gate.py --selftest
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools" / "verification"))

from _module_tree import read_declarations  # noqa: E402
from workflow_reader import Command, parse, shell_commands  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
TABLE = Path("verification") / "generated" / "rust-targets.json"
TEST_KINDS = ("rust_test", "rust_doc_test")

SCAN_GLOBS = (
    ".github/workflows/*.yml",
    "scripts/*.sh",
    "scripts/*.sh.example",
)

BAZEL_TEST = re.compile(r"\bbazel\s+test\b")
LABEL = re.compile(r"(?<![\w$])(//[A-Za-z0-9_./-]*:[A-Za-z0-9_.+-]+)")
MODULE_FILTER = re.compile(r"--test_arg=([a-z][a-z0-9_]*)::")


def load_targets(root: Path) -> dict[str, dict]:
    return json.loads((root / TABLE).read_text())["targets"]


def commands(path: Path) -> list[Command]:
    """The commands a workflow's steps or a shell script run.

    From the workflow reader, so a command and its label lines apart — a `>-` fold, a
    trailing `\\` — are one command, and a comment or a usage line (`echo "usage: … bazel
    test …"`) is none.
    """
    text = path.read_text(encoding="utf-8")
    found = parse(text, str(path)).commands() if path.suffix == ".yml" else shell_commands(text)
    return [command for command in found if command.executed_segments()]


def root_modules(root: Path, row: dict) -> set[str]:
    """The modules the target's crate root declares at its top level — what a `module::`
    filter can name, since a test's name starts at the crate root."""
    path = root / row["root"]
    if not path.is_file():
        return set()
    return {d.name for d in read_declarations(path) if not d.enclosing}


def check(root: Path, targets: dict[str, dict]) -> tuple[list[str], int]:
    failures: list[str] = []
    named = 0
    for pattern in SCAN_GLOBS:
        for path in sorted(root.glob(pattern)):
            rel = path.relative_to(root)
            for command, block in ((c, seg) for c in commands(path) for seg in c.executed_segments()):
                number = command.line
                if not BAZEL_TEST.search(block):
                    continue
                labels = [lbl for lbl in LABEL.findall(block) if not lbl.startswith("//...")]
                for label in labels:
                    named += 1
                    row = targets.get(label)
                    if row is None or row["kind"] not in TEST_KINDS:
                        failures.append(
                            f"{rel}:{number}: `{label}` is not a test target of the build "
                            f"graph — it was renamed, merged or is not a test; repoint the lane"
                        )
                        continue
                    modules = root_modules(root, row)
                    for module in MODULE_FILTER.findall(block):
                        if module not in modules:
                            failures.append(
                                f"{rel}:{number}: filter `{module}::` names no module in "
                                f"`{label}` ({row['root']}) — libtest would select ZERO "
                                f"tests and exit 0"
                            )
    return failures, named


def _step(run: str) -> str:
    """A one-step workflow around `run`, a step's `run:` value with or without its key."""
    body = run if run.lstrip().startswith("run:") else f"run: {run}"
    lines = [line.strip() if i == 0 else line for i, line in enumerate(body.splitlines())]
    return "jobs:\n  a:\n    steps:\n      - " + "\n".join(lines) + "\n"


def selftest() -> int:
    failed = False
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "pkg" / "tests").mkdir(parents=True)
        (root / "pkg" / "tests" / "main.rs").write_text(
            "mod real_mod;\npub mod other {\n    mod nested_only;\n}\n// mod commented_out;\n"
        )
        targets = {
            "//pkg:real_test": {"kind": "rust_test", "root": "pkg/tests/main.rs"},
            "//pkg:a_library": {"kind": "rust_library", "root": "pkg/src/lib.rs"},
        }
        cases = [
            ("a named target that exists", "run: bazel test //pkg:real_test\n", ""),
            ("a named target that does not exist", "run: bazel test //pkg:ghost_test\n", "not a test target"),
            ("a library is not a test target", "run: bazel test //pkg:a_library\n", "not a test target"),
            (
                "a label split from its command across folded lines",
                "run: >-\n          scripts/run_test_lane.sh bazel test --test_output=all\n"
                "          //pkg:ghost_test\n",
                "not a test target",
            ),
            (
                "a label split from its command by a continuation",
                "run: |\n          bazel test --test_output=all \\\n            //pkg:ghost_test\n",
                "not a test target",
            ),
            ("a variable is not a static claim", 'run: bazel test "$BENCH"\n', ""),
            ("a build of a missing label is not a test lane", "run: bazel build //pkg:ghost\n", ""),
            ("the whole graph is not a label", "run: bazel test //... --test_output=errors\n", ""),
            (
                "a usage example in a comment is not an invocation",
                "run: |\n          # run_test_lane.sh bazel test //pkg:ghost_test\n          true\n",
                "",
            ),
            (
                "a usage message is not an invocation",
                '  echo "usage: $0 bazel test //pkg:target --test_arg=<module>::" >&2\n',
                "",
            ),
            (
                "a filter naming a declared module",
                "run: bazel test //pkg:real_test --test_arg=real_mod::\n",
                "",
            ),
            (
                "an inline module is declared too",
                "run: bazel test //pkg:real_test --test_arg=other::x\n",
                "",
            ),
            (
                "a label of a neighbouring segment is not the test lane's",
                "run: bazel build //pkg:ghost && bazel test //pkg:real_test\n",
                "",
            ),
            (
                "a filter of a neighbouring segment is not the test lane's",
                "run: bazel test //pkg:real_test && scripts/x.sh --test_arg=ghost_mod::\n",
                "",
            ),
            (
                "a test lane after a neighbouring segment is still read",
                "run: true && bazel test //pkg:ghost_test\n",
                "not a test target",
            ),
            (
                "a module nested in another is not a crate-root filter",
                "run: bazel test //pkg:real_test --test_arg=nested_only::\n",
                "names no module",
            ),
            (
                "a commented-out module is not a module",
                "run: bazel test //pkg:real_test --test_arg=commented_out::\n",
                "names no module",
            ),
            (
                "a filter naming no module selects nothing",
                "run: bazel test //pkg:real_test --test_arg=ghost_mod::\n",
                "names no module",
            ),
        ]
        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (root / "scripts").mkdir()
        for label, content, expected in cases:
            # A case is a step's `run:` value, or a shell script when it is a usage line.
            if content.startswith("  echo"):
                (workflows / "ci.yml").write_text("jobs: {}\n", encoding="utf-8")
                (root / "scripts" / "lane.sh").write_text(content, encoding="utf-8")
            else:
                (root / "scripts" / "lane.sh").write_text("", encoding="utf-8")
                (workflows / "ci.yml").write_text(_step(content), encoding="utf-8")
            failures = check(root, targets)[0]
            ok = not failures if not expected else any(expected in f for f in failures)
            print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
            if not ok:
                failed = True
                print(f"        got {failures}")
    if failed:
        print("test-target gate: SELFTEST FAILED")
        return 1
    print("test-target gate: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    failures, named = check(REPO, load_targets(REPO))
    if failures:
        print("test-target gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    if named == 0:
        print("test-target gate: FAILED — no `bazel test` lane names a label; the scan read nothing")
        return 1
    print(f"test-target gate: OK — {named} label(s) named by `bazel test` lanes are test targets "
          f"of the build graph, and every module filter names a module the target declares")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
