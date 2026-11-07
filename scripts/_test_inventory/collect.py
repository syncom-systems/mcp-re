# SPDX-License-Identifier: Apache-2.0
"""The COMPILED half's collection: build every `rust_test` and list what each binary contains."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import _rust_targets

from _test_inventory.config import REPO


def listed(exe: Path) -> list[str]:
    out = subprocess.run([str(exe), "--list", "--format=terse"], capture_output=True, text=True,
                         check=True).stdout
    return sorted(line[: -len(": test")] for line in out.splitlines() if line.endswith(": test"))


def bazel(*args: str) -> str:
    done = subprocess.run(["bazel", *args], cwd=REPO, capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"FAILED ({done.returncode}): bazel {' '.join(args)}\n{done.stderr[-4000:]}")
    return done.stdout


def doctest_items(log: str) -> list[str]:
    """The items a rustdoc test log ran a doctest for. A crate-level doctest names no item
    (`test src/lib.rs - (line 35) - compile ... ok`), and is the empty item."""
    return sorted(set(re.findall(r"^test \S+ - (?:(\S+) )?\(line \d+\)", log, re.M)))


def _binary_entry(label: str, row: dict, exec_root: Path) -> dict:
    entry = {"label": label, "package": row["package"], "root": row["root"],
             "manual": row["manual"], "tests": []}
    if row["manual"]:
        built = subprocess.run(["bazel", "build", "--noshow_progress", label], cwd=REPO,
                               capture_output=True, text=True)
        if built.returncode != 0:
            entry["does_not_build"] = built.stderr[-2000:]
            return entry
    exe = exec_root / bazel("cquery", "--output=files", label).strip().splitlines()[0]
    entry["tests"] = listed(exe)
    return entry


def _doctests(docs: list[str]) -> list[dict]:
    bazel("test", "--noshow_progress", "--nocache_test_results", *docs)
    logs = Path(bazel("info", "bazel-testlogs").strip())
    doctests = []
    for label in docs:
        package, name = label[2:].split(":")
        log = (logs / package / name / "test.log").read_text()
        doctests.append({"label": label, "package": package, "items": doctest_items(log)})
    return doctests


def collect() -> dict:
    """Build every `rust_test` and list what each binary contains; run the doctest targets
    (their runner forwards no arguments, so `--list` cannot reach them) and read the items
    from the log. A `manual` target that does not build is recorded as containing nothing:
    nothing builds it, so it covers nothing."""
    table = _rust_targets.table()
    tests = {label: row for label, row in table.items() if row["kind"] == "rust_test"}
    docs = sorted(label for label, row in table.items() if row["kind"] == "rust_doc_test")
    bazel("build", "--noshow_progress", *(label for label, row in tests.items() if not row["manual"]))
    exec_root = Path(bazel("info", "execution_root").strip())
    binaries = [_binary_entry(label, row, exec_root) for label, row in sorted(tests.items())]
    return {"binaries": binaries, "doctests": _doctests(docs) if docs else []}
