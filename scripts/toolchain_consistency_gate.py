#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Toolchain-version consistency gate — one production rustc, stated once, read everywhere.

`MODULE.bazel`'s first `rust.toolchain` version is the production compiler: Bazel builds and
tests with it, and its cargo, rustfmt and clippy come from the same hermetic release. Every
other place that names a production Rust version must equal it:

  * `verification/policy/toolchains.lock.toml` `[rust].channel`, which the evidence engine
    fingerprints;
  * the `rust_toolchain` of each resolved Verus pin (`[verus]`, `[verus_linux_x86_64]`), because
    the prover runs on the registered toolchain's own `librustc_driver`;
  * the workflow job names, which state NO version: a required-check identifier that carried
    one would need a ruleset change with every compiler bump. The version is reported inside
    the job instead, by this gate's own pre-merge step.

The extraction lane's nightly is a separate compiler on purpose and is checked only for being
the nightly `[charon].rust_toolchain` pins.

    python3 scripts/toolchain_consistency_gate.py             # the verdict
    python3 scripts/toolchain_consistency_gate.py --selftest  # prove the verdict can be FAIL
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))

import _registries  # noqa: E402

VERSION = re.compile(r"\d+\.\d+\.\d+")
JOB_NAME_VERSION = re.compile(r"^    name:.*\d+\.\d+\.\d+", re.M)
WORKFLOW_FILES = ("pre-merge.yml", "live-infra-e2e.yml")


def production_version(module_text: str) -> str | None:
    block = re.search(r"rust\.toolchain\((.*?)^\)", module_text, re.S | re.M)
    versions = re.search(r"versions = \[\s*\"([^\"]+)\"", block.group(1)) if block else None
    return versions.group(1) if versions and VERSION.fullmatch(versions.group(1)) else None


def nightly_version(module_text: str) -> str | None:
    found = re.search(r"\"nightly/(\d{4}-\d{2}-\d{2})\"", module_text)
    return f"nightly-{found.group(1)}" if found else None


def check(module_text: str, lock: dict, workflows: dict[str, str], merge_gate: str) -> list[str]:
    problems = []
    want = production_version(module_text)
    if want is None:
        return ["MODULE.bazel: no production rust.toolchain version was read — comparing nothing is not a pass"]
    if lock.get("rust", {}).get("channel") != want:
        problems.append(f"toolchains.lock.toml [rust].channel is {lock.get('rust', {}).get('channel')!r}, "
                        f"MODULE.bazel builds with {want}")
    for table in ("verus", "verus_linux_x86_64"):
        pin = lock.get(table, {})
        if pin.get("state") == "resolved" and not str(pin.get("rust_toolchain", "")).startswith(f"{want}-"):
            problems.append(f"toolchains.lock.toml [{table}].rust_toolchain is "
                            f"{pin.get('rust_toolchain')!r}, not {want}-<target>")
    for path, text in workflows.items():
        problems += [f"{path}: a job name states a version ({m.group(0).strip()!r}); a check name is stable"
                     for m in JOB_NAME_VERSION.finditer(text)]
    if not workflows or not any(text.strip() for text in workflows.values()):
        problems.append("no workflow was read — comparing nothing is not a pass")
    if VERSION.search(merge_gate):
        problems.append("scripts/merge_readiness_gate.py names a version in the required check")
    nightly = nightly_version(module_text)
    pinned = lock.get("charon", {}).get("rust_toolchain")
    if nightly != pinned:
        problems.append(f"the extraction nightly is {nightly} in MODULE.bazel and {pinned} in the lock's [charon]")
    return problems


def load() -> tuple[str, dict, dict[str, str], str]:
    lock = _registries.document("toolchains", REPO, required=True)
    flows = {f".github/workflows/{n}": (REPO / ".github/workflows" / n).read_text() for n in WORKFLOW_FILES}
    return ((REPO / "MODULE.bazel").read_text(), lock, flows,
            (REPO / "scripts/merge_readiness_gate.py").read_text())


def verdict() -> int:
    module, lock, flows, merge_gate = load()
    problems = check(module, lock, flows, merge_gate)
    if problems:
        print(f"toolchain consistency gate: FAIL — {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"toolchain consistency gate: OK — one production Rust {production_version(module)} across "
          "MODULE.bazel, the toolchain lock and both Verus pins; no job name or required check "
          "carries a version")
    return 0


def selftest() -> int:
    module = 'rust.toolchain(\n    versions = [\n        "1.2.3",\n        "nightly/2026-01-02",\n    ],\n)\n'
    lock = {"rust": {"channel": "1.2.3"},
            "verus": {"state": "resolved", "rust_toolchain": "1.2.3-aarch64-apple-darwin"},
            "verus_linux_x86_64": {"state": "resolved", "rust_toolchain": "1.2.3-x86_64-unknown-linux-gnu"},
            "charon": {"rust_toolchain": "nightly-2026-01-02"}}
    flows = {"a.yml": "    name: Bazel build + test\n        name: step 1.2.3 is a step, not a check\n"}
    gate = 'names = ("Bazel build + test",)'

    def mutated(**kw):
        args = {"module_text": module, "lock": lock, "workflows": flows, "merge_gate": gate}
        args.update(kw)
        return check(**args)

    def with_lock(table, key, value):
        return {**lock, table: {**lock[table], key: value}}

    cases = [
        ("everything agrees", mutated(), None),
        ("the lock channel differs", mutated(lock=with_lock("rust", "channel", "1.2.4")), "[rust].channel"),
        ("the macOS Verus pin names another rustc",
         mutated(lock=with_lock("verus", "rust_toolchain", "1.2.2-aarch64-apple-darwin")), "[verus].rust_toolchain"),
        ("the Linux Verus pin names another rustc",
         mutated(lock=with_lock("verus_linux_x86_64", "rust_toolchain", "1.2.2-x86_64-unknown-linux-gnu")),
         "[verus_linux_x86_64]"),
        ("a job name states the right version",
         mutated(workflows={"a.yml": "    name: Bazel build + test (Rust 1.2.3)\n"}), "a job name states a version"),
        ("a job name states another version",
         mutated(workflows={"a.yml": "    name: tests (Bazel, 1.2.2)\n"}), "a job name states a version"),
        ("no workflow was read", mutated(workflows={}), "comparing nothing"),
        ("the merge fallback names a version",
         mutated(merge_gate='names = ("Bazel build + test (Rust 1.2.3)",)'), "merge_readiness_gate"),
        ("the extraction nightly moved in one place", mutated(module_text=module.replace("01-02", "01-03")),
         "extraction nightly"),
        ("no production version", mutated(module_text="rust.toolchain()\n"), "comparing nothing"),
    ]
    for label, problems, expect in cases:
        text = "\n".join(problems)
        if (expect is None) != (not problems) or (expect and expect not in text):
            print(f"SELFTEST FAILED: {label}: reported {problems}")
            return 1
    print(f"toolchain consistency gate selftest: PASS ({len(cases)} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else verdict())
