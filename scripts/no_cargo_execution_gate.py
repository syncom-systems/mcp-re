#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""No-Cargo-execution gate — Bazel is the Rust build and test authority, and nothing else runs.

THE INVARIANT. No CI workflow, repository script or tool, hook, verification lane,
remediation or audit skill, test harness, SLO or release path, container definition or
maintained developer command may invoke the `cargo` executable — directly, or through a
tool whose job is to drive it. Rust build and test execution is Bazel's. `Cargo.toml`,
lockfiles and prose are not violations: this gate reads INVOCATIONS, never mentions.

WHAT COUNTS AS AN INVOCATION, per context:

  * shell — workflow `run:` blocks, `*.sh`, Dockerfile `RUN`, Makefiles, hook entries,
    package.json scripts, and the fenced shell blocks of the maintained command documents:
    `cargo` or a `cargo-<tool>` binary in command position, and the wrappers that drive
    Cargo — `rustup run <toolchain> cargo`, `$CARGO`/`${CARGO}`, `napi build`,
    `maturin build|develop|publish`, `charon cargo`, `cross build|test`. Comments and
    `echo`/`printf` lines state a command without running it.
  * Python — an argv list whose first element is `cargo` or a `cargo-<tool>` (or ends in
    `/cargo`), a shell string beginning with one, and a `charon` argv followed by `cargo`.
  * Rust — `Command::new("cargo")`, or spawning `env!("CARGO")` / `var("CARGO")`.
  * JavaScript/TypeScript — `exec`/`spawn` of `cargo`, `napi build`, `maturin`.
  * TOML registries — an argv array (`protocol`, `control`, `argv`, `command`) whose first
    element is `cargo`.
  * pyproject.toml — a `maturin` build backend.

WHAT IS NOT READ: history. Archived documents, the changelog, dated review packets, rulings,
security audit records and finding ledgers describe what was run then; rewriting them would
falsify the record, and none of them is executed.

    python3 scripts/no_cargo_execution_gate.py            # the verdict
    python3 scripts/no_cargo_execution_gate.py --selftest # prove each rule can FAIL
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _no_cargo.classify import (  # noqa: E402,F401
    classify,
    executable_scripts,
    scan,
    tracked_files,
)
from _no_cargo.cli import judge  # noqa: E402
from _no_cargo.config import (  # noqa: E402,F401
    ARGV_KEYS,
    CARGO_ACTION,
    COMMAND_DOCS,
    FENCE,
    HISTORY,
    INLINE,
    PRINTS,
    REPO,
    SHELL_LANGS,
    SHELL_RULES,
)
from _no_cargo.pysrc import python_hits  # noqa: E402,F401
from _no_cargo.selftest import selftest  # noqa: E402,F401
from _no_cargo.shell import markdown_hits, package_json_hits, shell_hits  # noqa: E402,F401
from _no_cargo.sources import js_hits, rust_hits, toml_hits  # noqa: E402,F401
from _no_cargo.workflow import workflow_hits  # noqa: E402,F401


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    return judge()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
