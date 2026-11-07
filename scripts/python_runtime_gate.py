#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The Python support claim may not exceed the Python evidence — issue #746.

`sdk/python/pyproject.toml` declares which interpreters the shipped SDK supports.
`verification/policy/toolchains.lock.toml` `[python].interpreters` names the exact ones the
authoritative battery is measured on. Those are two different facts written in two places,
and before this gate existed they had drifted: the package claimed `>=3.10` — an unbounded
claim over every future runtime — while one unpinned CPython ran the battery.

So the rule is a mutual one, and both directions are failures:

  * a supported minor with no pinned interpreter is a claim with no evidence;
  * a pinned interpreter outside the supported range is evidence for something the package
    says it does not support, which is measurement effort spent outside the claim.

`requires-python` is parsed rather than pattern-matched for a lower and upper bound, because
a range this gate cannot read is a range it cannot check, and silently passing an
unrecognised specifier is exactly the "configured but enforces nothing" shape the repository
refuses. An unbounded upper end therefore FAILS: it claims every future minor.

THE THIRD FACT is the one that broke on the v0.17 candidate: a **deploy image that
installs the shipped wheel** carries an interpreter too, and nothing related it to either
of the two above. `deploy/docker/Dockerfile.loadgen` sat on `python:3.12-slim` — correct
while the package claimed `>=3.10`, and unbuildable the moment the support claim was
narrowed to `>=3.14.5`. It failed at `docker build`, in stage 5, after a three-replica
fleet rollout, with `ERROR: Package 'mcp-re-sdk' requires a different Python` — a support
decision surfacing as a deploy failure two lanes away from where it was taken.

So a Dockerfile stage that pip-installs the MCP-RE wheel must name a base image that is
EXACTLY one of the pinned interpreters. Exactly, not merely inside the range: a floating
`python:3.14-slim` is a different artefact on every rebuild, which is the reason
`Dockerfile.inner` already gives for pinning `mcp` to an exact version, and "inside the
range at build time" is not a property of the file. A stage that does NOT install the
wheel is not bound by this — `Dockerfile.inner` runs the upstream MCP SDK and nothing of
ours, and its interpreter is its own business.

THE FIFTH FACT is the interpreter the repository's own tooling runs on. The gates, the
verification tools and the SDK batteries are Python, and each runs on whatever `python3`
its environment resolves: a runner's system interpreter, or a developer's newest Homebrew
one. `.python-version` names it once, for the tools that read a file rather than the lock
(`actions/setup-python`, uv, pyenv), and three things must agree with it:

  * it is one of the pinned interpreters;
  * the default rules_python toolchain in `MODULE.bazel`, which runs every Bazel `py_test`;
  * every workflow job that runs Python sets up that interpreter, from that file, before
    its first Python step. A job that does not runs the runner image's system Python.

Run: python3 scripts/python_runtime_gate.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _python_runtime.config import (  # noqa: E402,F401
    DOCKER_DIR,
    ECOSYSTEM,
    MODULE_BAZEL,
    PYPROJECT,
    REPO_ROOT,
    TOOLING_PIN,
    WHEEL_BUILD,
)
from _python_runtime.claim import check, supported_minors  # noqa: E402,F401
from _python_runtime.cli import fail, judge  # noqa: E402,F401
from _python_runtime.images import check_images, wheel_stages  # noqa: E402,F401
from _python_runtime.selftest import selftest  # noqa: E402,F401
from _python_runtime.tooling import (  # noqa: E402,F401
    ToolingInputs,
    check_job,
    check_tooling,
    setup_reads_pin,
    step_runs_python,
    tool_runs_python,
)
from _python_runtime.wheel import check_wheel_metadata  # noqa: E402,F401


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    return judge()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
