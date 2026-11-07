# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict on the real tree: the claim, then the images, the wheel and the tooling."""

from __future__ import annotations

import sys
import tomllib

import _toolchains
from workflow_reader import workflows

from _python_runtime.claim import check
from _python_runtime.config import (
    DOCKER_DIR,
    ECOSYSTEM,
    MODULE_BAZEL,
    PYPROJECT,
    REPO_ROOT,
    TOOLING_PIN,
    WHEEL_BUILD,
)
from _python_runtime.images import check_images
from _python_runtime.tooling import ToolingInputs, check_tooling
from _python_runtime.wheel import check_wheel_metadata


def fail(message: str) -> int:
    print(f"python-runtime gate: FAIL — {message}", file=sys.stderr)
    return 1


def _dockerfiles() -> dict[str, str]:
    return {
        path.relative_to(REPO_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(DOCKER_DIR.glob("Dockerfile*"))
        if path.is_file()
    }


def _deploy_refusal(project: dict, pinned: dict) -> tuple[str | None, int]:
    """The images and the wheel metadata, and how many Dockerfiles were examined."""
    dockerfiles = _dockerfiles()
    if not dockerfiles:
        return (
            f"no Dockerfile under {DOCKER_DIR.relative_to(REPO_ROOT)} — the image half of "
            f"this gate would measure nothing, which is not the same as finding nothing"
        ), 0
    refusal = check_images(dockerfiles, pinned)
    if refusal is None:
        refusal = check_wheel_metadata(WHEEL_BUILD.read_text(encoding="utf-8"), project)
    return refusal, len(dockerfiles)


def _tooling_refusal(pinned: dict) -> tuple[str | None, str | None, int]:
    """The tooling pin's refusal, the pin it read, and how many workflows were examined."""
    pin_file = REPO_ROOT / TOOLING_PIN
    tooling = pin_file.read_text(encoding="utf-8").strip() if pin_file.is_file() else None
    flows = workflows(REPO_ROOT)
    inputs = ToolingInputs(tooling, MODULE_BAZEL.read_text(encoding="utf-8"), flows)
    refusal = check_tooling(inputs, pinned, REPO_ROOT)
    return refusal, tooling, len(flows)


def judge() -> int:
    project = tomllib.load(PYPROJECT.open("rb"))["project"]
    entry = _toolchains.load().get(ECOSYSTEM)
    refusal, summary = check(project.get("requires-python"), entry)
    if refusal is not None:
        return fail(refusal)

    # Only reached once the claim and the pin agree, so `pinned` is the set `check` accepted.
    pinned, _ = _toolchains.interpreters(entry, ECOSYSTEM)
    refusal, dockerfile_count = _deploy_refusal(project, pinned)
    if refusal is not None:
        return fail(refusal)
    refusal, tooling, workflow_count = _tooling_refusal(pinned)
    if refusal is not None:
        return fail(refusal)

    print(
        f"python-runtime gate: OK — {summary}; {dockerfile_count} deploy Dockerfile(s) "
        f"examined, every stage installing the MCP-RE wheel on a pinned interpreter; the "
        f"Bazel wheel's metadata equals pyproject.toml's; {TOOLING_PIN}, the Bazel toolchain "
        f"and every Python-running job of {workflow_count} workflow(s) name {tooling}"
    )
    return 0
