# SPDX-License-Identifier: Apache-2.0
"""The fourth fact: the wheel Bazel builds carries the metadata pyproject.toml states."""

from __future__ import annotations

import ast
import re


def _wheel_kwargs(build_text: str) -> dict | None:
    """The literal keyword arguments of the `py_wheel(...)` call in a BUILD file."""
    match = re.search(r"^py_wheel\((.*?)^\)", build_text, re.M | re.S)
    if match is None:
        return None
    call = ast.parse("py_wheel(" + match.group(1) + ")", mode="eval").body
    out = {}
    for keyword in call.keywords:
        try:
            out[keyword.arg] = ast.literal_eval(keyword.value)
        except ValueError:
            continue  # select() and other non-literals are not metadata
    return out


def check_wheel_metadata(build_text: str, project: dict) -> str | None:
    """The fourth fact: the wheel Bazel builds carries the metadata pyproject.toml states."""
    wheel = _wheel_kwargs(build_text)
    if wheel is None:
        return "sdk/python/BUILD.bazel has no py_wheel target, so no wheel is built"
    extras = {k: sorted(v) for k, v in (project.get("optional-dependencies") or {}).items()}
    pairs = (
        ("distribution", wheel.get("distribution"), project.get("name")),
        ("version", wheel.get("version"), project.get("version")),
        ("python_requires", wheel.get("python_requires"), project.get("requires-python")),
        ("extra_requires", {k: sorted(v) for k, v in (wheel.get("extra_requires") or {}).items()},
         extras),
    )
    for field, built, declared in pairs:
        if built != declared:
            return (
                f"the wheel's {field} is {built!r} and pyproject.toml declares {declared!r}. "
                f"py_wheel reads no pyproject, so the two are one fact written twice; the wheel "
                f"that ships would claim something the declaration does not"
            )
    return None
