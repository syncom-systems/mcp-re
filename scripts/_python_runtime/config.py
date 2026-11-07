# SPDX-License-Identifier: Apache-2.0
"""Where the gate reads from and the syntax of the files it reads."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "verification"))

PYPROJECT = REPO_ROOT / "sdk" / "python" / "pyproject.toml"
ECOSYSTEM = "python"
DOCKER_DIR = REPO_ROOT / "deploy" / "docker"

#: `FROM <image> AS <stage>` — the stage name is optional, because an unnamed final stage
#: is still a stage that can install the wheel.
FROM_LINE = re.compile(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE)

#: A `python:` base image, with the version as the tag's leading component.
PYTHON_BASE = re.compile(r"^python:([0-9][^-\s]*)(?:-\S+)?$")

#: What makes a stage one that runs OUR wheel. Matched on the install command rather than
#: on the stage name: a stage renamed from `loadgen` to anything else installs the same
#: wheel, and a rule keyed on the name would stop applying without anything changing.
INSTALLS_SDK = re.compile(r"pip3?\s+install[^\n]*(?:/wheels/|sdk/python)")

#: One clause of a `requires-python` specifier: an operator and a dotted version.
CLAUSE = re.compile(r"^(>=|>|<=|<|==|!=|~=)\s*(\d+)\.(\d+)(?:\.\d+)?$")

#: The Bazel wheel target. Its metadata restates pyproject.toml's, because py_wheel reads no
#: pyproject — so the two are one fact written twice, and this is what keeps them one.
WHEEL_BUILD = REPO_ROOT / "sdk" / "python" / "BUILD.bazel"

#: The tooling interpreter, for the tools that read a file rather than the lock.
TOOLING_PIN = ".python-version"
MODULE_BAZEL = REPO_ROOT / "MODULE.bazel"

#: The `python.toolchain(...)` call in MODULE.bazel and the version it registers.
BAZEL_TOOLCHAIN = re.compile(r"^python\.toolchain\((.*?)^\)", re.S | re.M)
BAZEL_VERSION = re.compile(r'python_version\s*=\s*"([^"]+)"')

SETUP_PYTHON = "actions/setup-python@"

#: `python` or `python3` as a word of its own: not `sdk/python`, not `--python`.
PYTHON_WORD = re.compile(r"(?<![\w./-])python3?(?![\w.-])")
