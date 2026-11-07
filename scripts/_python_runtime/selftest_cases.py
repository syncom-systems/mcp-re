# SPDX-License-Identifier: Apache-2.0
"""The selftest's scenarios: each refusal paired with the acceptance it must not swallow.

A gate that refuses everything measures as little as one that refuses nothing.
"""

from __future__ import annotations

import _toolchains
from workflow_reader import Workflow, parse

from _python_runtime.config import ECOSYSTEM


WHEEL_SELFTEST_PROJECT = {
    "name": "mcp-re-sdk", "version": "0.1.0", "requires-python": ">=3.14.5,<3.15",
    "optional-dependencies": {"mcp": ["mcp>=2.0,<3.0"]},
}
_WHEEL_OK = ('py_wheel(\n    distribution = "mcp-re-sdk",\n    version = "0.1.0",\n'
             '    python_requires = ">=3.14.5,<3.15",\n'
             '    extra_requires = {"mcp": ["mcp>=2.0,<3.0"]},\n'
             '    platform = select({"//x": "y"}),\n)\n')
WHEEL_SELFTEST_CASES = (
    ("a wheel that restates pyproject", _WHEEL_OK, False),
    ("a wheel with another version", _WHEEL_OK.replace('"0.1.0"', '"0.2.0"'), True),
    ("a wheel with a wider supported range", _WHEEL_OK.replace(",<3.15", ""), True),
    ("a wheel with an extra pyproject lacks",
     _WHEEL_OK.replace('{"mcp": ["mcp>=2.0,<3.0"]}', '{"mcp": ["mcp>=2.0,<3.0"], "x": ["y"]}'), True),
    ("no wheel target at all", "filegroup(name = 'x')\n", True),
)


#: The ways the support claim itself can be wrong or disagree with a well-formed pin, each
#: paired with the positive case it must not reject. A gate that refuses everything measures
#: as little as one that refuses nothing.
CLAIM_CASES = (
    (
        "an unbounded support claim",
        ">=3.10",
        {"state": "resolved", "interpreters": ["3.10.20"]},
        True,
    ),
    (
        "a supported minor nothing measures",
        ">=3.10,<3.13",
        {"state": "resolved", "interpreters": ["3.10.20", "3.11.15"]},
        True,
    ),
    (
        "an interpreter measured outside the claim",
        ">=3.10,<3.12",
        {"state": "resolved", "interpreters": ["3.10.20", "3.11.15", "3.12.13"]},
        True,
    ),
)

#: The pin-shape cases the Node runtime gate runs too, from `_toolchains`, against a claim
#: the well-formed pin satisfies exactly.
PIN_CLAIM = ">=3.10,<3.12"
SELFTEST_CASES = CLAIM_CASES + tuple(
    (name, PIN_CLAIM, entry, must_refuse)
    for name, entry, must_refuse in _toolchains.pin_shape_cases(ECOSYSTEM, ["3.10.20", "3.11.15"])
)


#: The wheel-installing base image, against the pinned set. Same shape and same rule as
#: `SELFTEST_CASES`: every refusal paired with the acceptance it must not swallow.
IMAGE_SELFTEST_CASES = (
    (
        "the stale base image the v0.17 candidate actually carried",
        {"Dockerfile.loadgen": "FROM rust:1 AS wheel\nRUN cd sdk/python && maturin build\n"
                               "FROM python:3.12-slim AS loadgen\n"
                               "RUN pip install --no-cache-dir /wheels/*.whl\n"},
        True,
    ),
    (
        "a floating minor tag inside the supported range",
        {"Dockerfile.loadgen": "FROM python:3.14-slim AS loadgen\n"
                               "RUN pip install --no-cache-dir /wheels/*.whl\n"},
        True,
    ),
    (
        "a base image naming no readable version",
        {"Dockerfile.loadgen": "FROM ghcr.io/example/python AS loadgen\n"
                               "RUN pip install --no-cache-dir /wheels/*.whl\n"},
        True,
    ),
    (
        "the install attributed to the BUILDER stage rather than the runtime one",
        {"Dockerfile.loadgen": "FROM python:3.12-slim AS wheel\n"
                               "RUN pip3 install --no-cache-dir maturin\n"
                               "FROM python:3.14.7-slim AS loadgen\n"
                               "RUN pip install --no-cache-dir /wheels/*.whl\n"},
        False,
    ),
    (
        "a stage that installs something else entirely",
        {"Dockerfile.inner": "FROM python:3.12-slim AS inner\n"
                             "RUN pip install --no-cache-dir \"mcp==2.0.0\"\n"},
        False,
    ),
    (
        "the pinned interpreter, exactly",
        {"Dockerfile.loadgen": "FROM python:3.14.7-slim AS loadgen\n"
                               "RUN pip install --no-cache-dir /wheels/*.whl\n"},
        False,
    ),
)

#: The pin the image cases are measured against — one interpreter, as the tree declares.
IMAGE_SELFTEST_PIN = {(3, 14): "3.14.7"}


_MODULE_OK = 'python.toolchain(\n    is_default = True,\n    python_version = "3.14.7",\n)\n'
_CHECKOUT = "      - uses: actions/checkout@v6\n"
_SETUP = ("      - uses: actions/setup-python@v7\n        with:\n"
          "          python-version-file: .python-version\n")
_GATE = "      - run: python3 scripts/x_gate.py\n"


def _flow(steps: str) -> list[Workflow]:
    return [parse("on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + steps, "w.yml")]


#: The tooling pin against MODULE.bazel and the workflows, each refusal paired with the
#: acceptance it must not swallow.
TOOLING_SELFTEST_CASES = (
    ("every place names the pinned interpreter", "3.14.7", _MODULE_OK,
     _flow(_CHECKOUT + _SETUP + _GATE), False),
    ("no tooling pin file", None, _MODULE_OK, _flow(_CHECKOUT + _SETUP + _GATE), True),
    ("a tooling pin outside the pinned set", "3.14.6", _MODULE_OK.replace("3.14.7", "3.14.6"),
     _flow(_CHECKOUT + _SETUP + _GATE), True),
    ("the Bazel toolchain the repository had", "3.14.7", _MODULE_OK.replace("3.14.7", "3.12"),
     _flow(_CHECKOUT + _SETUP + _GATE), True),
    ("a job running Python on the runner's interpreter", "3.14.7", _MODULE_OK,
     _flow(_CHECKOUT + _GATE), True),
    ("a job setting Python up only after its first Python step", "3.14.7", _MODULE_OK,
     _flow(_CHECKOUT + _GATE + _SETUP), True),
    ("a setup step naming a floating minor", "3.14.7", _MODULE_OK,
     _flow(_CHECKOUT + _SETUP.replace("python-version-file: .python-version",
                                      'python-version: "3.14"') + _GATE), True),
    ("the pin file read from a checkout path", "3.14.7", _MODULE_OK,
     _flow(_CHECKOUT + _SETUP.replace(": .python-version", ": tools/.python-version") + _GATE), False),
    ("another file read as the pin", "3.14.7", _MODULE_OK,
     _flow(_CHECKOUT + _SETUP.replace(": .python-version", ": runtime.txt") + _GATE), True),
    ("Python inside a command substitution", "3.14.7", _MODULE_OK,
     _flow(_CHECKOUT + "      - run: d=\"$(python3 -c 'print(1)')\"\n"), True),
    ("a job that runs no Python", "3.14.7", _MODULE_OK,
     _flow(_CHECKOUT + "      - run: cd sdk/python && ls --python\n"), False),
    ("no workflow at all", "3.14.7", _MODULE_OK, [], True),
)
