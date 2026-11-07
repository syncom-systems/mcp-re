# SPDX-License-Identifier: Apache-2.0
"""Selftest: the path extractors, which are half the gate — a pattern that stopped matching
would report an empty scope as a clean tree."""

from __future__ import annotations

from _merge_path.extract import (
    command_position_paths,
    not_executable,
    scripts_in,
    truncating_fetches,
)
from _merge_path.selftest_support import expect
from workflow_reader import parse, shell_commands

_EXTRACTED = [
    ("true \\\n    && python3 scripts/module_size_gate.py \\\n    --x", "scripts/module_size_gate.py"),
    ("true \\\n    && ./scripts/verification_runner_preflight.sh \\\n    --x", "scripts/verification_runner_preflight.sh"),
    ("python3 tools/verification/test_views.py", "tools/verification/test_views.py"),
]

#: COUNT INVOCATIONS, NOT MENTIONS. A script a comment explains, or a usage line names, is
#: not one a workflow runs, and reading either as coverage is a control enforced by prose.
_MENTIONS = [
    ("# python3 scripts/a_gate.py is why this step exists\ntrue", "a comment"),
    ('echo "usage: python3 scripts/a_gate.py"', "a usage line"),
]

#: The command-position extractor, which is the half that found an unstageable mode. Both
#: directions, because either mistake is silent: a pattern that matched an interpreted path
#: would demand an execute bit nothing uses, and one that missed a program would report a
#: control as runnable that cannot start.
_COMMAND_POSITION = [
    ("true \\\n    && tools/verification/evidence-class-census --selftest", True, "a program after &&"),
    ("jobs:\n  a:\n    steps:\n      - run: tools/verification/verify-mutations\n", True, "a program as a run: step"),
    ("  scripts/run_gate.sh --selftest", True, "a program at the head of a line"),
    ("true \\\n    && python3 tools/verification/test_views.py", False, "an argument to python3"),
    ("    . scripts/lib/sat_replay_fleet.sh || exit 1", False, "a sourced shim"),
    ("jobs:\n  a:\n    steps:\n      - run: bash scripts/demo-local.sh\n", False, "an argument to bash"),
    ('docker run --rm "$image" \\\n  ./tools/verification/regenerate-lean', True, "a program another program runs"),
    ('image="$(python3 tools/verification/extraction-image load)"', False, "an argument to python3 inside a substitution"),
]

_CHECKOUT_DEEP = "      - uses: actions/checkout@v7\n        with:\n          fetch-depth: 0\n"
_CHECKOUT = "      - uses: actions/checkout@v7\n"

#: The shallow-fetch rule, both directions. It exists because the defect it names was
#: introduced BY a new control and broke a different one: the fix and the breakage were in
#: the same commit, and nothing related them.
_SHALLOW_FETCH = [
    ("jobs:\n  a:\n    steps:\n" + _CHECKOUT_DEEP + "      - run: git fetch --no-tags --depth=1 origin main\n",
     True, "a --depth fetch in a deep checkout"),
    ("jobs:\n  a:\n    steps:\n" + _CHECKOUT_DEEP + "      - run: git fetch --no-tags origin main\n",
     False, "a full fetch in a deep checkout"),
    ("jobs:\n  a:\n    steps:\n" + _CHECKOUT + "      - run: git fetch --depth=1 origin main\n",
     False, "a shallow fetch where no step asked for the whole graph"),
    ("jobs:\n  a:\n    steps:\n" + _CHECKOUT_DEEP + "      - run: git fetch --shallow-since=2026-01-01 origin main\n",
     True, "the other shallowing form"),
    ("jobs:\n  a:\n    steps:\n" + _CHECKOUT_DEEP
     + "  b:\n    steps:\n" + _CHECKOUT + "      - run: git fetch --depth=1 origin main\n",
     False, "a shallow fetch in a job that never took the whole graph, beside one that did"),
]


def _check_script_extractor() -> None:
    expect(
        "tools/verification/verify" not in scripts_in(shell_commands("python3 tools/verification/verify")),
        "the extractor matched an extensionless path",
    )
    for text, wanted in _EXTRACTED:
        expect(wanted in scripts_in(shell_commands(text)), f"the extractor missed {wanted} in {text!r}")
    for text, why in _MENTIONS:
        expect(not scripts_in(shell_commands(text)), f"{why} counted as an invocation")


def _check_command_position() -> None:
    for text, wanted, why in _COMMAND_POSITION:
        commands = parse(text).commands() if text.startswith("jobs:") else shell_commands(text)
        matched = bool(command_position_paths(commands))
        expect(
            matched is wanted,
            f"command-position extractor {'missed' if wanted else 'matched'} {why}: {text!r}",
        )


def _check_not_executable() -> None:
    """A path that exists and is not executable must be reported, while a missing path must
    not be — that is the coverage half's finding, and naming it here would send someone to
    the wrong fix."""
    expect(
        not_executable({"scripts/local_gate.sh", "README.md"}) == ["README.md"],
        "the executable check does not distinguish a non-executable file",
    )
    expect(
        not not_executable({"scripts/a-file-that-does-not-exist.sh"}),
        "a missing path was reported as a permissions defect",
    )


def _check_shallow_fetch() -> None:
    for text, wanted, why in _SHALLOW_FETCH:
        flagged = bool(truncating_fetches(parse(text)))
        expect(flagged is wanted, f"shallow-fetch rule {'missed' if wanted else 'flagged'} {why}")


def check() -> None:
    _check_script_extractor()
    _check_command_position()
    _check_not_executable()
    _check_shallow_fetch()
