# SPDX-License-Identifier: Apache-2.0
"""The reader's selftest: every quirk of the YAML subset, the shell reader and the path filter."""

from __future__ import annotations

from _workflow.globs import glob_matches
from _workflow.model import parse
from _workflow.shell import named_paths, shell_commands
from _workflow.syntax import WorkflowSyntaxError, parse_yaml


def _case(label: str, ok: bool, got: object) -> bool:
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got {got!r}")
    return ok


_TRIGGER_TEXT = (
    "on:\n"
    "  pull_request:\n"
    "    paths:\n"
    '      - "a/**"\n'
    "      # why the next one is here\n"
    "      - b/c.py  # trailing note\n"
    "\n"
    "      - 'd/*'\n"
    "  push:\n"
    "    branches: [main]\n"
    "  schedule:\n"
    '    - cron: "0 4 * * *" # nightly\n'
    "  workflow_dispatch:\n"
    "jobs:\n"
    "  build:\n"
    "    steps:\n"
    "      - uses: docker/build-push-action@v6\n"
    "        with:\n"
    "          push: true\n"
)


def _trigger_cases() -> list[bool]:
    triggers = parse(_TRIGGER_TEXT).triggers
    ignored = parse("on:\n  pull_request:\n    paths-ignore:\n      - docs/**\n").triggers["pull_request"]
    return [
        _case(
            "a comment and a blank line inside a list do not end it; a trailing comment is not a pattern",
            triggers["pull_request"].paths == ("a/**", "b/c.py", "d/*"),
            triggers.get("pull_request"),
        ),
        _case(
            "a trigger with no `paths:` is unfiltered, and a key named `push:` inside a job is not a trigger",
            triggers["push"].paths is None and not triggers["push"].filtered and set(triggers)
            == {"pull_request", "push", "schedule", "workflow_dispatch"},
            triggers,
        ),
        _case("`paths-ignore:` filters a trigger too", ignored.filtered and ignored.paths is None, ignored),
        _case(
            "`on:` as a flow list and as a single name",
            set(parse("on: [push, pull_request]\n").triggers) == {"push", "pull_request"}
            and set(parse("on: push\n").triggers) == {"push"},
            None,
        ),
    ]


_JOB_TEXT = (
    "on:\n  pull_request:\njobs:\n  a:\n    name: Check A\n    runs-on: [self-hosted, macOS]\n"
    "    env:\n      X: 1\n    steps:\n      - name: one\n        run: |\n"
    "          # a script/x.py in a comment\n"
    "          python3 scripts/a_gate.py --selftest   # and a trailing one\n"
    "          bazel test \\\n            //pkg:t \\\n            --test_arg=m::\n"
    '          echo "usage: scripts/b_gate.py"\n'
    "      - run: >-\n          scripts/run_test_lane.sh bazel test --test_output=all\n"
    "          //pkg:folded\n"
    "      - uses: actions/checkout@v7\n        with:\n          fetch-depth: 0\n"
    "  b:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: tools/verification/verify-tests\n"
)


def _job_cases() -> list[bool]:
    flow = parse(_JOB_TEXT)
    a, b = flow.jobs["a"], flow.jobs["b"]
    empty = parse("jobs:\n  a:\n    steps:\n      - run: |\n      - run: >-\n").commands()
    texts = [c.text for c in a.commands()]
    return [
        _case(
            "jobs are only the keys under `jobs:`, the check name is `name:` or the key",
            set(flow.jobs) == {"a", "b"} and a.name == "Check A" and b.name == "b",
            flow.jobs,
        ),
        _case("runs-on as a flow list", a.runs_on == ("self-hosted", "macOS"), a.runs_on),
        _case("an empty block scalar runs nothing", empty == [], empty),
        _case(
            "comments are dropped, `\\` continuations are joined, a `>-` scalar folds to one line",
            texts == [
                "python3 scripts/a_gate.py --selftest",
                "bazel test //pkg:t --test_arg=m::",
                'echo "usage: scripts/b_gate.py"',
                "scripts/run_test_lane.sh bazel test --test_output=all //pkg:folded",
            ],
            texts,
        ),
        _case("a usage line prints rather than runs", [c.prints for c in a.commands()] == [False, False, True, False], None),
        _case("a step's `with:` is read", a.steps[2].with_ == {"fetch-depth": "0"}, a.steps[2].with_),
        _case(
            "line numbers point at the command",
            [c.line for c in a.commands()] == [13, 14, 17, 19],
            [c.line for c in a.commands()],
        ),
    ]


_INVOCATIONS = [
    ("python3 scripts/x.py --flag", [("scripts/x.py", "python3")], "an interpreted script"),
    ("FOO=1 ./scripts/x.sh a b", [("scripts/x.sh", None)], "a program after an assignment"),
    ("true && tools/verification/verify || exit 1", [("true", None), ("tools/verification/verify", None), ("exit", None)], "segments at && and ||"),
    ("if python3 -I scripts/x.py; then echo ok; fi", [("scripts/x.py", "python3"), ("fi", None)], "a program after `if`, flags before the script; `echo` prints"),
    ("timeout 300 sudo apt-get update", [("apt-get", None)], "timeout and sudo wrap a program"),
    ('echo "run scripts/x.py"', [], "a usage line runs nothing"),
    ('echo "$T" | docker login ghcr.io -u u --password-stdin', [("docker", None)], "a pipe after `echo` runs its program"),
    ('echo "::group::x" && python3 scripts/x.py', [("scripts/x.py", "python3")], "a chain after `echo` runs its program"),
    ('grep "a|b" file', [("grep", None)], "a quoted `|` does not split"),
    (". scripts/lib/shim.sh", [("scripts/lib/shim.sh", ".")], "a sourced file"),
    ('image="$(python3 tools/x load)" || return 1', [("tools/x", "python3"), ("return", None)], "a command substitution runs its own command"),
    ("true `# a note naming scripts/x.py` && scripts/y.sh", [("true", None), ("scripts/y.sh", None)], "a backtick comment runs nothing"),
    ("a=`scripts/z.sh`", [("scripts/z.sh", None)], "a backtick substitution runs its command"),
]


def _ran(text: str) -> list[tuple[str, str | None]]:
    return [(i.program, i.interpreter) for c in shell_commands(text) for i in c.invocations()]


def _invocation_cases() -> list[bool]:
    return [_case(f"invocations: {label}", _ran(text) == expect, _ran(text)) for text, expect, label in _INVOCATIONS]


def _printing_cases() -> list[bool]:
    piped = shell_commands('echo "$T" | docker login ghcr.io -u u --password-stdin')[0]
    chained = shell_commands('echo "::group::x" && python3 scripts/x.py')[0]
    usage = shell_commands('echo "usage: scripts/x.py" | tee -a log && printf x')[0]
    only_prints = shell_commands("echo a && printf b")[0]
    noted = shell_commands("true \\\n  `# scripts/x.py explains the next link` \\\n  && python3 scripts/y.py")[0]
    prose = "run ./tools/verification/verify-tests and scripts/x.py."
    return [
        _case(
            "a command that prints and runs is not a usage line; its executed code keeps what runs",
            not piped.prints and "docker login" in piped.executed and "echo" not in piped.executed
            and not chained.prints and named_paths(chained.executed) == {"scripts/x.py"},
            (piped.prints, piped.executed, chained.executed),
        ),
        _case(
            "`prints` is a command whose every segment prints, and then nothing is executed",
            only_prints.prints and only_prints.executed == "" and not usage.prints and named_paths(usage.executed) == set(),
            (usage.prints, usage.executed),
        ),
        _case("a backtick comment is not code", named_paths(noted.code) == {"scripts/y.py"}, named_paths(noted.code)),
        _case(
            "named paths see an extensionless entry point and ignore prose punctuation",
            named_paths(prose) == {"tools/verification/verify-tests", "scripts/x.py"},
            named_paths(prose),
        ),
    ]


def _refuses(label: str, action) -> bool:
    try:
        action()
    except WorkflowSyntaxError:
        return _case(label, True, None)
    return _case(label, False, "accepted")


_REFUSED_YAML = [
    ("x: &anchor\n  a: 1\n", "an anchor"),
    ("x: {a: 1}\n", "a flow mapping with content"),
    ("x:\n  - a\n  y: 1\n", "content the reader cannot place"),
    ("jobs:\n  a: {}\n  a: {}\n", "a repeated key"),
    ("on:\n  pull_request:\n  pull_request:\n    paths: [a]\n", "a repeated trigger"),
    ("x: |2\n    a # b\n    c\n", "a block scalar header with an indentation indicator"),
    ("x:\n  - >-1\n    a\n", "an indentation indicator in a sequence entry"),
]


def _path_filter_cases() -> list[bool]:
    return [
        _case(
            "`**` crosses a separator, `*` does not, and `**/` matches the root",
            glob_matches("a/**", "a/b/c.rs") and not glob_matches("a/*", "a/b/c.rs")
            and glob_matches("**/BUILD.bazel", "BUILD.bazel") and glob_matches("**/BUILD.bazel", "a/b/BUILD.bazel")
            and not glob_matches("**/BUILD.bazel", "a/BUILD.bazel.bak"),
            None,
        ),
        _refuses("refuses a `?` pattern rather than guessing", lambda: glob_matches("a/?.rs", "a/b.rs")),
    ]


def _refusal_cases() -> list[bool]:
    return [_refuses(f"refuses {label}", lambda text=text: parse_yaml(text)) for text, label in _REFUSED_YAML]


def selftest() -> int:
    results = (
        _trigger_cases()
        + _job_cases()
        + _invocation_cases()
        + _printing_cases()
        + _path_filter_cases()
        + _refusal_cases()
    )
    if not all(results):
        print("workflow reader: SELFTEST FAILED")
        return 1
    print(f"workflow reader: selftest passed ({len(results)} cases)")
    return 0
