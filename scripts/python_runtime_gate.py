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

import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools" / "verification"))

import _toolchains  # noqa: E402
from workflow_reader import Job, Step, Workflow, parse, workflows  # noqa: E402

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


def fail(message: str) -> int:
    print(f"python-runtime gate: FAIL — {message}", file=sys.stderr)
    return 1


def supported_minors(specifier: str) -> tuple[list[tuple[int, int]], str | None]:
    """The (major, minor) pairs a `requires-python` specifier admits, or why it cannot be read."""
    floor: tuple[int, int] | None = None
    ceiling: tuple[int, int] | None = None
    ceiling_inclusive = False
    for raw in specifier.split(","):
        clause = raw.strip()
        match = CLAUSE.match(clause)
        if match is None:
            return [], f"cannot read the clause {clause!r} of requires-python {specifier!r}"
        operator, major, minor = match.group(1), int(match.group(2)), int(match.group(3))
        if operator == ">=":
            floor = (major, minor)
        elif operator == "<":
            ceiling, ceiling_inclusive = (major, minor), False
        elif operator == "<=":
            ceiling, ceiling_inclusive = (major, minor), True
        else:
            return [], (
                f"the clause {clause!r} is not a bound this gate reads. Express the support "
                f"claim as `>=X.Y,<A.B`, so a reader and this gate agree on it"
            )
    if floor is None:
        return [], f"requires-python {specifier!r} states no lower bound"
    if ceiling is None:
        return [], (
            f"requires-python {specifier!r} has no upper bound, so it claims support for "
            f"every future Python minor — including ones no battery has ever run on"
        )
    if floor[0] != ceiling[0]:
        return [], f"requires-python {specifier!r} spans two major versions; not supported here"
    last = ceiling[1] if ceiling_inclusive else ceiling[1] - 1
    return [(floor[0], minor) for minor in range(floor[1], last + 1)], None


def check(specifier: str | None, entry) -> tuple[str | None, str]:
    """(refusal, summary) for one support claim measured against one runtime pin.

    Pure, and separate from `main` for one reason: `--selftest` has to be able to feed it
    the divergences this gate exists to catch. A gate whose logic can only be exercised by
    editing the real registry is a gate nobody proves is alive.
    """
    if not specifier:
        return "sdk/python/pyproject.toml declares no requires-python", ""
    claimed, unreadable = supported_minors(specifier)
    if unreadable is not None:
        return unreadable, ""

    pinned, malformed = _toolchains.interpreters(entry, ECOSYSTEM)
    if malformed is not None:
        return malformed, ""

    missing = [f"{major}.{minor}" for major, minor in claimed if (major, minor) not in pinned]
    extra = [
        f"{major}.{minor} ({pinned[(major, minor)]})"
        for (major, minor) in sorted(pinned)
        if (major, minor) not in claimed
    ]
    if missing:
        return (
            f"requires-python {specifier} claims {', '.join(missing)}, which no pinned "
            f"interpreter measures. A support claim wider than its evidence reads one "
            f"runtime's green as proof about the rest"
        ), ""
    if extra:
        return (
            f"[python].interpreters pins {', '.join(extra)}, outside the supported range "
            f"{specifier}. Either support it or stop measuring it"
        ), ""

    covered = ", ".join(pinned[key] for key in sorted(pinned))
    return None, (
        f"requires-python {specifier} claims {len(claimed)} minor(s), each measured on "
        f"exactly one pinned interpreter ({covered})"
    )


def wheel_stages(text: str) -> list[tuple[str, str | None]]:
    """`(base image, stage name)` for every stage in one Dockerfile that installs OUR wheel.

    A forward pass over the file rather than a regex over the whole text: the install
    command must be attributed to the stage it is IN, and the two `FROM` lines in
    `Dockerfile.loadgen` are two different interpreters. Attributing an install to the
    wrong stage would check the builder's Python and pass while the runtime's is wrong —
    which is the defect, inverted.
    """
    found: list[tuple[str, str | None]] = []
    base: str | None = None
    stage: str | None = None
    claimed = False
    for line in text.splitlines():
        opening = FROM_LINE.match(line.strip())
        if opening is not None:
            base, stage, claimed = opening.group(1), opening.group(2), False
            continue
        if base is None or claimed:
            continue
        if INSTALLS_SDK.search(line):
            found.append((base, stage))
            claimed = True
    return found


def check_images(dockerfiles: dict[str, str], pinned: dict[tuple[int, int], str]) -> str | None:
    """The third fact: a stage that installs the wheel runs a PINNED interpreter.

    `dockerfiles` is `{path: text}` so `--selftest` can feed it files that do not exist;
    a gate whose only input is the real tree is one nobody proves is alive.
    """
    allowed = set(pinned.values())
    for path in sorted(dockerfiles):
        for base, stage in wheel_stages(dockerfiles[path]):
            where = f"{path} stage {stage!r}" if stage else path
            match = PYTHON_BASE.match(base)
            if match is None:
                return (
                    f"{where} installs the MCP-RE wheel on base image {base!r}, which names "
                    f"no Python version this gate can read. The interpreter that runs the "
                    f"shipped wheel is part of the support claim and must be stated"
                )
            version = match.group(1)
            if version not in allowed:
                inside = tuple(int(part) for part in version.split(".") if part.isdigit())
                hint = (
                    "it is not an exact major.minor.patch, so what it resolves to is a "
                    "property of the day it is built"
                    if len(inside) != 3
                    else "that interpreter is not one the battery is measured on"
                )
                return (
                    f"{where} installs the MCP-RE wheel on python:{version}, and "
                    f"[python].interpreters pins {', '.join(sorted(allowed))} — {hint}. "
                    f"A deploy image outside the supported range cannot install the wheel "
                    f"at all, and it fails at `docker build` inside a fleet proof rather "
                    f"than where the support decision was taken"
                )
    return None


#: The Bazel wheel target. Its metadata restates pyproject.toml's, because py_wheel reads no
#: pyproject — so the two are one fact written twice, and this is what keeps them one.
WHEEL_BUILD = REPO_ROOT / "sdk" / "python" / "BUILD.bazel"


def _wheel_kwargs(build_text: str) -> dict | None:
    """The literal keyword arguments of the `py_wheel(...)` call in a BUILD file."""
    import ast

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


#: The tooling interpreter, for the tools that read a file rather than the lock.
TOOLING_PIN = ".python-version"
MODULE_BAZEL = REPO_ROOT / "MODULE.bazel"

#: The `python.toolchain(...)` call in MODULE.bazel and the version it registers.
BAZEL_TOOLCHAIN = re.compile(r"^python\.toolchain\((.*?)^\)", re.S | re.M)
BAZEL_VERSION = re.compile(r'python_version\s*=\s*"([^"]+)"')

SETUP_PYTHON = "actions/setup-python@"

#: `python` or `python3` as a word of its own: not `sdk/python`, not `--python`.
PYTHON_WORD = re.compile(r"(?<![\w./-])python3?(?![\w.-])")


def tool_runs_python(path: str, root: Path) -> bool:
    """Whether the repository file a command runs is Python, or a shell script that runs it."""
    target = root / path
    if path.endswith(".py"):
        return True
    if not target.is_file():
        return False
    text = target.read_text(encoding="utf-8", errors="replace")
    first = text.split("\n", 1)[0]
    if first.startswith("#!"):
        if "python" in first:
            return True
        if not re.search(r"\b(ba|z)?sh\b", first):
            return False
    return any(
        PYTHON_WORD.search(line.split("#", 1)[0]) for line in text.splitlines()[1:]
    )


def step_runs_python(step: Step, root: Path) -> bool:
    for command in step.commands():
        if PYTHON_WORD.search(command.executed):
            return True
        for invocation in command.invocations():
            if invocation.program.startswith(("scripts/", "tools/")) and tool_runs_python(
                invocation.program, root
            ):
                return True
    return False


def setup_reads_pin(step: Step) -> bool:
    """The step reads the pin file, at the root of the repository or of a checkout `path:`."""
    named = step.with_.get("python-version-file", "")
    return (named == TOOLING_PIN or named.endswith("/" + TOOLING_PIN)) and "python-version" not in step.with_


def check_job(path: str, job: Job, root: Path) -> str | None:
    """A job that runs Python sets up the pinned interpreter, from the pin file, first."""
    set_up = False
    for step in job.steps:
        if step.uses and step.uses.startswith(SETUP_PYTHON):
            if not setup_reads_pin(step):
                return (
                    f"{path} job {job.key!r} line {step.line}: setup-python names its version "
                    f"{step.with_!r} instead of reading `python-version-file: {TOOLING_PIN}`, "
                    f"so a pin bump would leave this job behind"
                )
            set_up = True
        elif not set_up and step_runs_python(step, root):
            return (
                f"{path} job {job.key!r} line {step.line} runs Python before any "
                f"`{SETUP_PYTHON}` step reading {TOOLING_PIN}, so it runs the runner "
                f"image's system interpreter, not the pinned one"
            )
    return None


def check_tooling(
    tooling: str | None, module_text: str, flows: list[Workflow], pinned: dict, root: Path
) -> str | None:
    """The fifth fact: the repository's tooling runs one pinned interpreter."""
    allowed = sorted(pinned.values())
    if tooling is None:
        return f"{TOOLING_PIN} is missing, so no tool that reads it runs a pinned interpreter"
    if tooling not in allowed:
        return f"{TOOLING_PIN} names {tooling!r}, and [python].interpreters pins {', '.join(allowed)}"
    block = BAZEL_TOOLCHAIN.search(module_text)
    bazel = BAZEL_VERSION.search(block.group(1)) if block else None
    if bazel is None:
        return "MODULE.bazel registers no python.toolchain version this gate can read"
    if bazel.group(1) != tooling:
        return (
            f"MODULE.bazel registers rules_python {bazel.group(1)!r} and {TOOLING_PIN} names "
            f"{tooling!r}: every Bazel py_test runs an interpreter the tooling does not"
        )
    if not flows:
        return "no workflow was read — checking nothing is not a pass"
    for flow in flows:
        for job in flow.jobs.values():
            refusal = check_job(flow.path, job, root)
            if refusal is not None:
                return refusal
    return None


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


def selftest() -> int:
    failures = 0
    for name, tooling, module_text, flows, must_refuse in TOOLING_SELFTEST_CASES:
        refused = check_tooling(tooling, module_text, flows, IMAGE_SELFTEST_PIN, REPO_ROOT) is not None
        if refused != must_refuse:
            verb = "was accepted" if must_refuse else "was refused"
            print(f"  SELFTEST FAIL: {name} {verb}", file=sys.stderr)
            failures += 1
        else:
            print(f"  ok   {name}: {'refused' if refused else 'accepted'}")
    for name, files, must_refuse in IMAGE_SELFTEST_CASES:
        refused = check_images(files, IMAGE_SELFTEST_PIN) is not None
        if refused != must_refuse:
            verb = "was accepted" if must_refuse else "was refused"
            print(f"  SELFTEST FAIL: {name} {verb}", file=sys.stderr)
            failures += 1
        else:
            print(f"  ok   {name}: {'refused' if refused else 'accepted'}")
    for name, specifier, entry, must_refuse in SELFTEST_CASES:
        refusal, _ = check(specifier, entry)
        refused = refusal is not None
        if refused != must_refuse:
            verb = "was accepted" if must_refuse else "was refused"
            print(f"  SELFTEST FAIL: {name} {verb}", file=sys.stderr)
            failures += 1
        else:
            print(f"  ok   {name}: {'refused' if refused else 'accepted'}")
    for name, text, must_refuse in WHEEL_SELFTEST_CASES:
        refused = check_wheel_metadata(text, WHEEL_SELFTEST_PROJECT) is not None
        if refused != must_refuse:
            verb = "was accepted" if must_refuse else "was refused"
            print(f"  SELFTEST FAIL: {name} {verb}", file=sys.stderr)
            failures += 1
        else:
            print(f"  ok   {name}: {'refused' if refused else 'accepted'}")
    if failures:
        print(f"python-runtime gate: SELFTEST FAIL — {failures} case(s)", file=sys.stderr)
        return 1
    total = (len(SELFTEST_CASES) + len(IMAGE_SELFTEST_CASES) + len(WHEEL_SELFTEST_CASES)
             + len(TOOLING_SELFTEST_CASES))
    print(f"python-runtime gate: SELFTEST OK — {total} case(s)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    project = tomllib.load(PYPROJECT.open("rb"))["project"]
    entry = _toolchains.load().get(ECOSYSTEM)
    refusal, summary = check(project.get("requires-python"), entry)
    if refusal is not None:
        return fail(refusal)

    # Only reached once the claim and the pin agree, so `pinned` is the set `check` accepted.
    pinned, _ = _toolchains.interpreters(entry, ECOSYSTEM)
    dockerfiles = {
        path.relative_to(REPO_ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(DOCKER_DIR.glob("Dockerfile*"))
        if path.is_file()
    }
    if not dockerfiles:
        return fail(
            f"no Dockerfile under {DOCKER_DIR.relative_to(REPO_ROOT)} — the image half of "
            f"this gate would measure nothing, which is not the same as finding nothing"
        )
    image_refusal = check_images(dockerfiles, pinned)
    if image_refusal is not None:
        return fail(image_refusal)
    wheel_refusal = check_wheel_metadata(WHEEL_BUILD.read_text(encoding="utf-8"), project)
    if wheel_refusal is not None:
        return fail(wheel_refusal)
    pin_file = REPO_ROOT / TOOLING_PIN
    tooling = pin_file.read_text(encoding="utf-8").strip() if pin_file.is_file() else None
    flows = workflows(REPO_ROOT)
    tooling_refusal = check_tooling(
        tooling, MODULE_BAZEL.read_text(encoding="utf-8"), flows, pinned, REPO_ROOT
    )
    if tooling_refusal is not None:
        return fail(tooling_refusal)

    print(
        f"python-runtime gate: OK — {summary}; {len(dockerfiles)} deploy Dockerfile(s) "
        f"examined, every stage installing the MCP-RE wheel on a pinned interpreter; the "
        f"Bazel wheel's metadata equals pyproject.toml's; {TOOLING_PIN}, the Bazel toolchain "
        f"and every Python-running job of {len(flows)} workflow(s) name {tooling}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
