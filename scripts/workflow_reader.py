#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Workflow reader — the one reader of `.github/workflows/*.yml`, and of the shell commands
those workflows and the repository's scripts run.

THE FAILURE CLASS: a gate that reads a workflow with a private line regex answers a question
about the regex, not the workflow. Ten gates did, and each rediscovered the same quirks
separately or not at all. One parser ended a `paths:` list at a comment. One counted a
script named in a comment as a job that runs it. One read every two-space key under `on:`
as a job. One skipped a command whose line ended in `\\`. Each gate's own property was
right, and each gate measured something narrower or wider than it claimed.

So this module owns the syntax, and a gate states only its own property:

  * `read(path)` / `parse(text)` give a `Workflow`. It has `triggers`, each with its path
    filter or none, and `jobs`, each with the check name GitHub reports and its steps.
  * `shell_commands(text)` gives the logical commands of a `run:` body or a shell script.
    Comment lines and trailing comments are dropped and `\\` continuations are joined.
    A segment that prints (`echo`, `printf`) names a command without running it:
    `Command.executed_segments()` is the command without its printing segments, and
    `Command.prints` marks a command that only prints. `echo "$T" | docker login …` still runs `docker`.
  * `Command.invocations()` gives what each non-printing segment of a command runs: the
    program, or the script an interpreter is handed. `named_paths` gives every repository path a command
    names in any position.
  * `glob_matches` is GitHub's path-filter matching.

It is stdlib only. The YAML read is the subset these workflows use: block mappings and
sequences, `|`/`>` block scalars, flow sequences, quoted and plain scalars, and comments.
Anything outside that subset (an anchor, an alias, a merge key, a flow mapping with
content, a block scalar header with an indentation indicator, a repeated key) raises `WorkflowSyntaxError` rather than being read wrongly. A reader that guesses
is the defect this module exists to remove.

Run:  python3 scripts/workflow_reader.py --selftest
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

WORKFLOWS = Path(".github") / "workflows"


class WorkflowSyntaxError(ValueError):
    """The workflow uses YAML this reader does not read. Never read as an empty workflow."""


# ---------------------------------------------------------------------------- YAML subset


@dataclass
class Scalar:
    value: str
    line: int
    #: For a block scalar, every content line with its own line number, before folding.
    lines: tuple[tuple[int, str], ...] = ()
    #: `|` for a literal block scalar, `>` for a folded one, empty for any other scalar.
    style: str = ""


@dataclass
class Mapping:
    line: int
    items: dict[str, object] = field(default_factory=dict)
    key_lines: dict[str, int] = field(default_factory=dict)

    def get(self, key: str):
        return self.items.get(key)


@dataclass
class Sequence:
    line: int
    items: list[object] = field(default_factory=list)


_KEY = re.compile(r"""^(?P<key>"[^"]*"|'[^']*'|[^\s#'"\-\[{][^:#]*?|-[^\s:][^:#]*?)\s*:(?:\s+|$)(?P<rest>.*)$""")
_BLOCK = re.compile(r"^[|>][+-]?$")


def _strip_comment(text: str) -> str:
    """`text` without a trailing `# comment` outside quotes."""
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"" and (i == 0 or text[i - 1] in " \t[,:"):
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.rstrip()


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _flow(text: str, line: int) -> Sequence | Mapping | Scalar:
    """A flow sequence `[a, b]`; an empty flow mapping `{}`; otherwise a plain scalar."""
    body = _strip_comment(text)
    if body.startswith("["):
        if not body.endswith("]") or "[" in body[1:]:
            raise WorkflowSyntaxError(f"line {line}: a nested or unterminated flow sequence")
        inner = body[1:-1].strip()
        return Sequence(line, [Scalar(_unquote(v), line) for v in inner.split(",")] if inner else [])
    if body.startswith("{"):
        if body.replace(" ", "") != "{}":
            raise WorkflowSyntaxError(f"line {line}: a flow mapping with content")
        return Mapping(line)
    if body.startswith(("&", "*")) or body.startswith("<<"):
        raise WorkflowSyntaxError(f"line {line}: an anchor, alias or merge key")
    return Scalar(_unquote(body), line)


class _Parser:
    def __init__(self, text: str) -> None:
        self.lines = text.splitlines()

    @staticmethod
    def _indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    def _next(self, i: int) -> int:
        """The index of the next line that carries YAML content."""
        while i < len(self.lines):
            stripped = self.lines[i].strip()
            if stripped and not stripped.startswith("#"):
                return i
            i += 1
        return i

    def node(self, i: int, indent: int) -> tuple[object | None, int]:
        i = self._next(i)
        if i >= len(self.lines) or self._indent(self.lines[i]) < indent:
            return None, i
        at = self._indent(self.lines[i])
        if self.lines[i].lstrip().startswith("-") and self.lines[i].lstrip()[1:2] in ("", " "):
            return self.sequence(i, at)
        return self.mapping(i, at)

    def block_scalar(self, i: int, indent: int, style: str, line: int) -> tuple[Scalar, int]:
        content: list[tuple[int, str]] = []
        block_indent: int | None = None
        while i < len(self.lines):
            raw = self.lines[i]
            if raw.strip() and self._indent(raw) <= indent:
                break
            if raw.strip() and block_indent is None:
                block_indent = self._indent(raw)
            content.append((i + 1, raw[block_indent:] if block_indent and raw.strip() else ""))
            i += 1
        while content and not content[-1][1]:
            content.pop()
        if style.startswith(">"):
            folded: list[str] = []
            for _n, text in content:
                if not text:
                    folded.append("\n")
                elif folded and not folded[-1].endswith("\n"):
                    folded[-1] += " " + text
                else:
                    folded.append(text)
            value = "".join(part if part.endswith("\n") else part + "\n" for part in folded)
        else:
            value = "".join(text + "\n" for _n, text in content)
        return Scalar(value, line, tuple(content), style[0]), i

    def value(self, rest: str, i: int, indent: int, line: int) -> tuple[object | None, int]:
        """The value of a key or sequence entry whose text after the indicator is `rest`."""
        rest = rest.strip()
        if _BLOCK.match(_strip_comment(rest)):
            return self.block_scalar(i, indent, _strip_comment(rest), line)
        if rest[:1] in ("|", ">"):
            raise WorkflowSyntaxError(f"line {line}: a block scalar header this reader does not read: {rest!r}")
        if not rest or rest.startswith("#"):
            nxt = self._next(i)
            if nxt < len(self.lines):
                at = self._indent(self.lines[nxt])
                if at > indent or (at == indent and self.lines[nxt].lstrip().startswith("- ")):
                    return self.node(nxt, at)
            return None, i
        scalar = _flow(rest, line)
        # A plain scalar may continue on more-indented lines.
        while isinstance(scalar, Scalar) and rest[0] not in "'\"":
            nxt = self._next(i)
            if nxt >= len(self.lines) or self._indent(self.lines[nxt]) <= indent:
                break
            if _KEY.match(self.lines[nxt].strip()) or self.lines[nxt].lstrip().startswith("- "):
                break
            scalar.value += " " + _strip_comment(self.lines[nxt].strip())
            i = nxt + 1
        return scalar, i

    def mapping(self, i: int, indent: int) -> tuple[Mapping, int]:
        node = Mapping(i + 1)
        while True:
            i = self._next(i)
            if i >= len(self.lines) or self._indent(self.lines[i]) != indent:
                return node, i
            stripped = self.lines[i].strip()
            if stripped.startswith("- "):
                return node, i
            match = _KEY.match(stripped)
            if not match:
                raise WorkflowSyntaxError(f"line {i + 1}: expected `key:` at indent {indent}: {stripped!r}")
            key = _unquote(match.group("key"))
            if key == "<<":
                raise WorkflowSyntaxError(f"line {i + 1}: a merge key")
            if key in node.items:
                raise WorkflowSyntaxError(f"line {i + 1}: key {key!r} repeats the one at line {node.key_lines[key]}")
            value, nxt = self.value(match.group("rest"), i + 1, indent, i + 1)
            node.items[key] = value
            node.key_lines[key] = i + 1
            i = nxt

    def sequence(self, i: int, indent: int) -> tuple[Sequence, int]:
        node = Sequence(i + 1)
        while True:
            i = self._next(i)
            if i >= len(self.lines) or self._indent(self.lines[i]) != indent:
                return node, i
            stripped = self.lines[i].strip()
            if not (stripped == "-" or stripped.startswith("- ")):
                return node, i
            rest = stripped[1:].lstrip()
            column = indent + (len(stripped) - len(rest))
            if rest and rest[0] not in "'\"[{" and _KEY.match(rest):
                # `- key: value` opens a mapping whose keys sit at the entry's column.
                self.lines[i] = " " * column + rest
                value, i = self.mapping(i, column)
            else:
                value, i = self.value(rest, i + 1, indent, i + 1)
            node.items.append(value)


def parse_yaml(text: str) -> Mapping:
    parsed, end = _Parser(text).node(0, 0)
    parser_lines = text.splitlines()
    rest = _Parser(text)._next(end)
    if rest < len(parser_lines):
        raise WorkflowSyntaxError(f"line {rest + 1}: content the reader could not place")
    if parsed is None:
        return Mapping(1)
    if not isinstance(parsed, Mapping):
        raise WorkflowSyntaxError("a workflow is a mapping at the top level")
    return parsed


def _strings(node: object) -> tuple[str, ...] | None:
    if node is None:
        return None
    if isinstance(node, Scalar):
        return (node.value,)
    if isinstance(node, Sequence):
        return tuple(item.value for item in node.items if isinstance(item, Scalar))
    raise WorkflowSyntaxError("expected a scalar or a sequence of scalars")


# ------------------------------------------------------------------------------ the model


@dataclass(frozen=True)
class Trigger:
    name: str
    #: `None` when the trigger has no `paths:` filter: then every change starts it.
    paths: tuple[str, ...] | None
    paths_ignore: tuple[str, ...] | None

    @property
    def filtered(self) -> bool:
        """Does this trigger start on only some changes?"""
        return self.paths is not None or self.paths_ignore is not None


@dataclass(frozen=True)
class Command:
    line: int
    text: str

    @property
    def prints(self) -> bool:
        """A usage line: every segment prints, so the command names others without running them."""
        segments = self.segments()
        return bool(segments) and all(_prints(segment) for segment in segments)

    def executed_segments(self) -> list[str]:
        """The segments this command runs, without those that only print.

        A segment, not the whole command: `echo "$T" | docker login …` prints and runs
        `docker login`, and a reader that dropped the command for its first word would hide
        the login. A predicate about one invocation — its flags, its labels — reads the
        segment that holds it, never a neighbour's.
        """
        return [segment for segment in self.segments() if not _prints(segment)]

    @property
    def executed(self) -> str:
        """`executed_segments()` as one text, for a question about the whole command."""
        return " ; ".join(self.executed_segments())

    def segments(self) -> list[str]:
        return _segments(self.text)

    @property
    def code(self) -> str:
        """The command without the backtick comments a long chain carries between links."""
        return _BACKTICK_COMMENT.sub(" ", self.text)

    def invocations(self) -> list[Invocation]:
        """What each segment of this command runs, without the segments that only print."""
        return [
            inv
            for seg in self.segments()
            if (inv := _invocation(seg)) is not None and inv.program not in _PRINTERS
        ]


@dataclass(frozen=True)
class Step:
    line: int
    name: str | None
    uses: str | None
    run: Scalar | None
    with_: dict[str, str]

    def commands(self) -> list[Command]:
        if self.run is None or (self.run.style and not self.run.lines):
            return []
        if self.run.style == "|":
            return shell_commands("\n".join(text for _n, text in self.run.lines), self.run.lines[0][0])
        if self.run.style == ">":
            return shell_commands(self.run.value, self.run.lines[0][0])
        return shell_commands(self.run.value, self.run.line)


@dataclass(frozen=True)
class Job:
    key: str
    #: The check name GitHub reports: the job's `name:`, or its key when it has none.
    name: str
    line: int
    runs_on: tuple[str, ...]
    steps: tuple[Step, ...]

    def commands(self) -> list[Command]:
        return [command for step in self.steps for command in step.commands()]


@dataclass(frozen=True)
class Workflow:
    path: str
    triggers: dict[str, Trigger]
    jobs: dict[str, Job]

    def commands(self) -> list[Command]:
        return [command for job in self.jobs.values() for command in job.commands()]


def _triggers(node: object) -> dict[str, Trigger]:
    if node is None:
        return {}
    if isinstance(node, Scalar):
        return {node.value: Trigger(node.value, None, None)}
    if isinstance(node, Sequence):
        return {item.value: Trigger(item.value, None, None) for item in node.items if isinstance(item, Scalar)}
    if not isinstance(node, Mapping):
        raise WorkflowSyntaxError("`on:` is neither a name, a list nor a mapping")
    out: dict[str, Trigger] = {}
    for name, body in node.items.items():
        if isinstance(body, Mapping):
            out[name] = Trigger(name, _strings(body.get("paths")), _strings(body.get("paths-ignore")))
        else:
            out[name] = Trigger(name, None, None)
    return out


def _step(node: object) -> Step:
    if not isinstance(node, Mapping):
        raise WorkflowSyntaxError("a step is not a mapping")
    run = node.get("run")
    if run is not None and not isinstance(run, Scalar):
        raise WorkflowSyntaxError(f"line {node.line}: `run:` is not a scalar")
    with_node = node.get("with")
    with_ = {
        key: value.value
        for key, value in (with_node.items.items() if isinstance(with_node, Mapping) else ())
        if isinstance(value, Scalar)
    }
    name, uses = node.get("name"), node.get("uses")
    return Step(
        node.line,
        name.value if isinstance(name, Scalar) else None,
        uses.value if isinstance(uses, Scalar) else None,
        run,
        with_,
    )


def _jobs(node: object) -> dict[str, Job]:
    if node is None:
        return {}
    if not isinstance(node, Mapping):
        raise WorkflowSyntaxError("`jobs:` is not a mapping")
    out: dict[str, Job] = {}
    for key, body in node.items.items():
        if not isinstance(body, Mapping):
            raise WorkflowSyntaxError(f"job `{key}` is not a mapping")
        name = body.get("name")
        steps = body.get("steps")
        out[key] = Job(
            key,
            name.value if isinstance(name, Scalar) else key,
            node.key_lines[key],
            _strings(body.get("runs-on")) or (),
            tuple(_step(s) for s in steps.items) if isinstance(steps, Sequence) else (),
        )
    return out


def parse(text: str, path: str = "<text>") -> Workflow:
    top = parse_yaml(text)
    return Workflow(path, _triggers(top.get("on")), _jobs(top.get("jobs")))


def read(path: Path) -> Workflow:
    return parse(path.read_text(encoding="utf-8"), str(path))


def workflows(root: Path) -> list[Workflow]:
    """Every workflow under `root`, in name order."""
    return [read(path) for path in sorted((root / WORKFLOWS).glob("*.yml"))]


# ---------------------------------------------------------------------------- shell commands

#: Programs that write their operands rather than run them.
_PRINTERS = {"echo", "printf"}
_BACKTICK_COMMENT = re.compile(r"`\s*#[^`]*`")


def _without_comment(line: str) -> str:
    """A shell line without its trailing comment: `#` starting a word, outside quotes."""
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t;&|("):
            return line[:i].rstrip()
    return line.rstrip()


def shell_commands(text: str, first_line: int = 1) -> list[Command]:
    """The logical commands of a shell text: comments dropped, continuations joined.

    A comment line inside a continuation ends nothing and contributes nothing, which is
    what the shell does with it too.
    """
    out: list[Command] = []
    buffer: list[str] = []
    start = first_line
    for offset, raw in enumerate(text.splitlines()):
        line = _without_comment(raw).strip()
        if not line:
            if buffer and not raw.strip():
                out.append(Command(start, " ".join(buffer)))
                buffer = []
            continue
        if not buffer:
            start = first_line + offset
        if line.endswith("\\"):
            buffer.append(line[:-1].rstrip())
            continue
        buffer.append(line)
        out.append(Command(start, " ".join(part for part in buffer if part)))
        buffer = []
    if buffer:
        out.append(Command(start, " ".join(part for part in buffer if part)))
    return out


def _segments(text: str) -> list[str]:
    """The simple commands in `text`: split at `&&`, `||`, `;` and `|` outside quotes, with
    every command substitution — `$(...)` or a backtick pair — lifted out as commands of its
    own, because what it runs is run.

    A backtick pair whose content starts with `#` is a comment that expands to nothing,
    which is how a long `&&` chain carries prose between its links.
    """
    out: list[str] = []
    current: list[str] = []
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        if quote == "'":
            current.append(ch)
            if ch == "'":
                quote = ""
            i += 1
            continue
        if text.startswith("$(", i) or ch == "`":
            close, depth, j = (")", 1, i + 2) if ch == "$" else ("`", 1, i + 1)
            start = j
            while j < len(text) and depth:
                if close == ")" and text.startswith("$(", j):
                    depth += 1
                    j += 1
                elif text[j] == close:
                    depth -= 1
                j += 1
            inner = text[start : j - 1]
            if not inner.lstrip().startswith("#"):
                out.extend(_segments(inner))
            current.append(" ")
            i = j
            continue
        if quote == '"':
            current.append(ch)
            if ch == '"':
                quote = ""
        elif ch in "'\"":
            quote = ch
            current.append(ch)
        elif text.startswith(("&&", "||"), i):
            out.append("".join(current))
            current = []
            i += 2
            continue
        elif ch in ";|":
            out.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    out.append("".join(current))
    return [segment.strip() for segment in out if segment.strip()]


#: Words that precede the program a segment runs, without being it.
_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "exec", "time", "env", "nohup", "{", "("}
#: Programs that run their first operand: a path handed to one is run, and needs no execute bit.
INTERPRETERS = {"python3", "python", "bash", "sh", "zsh", "source", ".", "node"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass(frozen=True)
class Invocation:
    #: The program, with a leading `./` removed.
    program: str
    #: The interpreter that runs `program`, or `None` when `program` runs as itself.
    interpreter: str | None
    #: The words after `program`.
    args: tuple[str, ...]


def _invocation(segment: str) -> Invocation | None:
    words = [word for word in segment.split() if word.strip("\"'")]
    while words and (_ASSIGNMENT.match(words[0]) or words[0] in _KEYWORDS):
        words.pop(0)
    while words and words[0] in ("timeout", "sudo", "nice"):
        words.pop(0)
        while words and (words[0].startswith("-") or words[0].isdigit() or re.fullmatch(r"\d+[smhd]?", words[0])):
            words.pop(0)
    if not words:
        return None
    head = words[0].strip("\"'")
    if head in INTERPRETERS:
        rest = words[1:]
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        if not rest:
            return None
        return Invocation(_program(rest[0]), head, tuple(rest[1:]))
    return Invocation(_program(head), None, tuple(words[1:]))


def _prints(segment: str) -> bool:
    inv = _invocation(segment)
    return inv is not None and inv.program in _PRINTERS


def _program(word: str) -> str:
    word = word.strip("\"'")
    return word[2:] if word.startswith("./") else word


#: A repository path named in a command, extension or not.
_NAMED_PATH = re.compile(r"(?:^|[\s`\"'./(=])((?:scripts|tools)/[A-Za-z0-9_./-]+)")


def named_paths(text: str) -> set[str]:
    """Every `scripts/` or `tools/` path `text` names, in any position."""
    return {path.rstrip(".") for path in _NAMED_PATH.findall(text)}


# ----------------------------------------------------------------------------- path filters


def glob_matches(pattern: str, path: str) -> bool:
    """GitHub's path-filter semantics: `**` crosses a separator, `*` does not, and `**/`
    also matches no directory at all, so `**/BUILD.bazel` matches the root's.

    `?`, `[...]`, a leading `!` and `+` mean something GitHub-specific that no filter in
    this repository uses; a pattern carrying one is refused rather than matched by a
    guess, because a guess here is a filter read as wider than GitHub applies it.
    """
    if any(ch in pattern for ch in "?[+") or pattern.startswith("!"):
        raise WorkflowSyntaxError(f"path filter {pattern!r} uses syntax this reader does not match")
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.fullmatch(out, path) is not None


# --------------------------------------------------------------------------------- selftest


def _case(label: str, ok: bool, got: object) -> bool:
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got {got!r}")
    return ok


def selftest() -> int:
    results: list[bool] = []

    triggers = parse(
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
    ).triggers
    results.append(_case(
        "a comment and a blank line inside a list do not end it; a trailing comment is not a pattern",
        triggers["pull_request"].paths == ("a/**", "b/c.py", "d/*"),
        triggers.get("pull_request"),
    ))
    results.append(_case(
        "a trigger with no `paths:` is unfiltered, and a key named `push:` inside a job is not a trigger",
        triggers["push"].paths is None and not triggers["push"].filtered and set(triggers)
        == {"pull_request", "push", "schedule", "workflow_dispatch"},
        triggers,
    ))
    ignored = parse("on:\n  pull_request:\n    paths-ignore:\n      - docs/**\n").triggers["pull_request"]
    results.append(_case("`paths-ignore:` filters a trigger too", ignored.filtered and ignored.paths is None, ignored))
    results.append(_case(
        "`on:` as a flow list and as a single name",
        set(parse("on: [push, pull_request]\n").triggers) == {"push", "pull_request"}
        and set(parse("on: push\n").triggers) == {"push"},
        None,
    ))

    flow = parse(
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
    a, b = flow.jobs["a"], flow.jobs["b"]
    results.append(_case(
        "jobs are only the keys under `jobs:`, the check name is `name:` or the key",
        set(flow.jobs) == {"a", "b"} and a.name == "Check A" and b.name == "b",
        flow.jobs,
    ))
    results.append(_case("runs-on as a flow list", a.runs_on == ("self-hosted", "macOS"), a.runs_on))
    empty = parse("jobs:\n  a:\n    steps:\n      - run: |\n      - run: >-\n").commands()
    results.append(_case("an empty block scalar runs nothing", empty == [], empty))
    texts = [c.text for c in a.commands()]
    results.append(_case(
        "comments are dropped, `\\` continuations are joined, a `>-` scalar folds to one line",
        texts == [
            "python3 scripts/a_gate.py --selftest",
            "bazel test //pkg:t --test_arg=m::",
            'echo "usage: scripts/b_gate.py"',
            "scripts/run_test_lane.sh bazel test --test_output=all //pkg:folded",
        ],
        texts,
    ))
    results.append(_case(
        "a usage line prints rather than runs",
        [c.prints for c in a.commands()] == [False, False, True, False],
        None,
    ))
    results.append(_case(
        "a step's `with:` is read",
        a.steps[2].with_ == {"fetch-depth": "0"},
        a.steps[2].with_,
    ))
    results.append(_case(
        "line numbers point at the command",
        [c.line for c in a.commands()] == [13, 14, 17, 19],
        [c.line for c in a.commands()],
    ))

    def ran(text: str) -> list[tuple[str, str | None]]:
        return [(i.program, i.interpreter) for c in shell_commands(text) for i in c.invocations()]

    for text, expect, label in [
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
    ]:
        got = ran(text)
        results.append(_case(f"invocations: {label}", got == expect, got))

    piped = shell_commands('echo "$T" | docker login ghcr.io -u u --password-stdin')[0]
    chained = shell_commands('echo "::group::x" && python3 scripts/x.py')[0]
    usage = shell_commands('echo "usage: scripts/x.py" | tee -a log && printf x')[0]
    results.append(_case(
        "a command that prints and runs is not a usage line; its executed code keeps what runs",
        not piped.prints and "docker login" in piped.executed and "echo" not in piped.executed
        and not chained.prints and named_paths(chained.executed) == {"scripts/x.py"},
        (piped.prints, piped.executed, chained.executed),
    ))
    results.append(_case(
        "`prints` is a command whose every segment prints, and then nothing is executed",
        shell_commands('echo a && printf b')[0].prints and shell_commands('echo a && printf b')[0].executed == ""
        and not usage.prints and named_paths(usage.executed) == set(),
        (usage.prints, usage.executed),
    ))

    noted = shell_commands("true \\\n  `# scripts/x.py explains the next link` \\\n  && python3 scripts/y.py")[0]
    results.append(_case(
        "a backtick comment is not code",
        named_paths(noted.code) == {"scripts/y.py"},
        named_paths(noted.code),
    ))
    results.append(_case(
        "named paths see an extensionless entry point and ignore prose punctuation",
        named_paths("run ./tools/verification/verify-tests and scripts/x.py.") == {"tools/verification/verify-tests", "scripts/x.py"},
        named_paths("run ./tools/verification/verify-tests and scripts/x.py."),
    ))
    results.append(_case(
        "`**` crosses a separator, `*` does not, and `**/` matches the root",
        glob_matches("a/**", "a/b/c.rs") and not glob_matches("a/*", "a/b/c.rs")
        and glob_matches("**/BUILD.bazel", "BUILD.bazel") and glob_matches("**/BUILD.bazel", "a/b/BUILD.bazel")
        and not glob_matches("**/BUILD.bazel", "a/BUILD.bazel.bak"),
        None,
    ))
    try:
        glob_matches("a/?.rs", "a/b.rs")
    except WorkflowSyntaxError:
        results.append(_case("refuses a `?` pattern rather than guessing", True, None))
    else:
        results.append(_case("refuses a `?` pattern rather than guessing", False, "matched"))
    for text, label in [
        ("x: &anchor\n  a: 1\n", "an anchor"),
        ("x: {a: 1}\n", "a flow mapping with content"),
        ("x:\n  - a\n  y: 1\n", "content the reader cannot place"),
        ("jobs:\n  a: {}\n  a: {}\n", "a repeated key"),
        ("on:\n  pull_request:\n  pull_request:\n    paths: [a]\n", "a repeated trigger"),
        ("x: |2\n    a # b\n    c\n", "a block scalar header with an indentation indicator"),
        ("x:\n  - >-1\n    a\n", "an indentation indicator in a sequence entry"),
    ]:
        try:
            parse_yaml(text)
        except WorkflowSyntaxError:
            results.append(_case(f"refuses {label}", True, None))
        else:
            results.append(_case(f"refuses {label}", False, "parsed"))

    if not all(results):
        print("workflow reader: SELFTEST FAILED")
        return 1
    print(f"workflow reader: selftest passed ({len(results)} cases)")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    root = Path(__file__).resolve().parent.parent
    read_all = workflows(root)
    if not read_all:
        print("workflow reader: FAILED — no workflow under .github/workflows")
        return 1
    commands = sum(len(w.commands()) for w in read_all)
    print(f"workflow reader: OK — {len(read_all)} workflow(s), "
          f"{sum(len(w.jobs) for w in read_all)} job(s), {commands} command(s) read")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
