# SPDX-License-Identifier: Apache-2.0
"""The logical commands of a shell text, and what each one runs or only prints."""

from __future__ import annotations

import re
from dataclasses import dataclass

from _workflow.comments import strip_comment
from _workflow.invocation import PRINTERS, Invocation, invocation, prints
from _workflow.segments import segments

_BACKTICK_COMMENT = re.compile(r"`\s*#[^`]*`")


@dataclass(frozen=True)
class Command:
    line: int
    text: str

    @property
    def prints(self) -> bool:
        """A usage line: every segment prints, so the command names others without running them."""
        parts = self.segments()
        return bool(parts) and all(prints(part) for part in parts)

    def executed_segments(self) -> list[str]:
        """The segments this command runs, without those that only print.

        A segment, not the whole command: `echo "$T" | docker login …` prints and runs
        `docker login`, and a reader that dropped the command for its first word would hide
        the login. A predicate about one invocation — its flags, its labels — reads the
        segment that holds it, never a neighbour's.
        """
        return [part for part in self.segments() if not prints(part)]

    @property
    def executed(self) -> str:
        """`executed_segments()` as one text, for a question about the whole command."""
        return " ; ".join(self.executed_segments())

    def segments(self) -> list[str]:
        return segments(self.text)

    @property
    def code(self) -> str:
        """The command without the backtick comments a long chain carries between links."""
        return _BACKTICK_COMMENT.sub(" ", self.text)

    def invocations(self) -> list[Invocation]:
        """What each segment of this command runs, without the segments that only print."""
        found = (invocation(part) for part in self.segments())
        return [inv for inv in found if inv is not None and inv.program not in PRINTERS]


def _without_comment(line: str) -> str:
    """A shell line without its trailing comment: `#` starting a word, outside quotes."""
    return strip_comment(line, None, " \t;&|(")


def _join(parts: list[str]) -> str:
    return " ".join(part for part in parts if part)


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
        out.append(Command(start, _join(buffer)))
        buffer = []
    if buffer:
        out.append(Command(start, _join(buffer)))
    return out


#: A repository path named in a command, extension or not.
_NAMED_PATH = re.compile(r"(?:^|[\s`\"'./(=])((?:scripts|tools)/[A-Za-z0-9_./-]+)")


def named_paths(text: str) -> set[str]:
    """Every `scripts/` or `tools/` path `text` names, in any position."""
    return {path.rstrip(".") for path in _NAMED_PATH.findall(text)}
