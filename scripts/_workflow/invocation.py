# SPDX-License-Identifier: Apache-2.0
"""What one simple shell command runs: the program, or the script an interpreter is handed."""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Programs that write their operands rather than run them.
PRINTERS = {"echo", "printf"}
#: Words that precede the program a segment runs, without being it.
_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "exec", "time", "env", "nohup", "{", "("}
#: Programs that run another program given as their operand.
_WRAPPERS = ("timeout", "sudo", "nice")
#: Programs that run their first operand: a path handed to one is run, and needs no execute bit.
INTERPRETERS = {"python3", "python", "bash", "sh", "zsh", "source", ".", "node"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_DURATION = re.compile(r"\d+[smhd]?")


@dataclass(frozen=True)
class Invocation:
    #: The program, with a leading `./` removed.
    program: str
    #: The interpreter that runs `program`, or `None` when `program` runs as itself.
    interpreter: str | None
    #: The words after `program`.
    args: tuple[str, ...]


def _program(word: str) -> str:
    word = word.strip("\"'")
    return word[2:] if word.startswith("./") else word


def _is_wrapper_operand(word: str) -> bool:
    return word.startswith("-") or word.isdigit() or _DURATION.fullmatch(word) is not None


def _skip_leaders(words: list[str]) -> None:
    """Drop the assignments and keywords that precede the program."""
    while words and (_ASSIGNMENT.match(words[0]) or words[0] in _KEYWORDS):
        words.pop(0)


def _skip_wrappers(words: list[str]) -> None:
    """Drop `timeout`, `sudo` and `nice` with their own options."""
    while words and words[0] in _WRAPPERS:
        words.pop(0)
        while words and _is_wrapper_operand(words[0]):
            words.pop(0)


def _command_words(segment: str) -> list[str]:
    """The words of `segment` from the program on: assignments, keywords and wrappers gone."""
    words = [word for word in segment.split() if word.strip("\"'")]
    _skip_leaders(words)
    _skip_wrappers(words)
    return words


def _interpreted(interpreter: str, operands: list[str]) -> Invocation | None:
    """The script `interpreter` is handed, once its own flags are past."""
    while operands and operands[0].startswith("-"):
        operands = operands[1:]
    if not operands:
        return None
    return Invocation(_program(operands[0]), interpreter, tuple(operands[1:]))


def invocation(segment: str) -> Invocation | None:
    words = _command_words(segment)
    if not words:
        return None
    head = words[0].strip("\"'")
    if head in INTERPRETERS:
        return _interpreted(head, words[1:])
    return Invocation(_program(head), None, tuple(words[1:]))


def prints(segment: str) -> bool:
    """Does `segment` only write its operands (`echo`, `printf`)?"""
    inv = invocation(segment)
    return inv is not None and inv.program in PRINTERS
