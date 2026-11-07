# SPDX-License-Identifier: Apache-2.0
"""The YAML subset the workflows use, read into `Scalar`, `Mapping` and `Sequence` nodes.

Block mappings and sequences, `|`/`>` block scalars, flow sequences, quoted and plain
scalars, and comments. Anything outside that subset raises `WorkflowSyntaxError` rather than
being read wrongly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from _workflow.comments import strip_comment


class WorkflowSyntaxError(ValueError):
    """The workflow uses YAML this reader does not read. Never read as an empty workflow."""


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
    return strip_comment(text, " \t[,:", " \t")


_QUOTED = re.compile(r"""(['"]).*\1""", re.DOTALL)


def _unquote(text: str) -> str:
    text = text.strip()
    return text[1:-1] if _QUOTED.fullmatch(text) else text


def _flow_sequence(body: str, line: int) -> Sequence:
    if not body.endswith("]") or "[" in body[1:]:
        raise WorkflowSyntaxError(f"line {line}: a nested or unterminated flow sequence")
    inner = body[1:-1].strip()
    return Sequence(line, [Scalar(_unquote(v), line) for v in inner.split(",")] if inner else [])


def _flow_mapping(body: str, line: int) -> Mapping:
    if body.replace(" ", "") != "{}":
        raise WorkflowSyntaxError(f"line {line}: a flow mapping with content")
    return Mapping(line)


def _flow(text: str, line: int) -> Sequence | Mapping | Scalar:
    """A flow sequence `[a, b]`; an empty flow mapping `{}`; otherwise a plain scalar."""
    body = _strip_comment(text)
    if body.startswith("["):
        return _flow_sequence(body, line)
    if body.startswith("{"):
        return _flow_mapping(body, line)
    if body.startswith(("&", "*", "<<")):
        raise WorkflowSyntaxError(f"line {line}: an anchor, alias or merge key")
    return Scalar(_unquote(body), line)


def _fold(content: list[tuple[int, str]]) -> str:
    """The value of a `>` block scalar: lines joined by a space, blank lines kept as breaks."""
    folded: list[str] = []
    for _n, text in content:
        if not text:
            folded.append("\n")
        elif folded and not folded[-1].endswith("\n"):
            folded[-1] += " " + text
        else:
            folded.append(text)
    return "".join(part if part.endswith("\n") else part + "\n" for part in folded)


def _is_dash(text: str) -> bool:
    """Is `text` (a line, indentation removed) a sequence entry?"""
    return text.startswith("-") and text[1:2] in ("", " ")


def _block_text(raw: str, block_indent: int | None) -> str:
    """One line of a block scalar with the block's indentation removed; a blank line is empty."""
    return raw[block_indent:] if block_indent and raw.strip() else ""


def _trim_blank(content: list[tuple[int, str]]) -> list[tuple[int, str]]:
    while content and not content[-1][1]:
        content.pop()
    return content


def _opens_mapping(rest: str) -> bool:
    """Does the text after a `-` start a `key: value` entry of a mapping?"""
    if not rest or rest[0] in "'\"[{":
        return False
    return _KEY.match(rest) is not None


def _opens_nested(text: str, at: int, indent: int) -> bool:
    """Is the line `text` at column `at` the nested value of a key sitting at `indent`?"""
    if at > indent:
        return True
    return at == indent and text.lstrip().startswith("- ")


def _check_key(node: Mapping, key: str, line: int) -> None:
    if key == "<<":
        raise WorkflowSyntaxError(f"line {line}: a merge key")
    if key in node.items:
        raise WorkflowSyntaxError(f"line {line}: key {key!r} repeats the one at line {node.key_lines[key]}")


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

    def _indent_at(self, i: int) -> int:
        return self._indent(self.lines[i])

    def trailing(self, end: int) -> int | None:
        """The line number of content left over after the parse ended at `end`, if any."""
        rest = self._next(end)
        return rest + 1 if rest < len(self.lines) else None

    def node(self, i: int, indent: int) -> tuple[object | None, int]:
        i = self._next(i)
        if i >= len(self.lines) or self._indent_at(i) < indent:
            return None, i
        at = self._indent_at(i)
        if _is_dash(self.lines[i].lstrip()):
            return self.sequence(i, at)
        return self.mapping(i, at)

    def _block_content(self, i: int, indent: int) -> tuple[list[tuple[int, str]], int]:
        """The lines of a block scalar whose parent sits at `indent`, with trailing blanks cut."""
        content: list[tuple[int, str]] = []
        block_indent: int | None = None
        while i < len(self.lines):
            raw = self.lines[i]
            if raw.strip() and self._indent(raw) <= indent:
                break
            if raw.strip() and block_indent is None:
                block_indent = self._indent(raw)
            content.append((i + 1, _block_text(raw, block_indent)))
            i += 1
        return _trim_blank(content), i

    def block_scalar(self, i: int, indent: int, style: str, line: int) -> tuple[Scalar, int]:
        content, i = self._block_content(i, indent)
        if style.startswith(">"):
            value = _fold(content)
        else:
            value = "".join(text + "\n" for _n, text in content)
        return Scalar(value, line, tuple(content), style[0]), i

    def value(self, rest: str, i: int, indent: int, line: int) -> tuple[object | None, int]:
        """The value of a key or sequence entry whose text after the indicator is `rest`."""
        rest = rest.strip()
        header = _strip_comment(rest)
        if _BLOCK.match(header):
            return self.block_scalar(i, indent, header, line)
        if rest[:1] in ("|", ">"):
            raise WorkflowSyntaxError(f"line {line}: a block scalar header this reader does not read: {rest!r}")
        if not rest or rest.startswith("#"):
            return self._nested_value(i, indent)
        return self._inline_value(rest, i, indent, line)

    def _nested_value(self, i: int, indent: int) -> tuple[object | None, int]:
        nxt = self._next(i)
        if nxt < len(self.lines):
            at = self._indent_at(nxt)
            if _opens_nested(self.lines[nxt], at, indent):
                return self.node(nxt, at)
        return None, i

    def _continues_plain(self, nxt: int, indent: int) -> bool:
        """Does the line at `nxt` continue a plain scalar whose parent sits at `indent`?"""
        if nxt >= len(self.lines) or self._indent_at(nxt) <= indent:
            return False
        text = self.lines[nxt]
        return not (_KEY.match(text.strip()) or text.lstrip().startswith("- "))

    def _inline_value(self, rest: str, i: int, indent: int, line: int) -> tuple[object, int]:
        scalar = _flow(rest, line)
        # A plain scalar may continue on more-indented lines.
        while isinstance(scalar, Scalar) and rest[0] not in "'\"":
            nxt = self._next(i)
            if not self._continues_plain(nxt, indent):
                break
            scalar.value += " " + _strip_comment(self.lines[nxt].strip())
            i = nxt + 1
        return scalar, i

    def _at_key(self, i: int, indent: int) -> bool:
        return i < len(self.lines) and self._indent_at(i) == indent and not self.lines[i].strip().startswith("- ")

    def _read_key(self, node: Mapping, i: int, indent: int) -> int:
        """Read the `key: value` entry at line `i` into `node`; the index after it."""
        stripped = self.lines[i].strip()
        match = _KEY.match(stripped)
        if not match:
            raise WorkflowSyntaxError(f"line {i + 1}: expected `key:` at indent {indent}: {stripped!r}")
        key = _unquote(match.group("key"))
        _check_key(node, key, i + 1)
        value, nxt = self.value(match.group("rest"), i + 1, indent, i + 1)
        node.items[key] = value
        node.key_lines[key] = i + 1
        return nxt

    def mapping(self, i: int, indent: int) -> tuple[Mapping, int]:
        node = Mapping(i + 1)
        i = self._next(i)
        while self._at_key(i, indent):
            i = self._next(self._read_key(node, i, indent))
        return node, i

    def _at_entry(self, i: int, indent: int) -> bool:
        if i >= len(self.lines) or self._indent_at(i) != indent:
            return False
        stripped = self.lines[i].strip()
        return stripped == "-" or stripped.startswith("- ")

    def _read_entry(self, i: int, indent: int) -> tuple[object | None, int]:
        stripped = self.lines[i].strip()
        rest = stripped[1:].lstrip()
        column = indent + (len(stripped) - len(rest))
        if _opens_mapping(rest):
            # `- key: value` opens a mapping whose keys sit at the entry's column.
            self.lines[i] = " " * column + rest
            return self.mapping(i, column)
        return self.value(rest, i + 1, indent, i + 1)

    def sequence(self, i: int, indent: int) -> tuple[Sequence, int]:
        node = Sequence(i + 1)
        i = self._next(i)
        while self._at_entry(i, indent):
            value, i = self._read_entry(i, indent)
            node.items.append(value)
            i = self._next(i)
        return node, i


def parse_yaml(text: str) -> Mapping:
    parser = _Parser(text)
    parsed, end = parser.node(0, 0)
    leftover = parser.trailing(end)
    if leftover is not None:
        raise WorkflowSyntaxError(f"line {leftover}: content the reader could not place")
    if parsed is None:
        return Mapping(1)
    if not isinstance(parsed, Mapping):
        raise WorkflowSyntaxError("a workflow is a mapping at the top level")
    return parsed
