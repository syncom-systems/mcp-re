# SPDX-License-Identifier: Apache-2.0
"""Reading the parsers' accepted flags and the flags documents put on command lines."""

from __future__ import annotations

import re
from pathlib import Path

from _proxy_flag_doc.config import (
    CLI_FLAG_LITERAL,
    DOC_ROOTS,
    FENCE,
    FLAG,
    LAUNCHER_FLAGS,
    SKIP_PARTS,
    SKIP_PATTERNS,
    SUPERSEDED,
    Tool,
)


def _parser_sources(repo: Path, tool: Tool) -> list[Path]:
    """Every file of `tool`'s parser that exists, in the order they are read."""
    files = [repo / rel for rel in tool.sources if (repo / rel).exists()]
    for rel in tool.source_dirs:
        files.extend(sorted((repo / rel).glob("*.rs")))
    return files


def known_flags(repo: Path, tool: Tool) -> set[str]:
    """Every `"--flag"` literal in `tool`'s parser."""
    source = "".join(p.read_text(encoding="utf-8") for p in _parser_sources(repo, tool))
    return set(CLI_FLAG_LITERAL.findall(source))


def _command_lines(block: str) -> list[str]:
    """The block's commands, with shell continuations joined."""
    return re.sub(r"\\\n\s*", " ", block).splitlines()


def documented_flags(markdown: str, launch: re.Pattern[str]) -> set[str]:
    """Every flag on a command line that launches one tool.

    Shell continuations are joined first, so a multi-line invocation is one command. Only
    the argv AFTER the binary counts: `bazel run //t:mcp_re_proxy_cli --features x --
    --bind y` gives `--bind`, not `--features`.
    """
    found: set[str] = set()
    commands = (c for block in FENCE.findall(markdown) for c in _command_lines(block))
    for command in commands:
        match = launch.search(command)
        if match:
            argv = command[match.end() :]
            found |= {f for f in FLAG.findall(argv) if f not in LAUNCHER_FLAGS}
    return found


def is_superseded(markdown: str) -> bool:
    return bool(SUPERSEDED.search(markdown[:4000]))


def _in_scope(repo: Path, path: Path) -> bool:
    rel = path.relative_to(repo).as_posix()
    if any(part in SKIP_PARTS for part in path.parts):
        return False
    return not any(p.search(rel) for p in SKIP_PATTERNS)


def doc_files(repo: Path) -> list[Path]:
    files: list[Path] = sorted(repo.glob("*.md"))
    for root in DOC_ROOTS:
        files.extend(p for p in sorted((repo / root).rglob("*.md")) if _in_scope(repo, p))
    return files
