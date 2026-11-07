# SPDX-License-Identifier: Apache-2.0
"""Every problem in a repository: unread parsers, bad flags, exemptions, collapsed floors."""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

from _proxy_flag_doc.config import MIN_SCANNED_DOCS, SUPERSEDED_DOCS, TOOLS, Tool
from _proxy_flag_doc.scan import doc_files, documented_flags, is_superseded, known_flags


class Exemption(NamedTuple):
    """What a document's superseded banner and its SUPERSEDED_DOCS entry add up to."""

    problems: list[str]
    scan: bool
    reported_skip: bool


def _exemption(rel: str, text: str) -> Exemption:
    banner, listed = is_superseded(text), rel in SUPERSEDED_DOCS
    if banner and listed:
        return Exemption([], False, True)
    if banner:
        return Exemption(
            [
                f"{rel}: carries a `> **Superseded` banner but is not in this gate's "
                f"SUPERSEDED_DOCS. A document does not exempt itself from the check its "
                f"command lines exist to pass; add it here if the exemption is intended."
            ],
            False,
            False,
        )
    if listed:
        return Exemption(
            [
                f"{rel}: is in SUPERSEDED_DOCS but no longer declares itself superseded. "
                f"Remove the entry so the document is scanned again."
            ],
            True,
            False,
        )
    return Exemption([], True, False)


def _parser_shortfall(tool: Tool, flags: set[str]) -> str | None:
    if len(flags) >= tool.min_flags:
        return None
    return (
        f"{tool.binary}: found only {len(flags)} flag literals in "
        f"{', '.join(tool.sources)} — the parser's shape changed and this gate is "
        f"no longer reading it. Fix the gate, do not skip it."
    )


def _unknown_flag_problems(rel: str, tool: Tool, unknown: set[str]) -> list[str]:
    return [
        f"{rel}: `{flag}` is used in a {tool.binary} command line but "
        f"{', '.join(tool.sources)} does not parse it. Remove it, or say in "
        f"the surrounding prose that it was removed (prose is not scanned; "
        f"command lines are)."
        for flag in sorted(unknown)
    ]


def _scan_document(
    rel: str, text: str, known: dict[str, set[str]], launch_docs: dict[str, int]
) -> list[str]:
    problems: list[str] = []
    for tool in TOOLS:
        flags = documented_flags(text, tool.launch_pattern())
        if flags:
            launch_docs[tool.binary] += 1
        problems.extend(_unknown_flag_problems(rel, tool, flags - known[tool.binary]))
    return problems


def _floor_problems(file_count: int, launch_docs: dict[str, int]) -> list[str]:
    problems: list[str] = []
    if file_count < MIN_SCANNED_DOCS:
        problems.append(
            f"the scan selected only {file_count} documents (floor {MIN_SCANNED_DOCS}) — "
            f"the document set collapsed, so a green here measured nothing. Fix the "
            f"selection, do not lower the floor."
        )
    for tool in TOOLS:
        if launch_docs[tool.binary] < tool.min_launch_docs:
            problems.append(
                f"only {launch_docs[tool.binary]} scanned document launches "
                f"{tool.binary} (floor {tool.min_launch_docs}) — either the invocation "
                f"pattern stopped matching or the guides moved out of scope. Fix the "
                f"selection, do not lower the floor."
            )
    return problems


def _known_by_tool(repo: Path) -> tuple[dict[str, set[str]], str | None]:
    """Each tool's accepted flags, or the first parser the gate has stopped reading."""
    known: dict[str, set[str]] = {}
    for tool in TOOLS:
        flags = known_flags(repo, tool)
        shortfall = _parser_shortfall(tool, flags)
        if shortfall:
            return known, shortfall
        known[tool.binary] = flags
    return known, None


def check(repo: Path, skipped: list[str] | None = None, floors: bool = True) -> list[str]:
    """Every problem in `repo`.

    `floors` is off only for the selftest's single-document fixtures, which are about the
    per-document logic rather than the size of the real corpus; the floor itself has its
    own case.
    """
    skipped = skipped if skipped is not None else []
    known, shortfall = _known_by_tool(repo)
    if shortfall:
        return [shortfall]
    problems: list[str] = []
    files = doc_files(repo)
    launch_docs: dict[str, int] = {tool.binary: 0 for tool in TOOLS}
    for path in files:
        rel = path.relative_to(repo).as_posix()
        text = path.read_text(encoding="utf-8")
        exemption = _exemption(rel, text)
        problems.extend(exemption.problems)
        if exemption.reported_skip:
            skipped.append(rel)
        if exemption.scan:
            problems.extend(_scan_document(rel, text, known, launch_docs))
    if floors:
        problems.extend(_floor_problems(len(files), launch_docs))
    return problems
