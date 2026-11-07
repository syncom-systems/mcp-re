# SPDX-License-Identifier: Apache-2.0
"""Provider findings and the repository files reached, for one shell script."""

from __future__ import annotations

import re

from _provider_neutral.config import (
    BACKTICK_COMMENT,
    CREDENTIAL_VARS,
    MESSAGE_WORDS,
    PROBE_WORDS,
    PROVIDER_CLIS,
    REGISTRY_HOSTS,
    REPO_PATH,
    Result,
)
from _provider_neutral.lexer import command_word, segments

_QUOTED_WORD = re.compile(r"[\"']([a-z]+)[\"']")


def normalize(token: str, repo_files: set[str]) -> str | None:
    """The repository file a token names, or None."""
    match = REPO_PATH.search(token.strip("\"'"))
    if match and match.group(1) in repo_files:
        return match.group(1)
    return None


def shell_code_lines(text: str) -> list[str]:
    lines = []
    for line in BACKTICK_COMMENT.sub(" ", text).splitlines():
        if line.lstrip().startswith("#"):
            continue
        # A trailing ` # comment` (whitespace before the hash) is a comment too.
        lines.append(re.sub(r"\s#\s.*$", "", line))
    return lines


def _line_findings(line: str) -> list[str]:
    """What a line says regardless of how it parses: quoted provider names, credentials, registries."""
    shown = line.strip()
    out = [
        f"provider CLI as a quoted literal ({m.group(1)!r}): {shown}"
        for m in _QUOTED_WORD.finditer(line)
        if m.group(1) in PROVIDER_CLIS
    ]
    if CREDENTIAL_VARS.search(line):
        out.append(f"cloud credential/account variable: {shown}")
    if REGISTRY_HOSTS.search(line):
        out.append(f"provider registry host: {shown}")
    return out


def _is_probe_at(words: list[str], i: int) -> bool:
    return words[i] in PROBE_WORDS or (words[i] == "command" and words[i + 1] in {"-v", "-V"})


def _probes_provider(words: list[str]) -> bool:
    """`command -v gcloud`, `which aws`: asking whether a provider CLI exists."""
    return any(
        _is_probe_at(words, i) and any(w in PROVIDER_CLIS for w in words[i + 1:])
        for i in range(len(words) - 1)
    )


def _segment_findings(words: list[str], base: str, shown: str) -> list[str]:
    out = []
    if base in PROVIDER_CLIS:
        out.append(f"provider CLI invoked ({base}): {shown}")
    if _probes_provider(words):
        out.append(f"provider CLI probed: {shown}")
    return out


def _segment_edges(command: str, args: list[str], repo_files: set[str]) -> set[str]:
    """Repository files a segment names — unless it is only a message about them."""
    if command in MESSAGE_WORDS:
        return set()
    return {found for word in [command, *args] if (found := normalize(word, repo_files))}


def _segment_result(words: list[str], shown: str, repo_files: set[str]) -> Result:
    command, args = command_word(words)
    if command is None:
        return [], set()
    base = command.rsplit("/", 1)[-1]
    return _segment_findings(words, base, shown), _segment_edges(command, args, repo_files)


def _line_result(line: str, repo_files: set[str]) -> Result:
    findings = _line_findings(line)
    edges: set[str] = set()
    for words in segments(line):
        segment_findings, segment_edges = _segment_result(words, line.strip(), repo_files)
        findings += segment_findings
        edges |= segment_edges
    return findings, edges


def shell_findings_and_edges(text: str, repo_files: set[str]) -> Result:
    findings: list[str] = []
    edges: set[str] = set()
    for line in shell_code_lines(text):
        line_findings, line_edges = _line_result(line, repo_files)
        findings += line_findings
        edges |= line_edges
    return findings, edges
