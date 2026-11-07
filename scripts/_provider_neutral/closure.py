# SPDX-License-Identifier: Apache-2.0
"""The execution closure of the local gate: which files it reaches, and whether any is a provider call."""

from __future__ import annotations

from collections import deque
from pathlib import Path

from _provider_neutral.config import ENTRY, FORBIDDEN_MEMBERS, REPO, REQUIRED_MEMBERS, Result
from _provider_neutral.pysrc import python_findings_and_edges
from _provider_neutral.shell import shell_findings_and_edges


def _kind_from_interpreter(first_line: str) -> str:
    if not first_line.startswith("#!"):
        return "other"
    if "python" in first_line:
        return "py"
    if "bash" in first_line or first_line.endswith("sh"):
        return "sh"
    return "other"


def kind(path: str, text: str) -> str:
    """How a closure file is read: "sh", "py" or "other"."""
    if path.endswith(".py"):
        return "py"
    if path.endswith(".sh"):
        return "sh"
    return _kind_from_interpreter(text.split("\n", 1)[0])


def _analyse_file(path: str, text: str, repo_files: set[str]) -> Result:
    how = kind(path, text)
    if how == "sh":
        return shell_findings_and_edges(text, repo_files)
    if how == "py":
        return python_findings_and_edges(text, path, repo_files)
    return [], set()


def analyse(read: dict[str, str], entry: str) -> tuple[set[str], dict[str, list[str]]]:
    repo_files = set(read)
    seen = {entry}
    queue = deque([entry])
    findings: dict[str, list[str]] = {}
    while queue:
        current = queue.popleft()
        hits, edges = _analyse_file(current, read.get(current, ""), repo_files)
        if hits:
            findings[current] = hits
        for found in sorted(edges - seen):
            seen.add(found)
            queue.append(found)
    return seen, findings


def _is_script_file(path: Path) -> bool:
    return path.is_file() and path.suffix in {"", ".py", ".sh"} and "__pycache__" not in path.parts


def read_repo() -> dict[str, str]:
    read: dict[str, str] = {}
    for top in ("scripts", "tools", "docs"):
        for path in (REPO / top).rglob("*"):
            if _is_script_file(path):
                read[path.relative_to(REPO).as_posix()] = path.read_text(encoding="utf-8", errors="replace")
    return read


def _finding_problems(findings: dict[str, list[str]]) -> list[str]:
    return [f"{path}: {hit}" for path, hits in sorted(findings.items()) for hit in hits]


def _required_problems(read: dict[str, str], closure: set[str]) -> list[str]:
    unreached = [m for m in REQUIRED_MEMBERS if m in read and m not in closure]
    missing = [m for m in REQUIRED_MEMBERS if m not in read]
    return [f"{m}: REQUIRED in the local closure and not reached" for m in unreached] + [
        f"{m}: REQUIRED in the local closure and does not exist" for m in missing
    ]


def _forbidden_problems(closure: set[str], entry: str) -> list[str]:
    return [f"{m}: a cloud driver is reachable from {entry}" for m in FORBIDDEN_MEMBERS if m in closure]


def adjudicate(read: dict[str, str], entry: str = ENTRY) -> tuple[set[str], list[str]]:
    closure, findings = analyse(read, entry)
    problems = _finding_problems(findings)
    problems += _required_problems(read, closure)
    problems += _forbidden_problems(closure, entry)
    return closure, problems
