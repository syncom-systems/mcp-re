# SPDX-License-Identifier: Apache-2.0
"""vitest controls: every registered `it(…)` / `test(…)` case, named by vitest's own reporter form."""

from __future__ import annotations

import re
from pathlib import Path

from _control_files import skipped, walk
from _control_model import Control
from _ecosystems import REPO_ROOT

_TS_EACH = re.compile(r"^\s*(?:it|test)\.each\s*\(")
#: An `it.each([...])("title", …)` whose table and title share one line: the title follows
#: the table's closing `)` and a second `(`.
_TS_EACH_INLINE = re.compile(r"\)\s*\(\s*(['\"`])(.+?)\1")
#: A project-local case declarer — `const tls = (name: string, fn) => it(name, …)`. Without
#: this every case declared through the wrapper is invisible, which is not a smaller census
#: but a wrong one: those controls ARE registered, so they would read as registry selectors
#: naming nothing.
_TS_WRAPPER = re.compile(r"^\s*(?:const|let|function)\s+([A-Za-z_$][\w$]*)\s*[=(]\s*\(?\s*([A-Za-z_$][\w$]*)")
_TS_TITLE = re.compile(r"^\s*(['\"`])(.+?)\1\s*,?\s*$")
_TS_SUITE = re.compile(r"^(\s*)describe(?:\.\w+)*\s*\(\s*(['\"`])(.+?)\2")
#: `describe.runIf(<expr>)("title", …)` and `describe.each([...])("title", …)`: the title
#: follows the modifier's own argument list, so it is not where `_TS_SUITE` looks. A suite
#: this misses does not vanish — its cases are still enumerated, under the WRONG reported
#: name, which is worse: the identity would join to nothing and a registration written
#: against it would name a case vitest never reports.
_TS_SUITE_MODIFIED = re.compile(
    r"^(\s*)describe\.\w+\s*\(.*?\)\s*\(\s*(['\"`])(.+?)\2"
)

#: How far after an `it.each([...])(` opening the case TITLE may sit. A table literal is
#: usually wrapped across lines and the title follows it, so the title is not on the
#: opening line — and a scanner that only reads that line reports zero controls for a whole
#: parametrised family while the file is full of them.
_TS_TITLE_LOOKAHEAD = 40

_TEST_FILE = re.compile(r"\.(test|spec)\.ts$")


def _case_declarers(lines: list[str]) -> re.Pattern[str]:
    """`it`/`test` plus every project-local wrapper that delegates to one.

    A wrapper is recognised by what it DOES — it takes a name and passes that same name to
    `it(` a few lines later — rather than by being listed somewhere, because a list of
    known helper names is a thing that goes stale silently and this measurement's whole
    value is that it does not.
    """
    names = ["it", "test"]
    for index, line in enumerate(lines):
        found = _TS_WRAPPER.match(line)
        if found is None:
            continue
        wrapper, parameter = found.group(1), found.group(2)
        delegates = re.compile(rf"\b(?:it|test)\s*\(\s*{re.escape(parameter)}\s*,")
        if any(delegates.search(text) for text in lines[index : index + 6]):
            names.append(wrapper)
    alternatives = "|".join(re.escape(name) for name in dict.fromkeys(names))
    return re.compile(rf"^\s*(?:{alternatives})(?:\.\w+)*\s*\(\s*(['\"`])(.+?)\1")


def _each_title(lines: list[str], index: int) -> str | None:
    """The title of the `it.each` family opened at `lines[index]`, on that line or after the table."""
    inline = _TS_EACH_INLINE.search(lines[index])
    if inline is not None:
        return inline.group(2)
    for line in lines[index + 1 : index + 1 + _TS_TITLE_LOOKAHEAD]:
        found = _TS_TITLE.match(line)
        if found is not None:
            return found.group(2)
    return None


def _case_title(lines: list[str], index: int, declarers: re.Pattern[str]) -> str | None:
    """The case title declared at `lines[index]`, or None if no case starts there."""
    case = declarers.match(lines[index])
    if case is not None:
        return case.group(2)
    if _TS_EACH.match(lines[index]) is None:
        return None
    return _each_title(lines, index)


def _open_suite(suites: list[tuple[int, str]], suite: re.Match[str]) -> None:
    """Enter `suite`, leaving every suite at the same or a deeper indent."""
    indent = len(suite.group(1))
    while suites and suites[-1][0] >= indent:
        suites.pop()
    suites.append((indent, suite.group(3)))


def _vitest_cases_in(path: Path, project: str, rel: str, rel_repo: Path) -> list[Control]:
    out: list[Control] = []
    lines = path.read_text(errors="replace").splitlines()
    suites: list[tuple[int, str]] = []
    declarers = _case_declarers(lines)
    for index, line in enumerate(lines):
        suite = _TS_SUITE.match(line) or _TS_SUITE_MODIFIED.match(line)
        if suite is not None:
            _open_suite(suites, suite)
            continue
        title = _case_title(lines, index, declarers)
        if title is None:
            continue
        trail = " > ".join([name for _, name in suites] + [title])
        out.append(
            Control(
                project=project,
                identity=f"vitest#{rel} > {trail}",
                kind="vitest",
                carrier=rel_repo.as_posix(),
                line=index + 1,
            )
        )
    return out


def _projects(manifest: str) -> list[Path]:
    return sorted(
        found.parent
        for found in walk(manifest)
        if not skipped(found.relative_to(REPO_ROOT))
    )


def _project_controls(project: Path) -> list[Control]:
    out: list[Control] = []
    for path in walk(".ts", project):
        rel_repo = path.relative_to(REPO_ROOT)
        if skipped(rel_repo) or not _TEST_FILE.search(path.name):
            continue
        out.extend(
            _vitest_cases_in(
                path,
                project.relative_to(REPO_ROOT).as_posix(),
                path.relative_to(project).as_posix(),
                rel_repo,
            )
        )
    return out


def vitest_controls() -> list[Control]:
    """Every vitest case, named `vitest#<file> > <suite> > … > <case>`.

    That separator is vitest's own reporter form and is what `tested_symbols` already
    carries, so the identity is the reported name rather than a path this module invents.

    A parametrised family (`it.each`) is ONE control identified by its TITLE TEMPLATE —
    `… at sign time: %s` — because that is what the source defines and what deleting would
    remove. The registry names the expanded cases, and `_census` matches them back to the
    template rather than this module inventing pytest's and vitest's id algebra, which it
    would get wrong in both.
    """
    return [control for project in _projects("package.json") for control in _project_controls(project)]
