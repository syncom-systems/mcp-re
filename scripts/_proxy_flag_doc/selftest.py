# SPDX-License-Identifier: Apache-2.0
"""The gate must catch a removed flag, must not cry wolf, and must not report a green
over a document set that collapsed or exempted itself."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _proxy_flag_doc.check import check
from _proxy_flag_doc.config import AUDITOR_MODULE, CLI_MODULE, SUPERSEDED_DOCS, TOOLS
from _proxy_flag_doc.selftest_cases import DOCUMENT_CASES, LISTED_CASES

SELFTEST_CLI = "\n".join(f'    "{f}" => x,' for f in [f"--flag{i}" for i in range(25)])
SELFTEST_CLI += '\n    "--bind" => x,\n    "--trust" => x,\n'

SELFTEST_AUDITOR = "\n".join(
    f'    "{f}" => x,'
    for f in [f"--aud-flag{i}" for i in range(8)] + ["--retained-evidence-dir", "--hop"]
)


def _write_parsers(repo: Path) -> None:
    """Every tool's parser source, so a case exercises the tool it names and not a gate
    that fell back to reading one file for both."""
    for rel, text in ((CLI_MODULE, SELFTEST_CLI), (AUDITOR_MODULE, SELFTEST_AUDITOR)):
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text, encoding="utf-8")


def _empty_repo(repo: Path) -> None:
    _write_parsers(repo)
    (repo / "docs").mkdir()
    (repo / "deploy").mkdir()


def _run_case(name: str, markdown: str, should_pass: bool, where: str) -> int:
    """One document in an otherwise empty repository; 1 when the verdict is wrong."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        _empty_repo(repo)
        target = repo / where
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(markdown, encoding="utf-8")
        problems = check(repo, floors=False)
    if (not problems) == should_pass:
        print(f"selftest ok: {name}")
        return 0
    print(f"SELFTEST FAIL: {name}: got {problems or 'no problems'}")
    return 1


def _run_empty_corpus() -> int:
    """The floors: an empty corpus must not read as a pass."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        _empty_repo(repo)
        problems = check(repo)
    if len(problems) != 1 + len(TOOLS) or not any("collapsed" in p for p in problems):
        print(f"SELFTEST FAIL: an empty document set was not refused: {problems}")
        return 1
    print("selftest ok: an empty document set is refused, not reported green")
    return 0


def selftest() -> int:
    failures = sum(_run_case(*case) for case in DOCUMENT_CASES)
    listed = sorted(SUPERSEDED_DOCS)[0]
    failures += sum(_run_case(name, md, ok, listed) for name, md, ok in LISTED_CASES)
    failures += _run_empty_corpus()
    return 1 if failures else 0

