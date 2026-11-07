# SPDX-License-Identifier: Apache-2.0
"""The self-test of the gate registry: rows parse and refuse what they must, the selftest
flag is read the way the gates write it, and this tree's registry matches its scripts."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _gates_problems import has_selftest, problems, selftest_problems
from _gates_registry import (
    REPO,
    SCRIPTS,
    Gate,
    RegistryError,
    load,
    not_controls,
    parse,
)

_ROW = '[[script]]\npath = "scripts/a.py"\nstages = [1]\nci = ["ci.yml:rust"]\nselftest = true\n'


class _Report:
    """The self-test's running tally: each case prints one line and counts a failure."""

    def __init__(self) -> None:
        self.failures = 0

    def case(self, label: str, ok: bool, detail: object = None) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            self.failures += 1
            if detail is not None:
                print(f"        got {detail!r}")


def _parse_cases(report: _Report) -> dict[str, Gate]:
    row = _ROW
    rows = parse(row)
    report.case(
        "a row parses", rows["scripts/a.py"].stages == (1,) and rows["scripts/a.py"].selftest, rows
    )
    refused = [
        (row + row, "a path with two rows"),
        (row.replace("selftest = true", "selftest = 1"), "a non-boolean selftest"),
        (row.replace('ci = ["ci.yml:rust"]', 'ci = ["rust"]'), "a ci entry without its workflow"),
        (row + 'colour = "red"\n', "an unknown field"),
        (row.replace("stages = [1]\n", ""), "a missing field"),
        (row + 'not_a_control = ""\n', "an empty reason"),
        ("", "an empty registry"),
        ("[[gate]]\n", "an unknown table"),
    ]
    for text, label in refused:
        try:
            parse(text)
            report.case(f"refuses {label}", False)
        except RegistryError:
            report.case(f"refuses {label}", True)
    return rows


def _flag_cases(report: _Report) -> None:
    report.case("a quoted --selftest is a selftest", has_selftest('if "--selftest" in sys.argv:'))
    report.case("a case arm is a selftest", has_selftest("    --selftest) selftest ;;"))
    report.case(
        "an argument passed on is not", not has_selftest("python3 scripts/x.py --selftest")
    )


def _population_cases(report: _Report, rows: dict[str, Gate], root: Path) -> None:
    row = _ROW
    (root / SCRIPTS).mkdir()
    (root / SCRIPTS / "a.py").write_text('if "--selftest" in sys.argv:\n    pass\n')
    found = problems(rows, root)
    report.case("a listed script with a matching row passes", found == [], found)
    (root / SCRIPTS / "b.sh").write_text("echo b\n")
    found = problems(rows, root)
    report.case(
        "an unlisted script fails", any("scripts/b.sh has no row" in p for p in found), found
    )
    (root / SCRIPTS / "b.sh").unlink()
    (root / SCRIPTS / "a.py").write_text("print('a')\n")
    found = problems(rows, root)
    report.case(
        "a selftest flag the script contradicts fails",
        any("selftest = true" in p for p in found),
        found,
    )
    (root / SCRIPTS / "a.py").unlink()
    found = problems(rows, root)
    report.case("a row naming no file fails", any("does not exist" in p for p in found), found)
    outside = parse(
        row.replace("scripts/a.py", "tools/x.sh").replace("selftest = true", "selftest = false")
    )
    (root / "tools").mkdir()
    (root / "tools" / "x.sh").write_text("echo x\n")
    found = problems(outside, root)
    report.case(
        "a row outside scripts/ without off_merge_path fails",
        any("outside scripts/" in p for p in found),
        found,
    )


def _exemption_cases(report: _Report) -> None:
    row = _ROW
    no_selftest = row.replace("selftest = true", "selftest = false")
    report.case(
        "not_controls reads the marker",
        not_controls(parse(row + 'not_a_control = "a demo"\n')) == {"scripts/a.py"},
    )
    bare = parse(no_selftest)["scripts/a.py"]
    report.case(
        "a control with no selftest and no exemption fails",
        any("no `--selftest`" in p for p in selftest_problems(bare)),
        selftest_problems(bare),
    )
    exempt = parse(no_selftest + 'selftest_exempt = "an installer"\n')
    report.case(
        "a stated selftest exemption passes", selftest_problems(exempt["scripts/a.py"]) == []
    )
    report.case(
        "a non-control needs no selftest",
        selftest_problems(parse(no_selftest + 'not_a_control = "a demo"\n')["scripts/a.py"]) == [],
    )
    dead = parse(row + 'selftest_exempt = "stale"\n')["scripts/a.py"]
    report.case(
        "an exemption on a row with a selftest fails",
        any("dead exemption" in p for p in selftest_problems(dead)),
        selftest_problems(dead),
    )


def _live_cases(report: _Report) -> None:
    live = load(REPO)
    report.case("this tree's registry loads", bool(live), None)
    found = problems(live, REPO)
    report.case("this tree's registry matches its scripts", not found, found)


def selftest() -> int:
    report = _Report()
    rows = _parse_cases(report)
    _flag_cases(report)
    with tempfile.TemporaryDirectory() as tmp:
        _population_cases(report, rows, Path(tmp))
        _exemption_cases(report)
    _live_cases(report)
    if report.failures:
        print(f"gate registry: SELFTEST FAILED ({report.failures})")
        return 1
    print("gate registry: selftest passed")
    return 0
