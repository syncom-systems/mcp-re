# SPDX-License-Identifier: Apache-2.0
"""The gate registry, `config/gates.toml`: one row per script.

The registry says which scripts are gates, where each runs, whether it has a `--selftest`
of its own, and why a script is not a control or not on the merge path. Its consumers:

  * `scripts/merge_path_gate.py` checks `local_gate.sh` and the workflows against the rows
    (`stages`, `ci`) and takes its exemptions from `off_merge_path`;
  * `_controls.gate_controls` takes the census's gate population from it: every
    `scripts/*.py|*.sh` except a row marked `not_a_control`.

This module reads and validates the rows, and checks what can be checked from the files
alone: that every script has a row, that every row names a file, that `selftest`
matches the script's own argument handling, and that a control with no selftest says why.
The checks against `local_gate.sh` and the workflows need the workflow reader and live in
the merge-path gate.

Run:  python3 tools/verification/_gates.py --selftest
"""

from __future__ import annotations

import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REGISTRY = "config/gates.toml"

#: Where the population lives: every `.py` and `.sh` file directly under it has a row.
SCRIPTS = "scripts"
SUFFIXES = (".py", ".sh")

FIELDS = frozenset(
    {"path", "stages", "ci", "selftest", "selftest_exempt", "not_a_control", "off_merge_path"}
)
REQUIRED = frozenset({"path", "stages", "ci", "selftest"})

#: A script that handles `--selftest` itself: the argument quoted as a literal, or a shell
#: `case` arm. An unquoted `--selftest` is an argument the script passes to ANOTHER program,
#: which is how `local_gate.sh` names it on every gate it runs.
SELFTEST = re.compile(r"[\"']--selftest[\"']|--selftest\)")


class RegistryError(ValueError):
    """The registry cannot be read as rows: a parse error, a bad field, a repeated path."""


@dataclass(frozen=True)
class Gate:
    path: str
    stages: tuple[int, ...]
    ci: tuple[str, ...]
    selftest: bool
    selftest_exempt: str | None
    not_a_control: str | None
    off_merge_path: str | None


def _reason(row: dict, field: str) -> str | None:
    value = row.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{row.get('path')}: `{field}` must be a non-empty reason")
    return value


def _gate(row: dict) -> Gate:
    unknown = sorted(row.keys() - FIELDS)
    missing = sorted(REQUIRED - row.keys())
    if unknown or missing:
        raise RegistryError(f"{row.get('path')}: unknown field(s) {unknown}, missing {missing}")
    path, stages, ci, selftest = row["path"], row["stages"], row["ci"], row["selftest"]
    if not isinstance(path, str) or not path:
        raise RegistryError(f"a row's `path` is not a path: {path!r}")
    if not isinstance(stages, list) or not all(isinstance(s, int) and not isinstance(s, bool) for s in stages):
        raise RegistryError(f"{path}: `stages` must be a list of stage numbers")
    if not isinstance(ci, list) or not all(isinstance(j, str) and ":" in j for j in ci):
        raise RegistryError(f"{path}: `ci` must be a list of `<workflow file>:<job key>`")
    if not isinstance(selftest, bool):
        raise RegistryError(f"{path}: `selftest` must be true or false")
    return Gate(
        path=path,
        stages=tuple(sorted(stages)),
        ci=tuple(sorted(ci)),
        selftest=selftest,
        selftest_exempt=_reason(row, "selftest_exempt"),
        not_a_control=_reason(row, "not_a_control"),
        off_merge_path=_reason(row, "off_merge_path"),
    )


def parse(text: str) -> dict[str, Gate]:
    """The rows of a registry text, keyed by path. Raises `RegistryError`."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RegistryError(f"{REGISTRY} does not parse: {exc}") from exc
    unknown = sorted(data.keys() - {"script"})
    if unknown:
        raise RegistryError(f"{REGISTRY}: unknown table(s) {unknown}")
    rows: dict[str, Gate] = {}
    for row in data.get("script", []):
        gate = _gate(row)
        if gate.path in rows:
            raise RegistryError(f"{gate.path} has two rows")
        rows[gate.path] = gate
    if not rows:
        raise RegistryError(f"{REGISTRY} has no rows; an empty registry lists nothing")
    return rows


def load(root: Path = REPO) -> dict[str, Gate]:
    """The rows of `root`'s registry. Raises `RegistryError`, including when it is absent."""
    path = root / REGISTRY
    if not path.is_file():
        raise RegistryError(f"{REGISTRY} does not exist")
    return parse(path.read_text(encoding="utf-8"))


def population(root: Path = REPO) -> set[str]:
    """Every script that must have a row: each `.py` and `.sh` file directly under `scripts/`."""
    directory = root / SCRIPTS
    if not directory.is_dir():
        return set()
    return {
        f"{SCRIPTS}/{path.name}"
        for path in directory.iterdir()
        if path.is_file() and path.suffix in SUFFIXES
    }


def not_controls(rows: dict[str, Gate]) -> set[str]:
    """The paths the registry marks as not a control."""
    return {path for path, gate in rows.items() if gate.not_a_control}


def has_selftest(text: str) -> bool:
    return bool(SELFTEST.search(text))


def problems(rows: dict[str, Gate], root: Path = REPO) -> list[str]:
    """What the files alone show the registry gets wrong."""
    found: list[str] = []
    for path in sorted(population(root) - rows.keys()):
        found.append(
            f"{path} has no row in {REGISTRY}. Every script under {SCRIPTS}/ is listed, so a "
            f"new one states whether it is a control and where it runs; add its row."
        )
    for path, gate in sorted(rows.items()):
        file = root / path
        if not file.is_file():
            found.append(f"{REGISTRY} has a row for {path}, which does not exist. Remove the row.")
            continue
        if not path.startswith(f"{SCRIPTS}/") and not gate.off_merge_path:
            found.append(
                f"{path} is outside {SCRIPTS}/ and carries no `off_merge_path`; a row outside "
                f"the population exists only to record that exemption."
            )
        actual = has_selftest(file.read_text(encoding="utf-8"))
        if actual != gate.selftest:
            found.append(
                f"{path}: `selftest = {str(gate.selftest).lower()}` but the script "
                f"{'handles' if actual else 'does not handle'} a `--selftest` argument of its own."
            )
        found.extend(selftest_problems(gate))
    return found


def selftest_problems(gate: Gate) -> list[str]:
    """A control with no selftest must say why; an exemption must exempt something.

    A gate whose only proof is that someone read it goes permissive with one edit and
    nothing notices, so a row that is a control and has no `--selftest` fails unless it
    carries `selftest_exempt` with the reason. A row that is not a control needs none.
    """
    if gate.selftest_exempt and (gate.selftest or gate.not_a_control):
        why = "has a selftest" if gate.selftest else "is not a control"
        return [
            f"{gate.path} carries `selftest_exempt` and {why}. A dead exemption is a claim "
            f"about nothing; remove it."
        ]
    if not gate.selftest and not gate.not_a_control and not gate.selftest_exempt:
        return [
            f"{gate.path} is a control with no `--selftest` and no `selftest_exempt`. Give it "
            f"a selftest that injects the defect it exists to catch and proves red, or record "
            f"in its row why it cannot have one."
        ]
    return []


def selftest() -> int:
    import tempfile

    failures = 0

    def case(label: str, ok: bool, detail: object = None) -> None:
        nonlocal failures
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failures += 1
            if detail is not None:
                print(f"        got {detail!r}")

    row = '[[script]]\npath = "scripts/a.py"\nstages = [1]\nci = ["ci.yml:rust"]\nselftest = true\n'
    rows = parse(row)
    case("a row parses", rows["scripts/a.py"].stages == (1,) and rows["scripts/a.py"].selftest, rows)
    for text, label in [
        (row + row, "a path with two rows"),
        (row.replace("selftest = true", "selftest = 1"), "a non-boolean selftest"),
        (row.replace('ci = ["ci.yml:rust"]', 'ci = ["rust"]'), "a ci entry without its workflow"),
        (row + 'colour = "red"\n', "an unknown field"),
        (row.replace("stages = [1]\n", ""), "a missing field"),
        (row + 'not_a_control = ""\n', "an empty reason"),
        ("", "an empty registry"),
        ("[[gate]]\n", "an unknown table"),
    ]:
        try:
            parse(text)
            case(f"refuses {label}", False)
        except RegistryError:
            case(f"refuses {label}", True)

    case("a quoted --selftest is a selftest", has_selftest('if "--selftest" in sys.argv:'))
    case("a case arm is a selftest", has_selftest("    --selftest) selftest ;;"))
    case("an argument passed on is not", not has_selftest("python3 scripts/x.py --selftest"))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / SCRIPTS).mkdir()
        (root / SCRIPTS / "a.py").write_text('if "--selftest" in sys.argv:\n    pass\n')
        case("a listed script with a matching row passes", problems(rows, root) == [], problems(rows, root))
        (root / SCRIPTS / "b.sh").write_text("echo b\n")
        found = problems(rows, root)
        case("an unlisted script fails", any("scripts/b.sh has no row" in p for p in found), found)
        (root / SCRIPTS / "b.sh").unlink()
        (root / SCRIPTS / "a.py").write_text("print('a')\n")
        found = problems(rows, root)
        case("a selftest flag the script contradicts fails", any("selftest = true" in p for p in found), found)
        (root / SCRIPTS / "a.py").unlink()
        found = problems(rows, root)
        case("a row naming no file fails", any("does not exist" in p for p in found), found)
        outside = parse(row.replace("scripts/a.py", "tools/x.sh").replace("selftest = true", "selftest = false"))
        (root / "tools").mkdir()
        (root / "tools" / "x.sh").write_text("echo x\n")
        found = problems(outside, root)
        case("a row outside scripts/ without off_merge_path fails", any("outside scripts/" in p for p in found), found)
        case("not_controls reads the marker", not_controls(parse(row + 'not_a_control = "a demo"\n')) == {"scripts/a.py"})
        bare = parse(row.replace("selftest = true", "selftest = false"))["scripts/a.py"]
        case("a control with no selftest and no exemption fails",
             any("no `--selftest`" in p for p in selftest_problems(bare)), selftest_problems(bare))
        exempt = parse(row.replace("selftest = true", "selftest = false") + 'selftest_exempt = "an installer"\n')
        case("a stated selftest exemption passes", selftest_problems(exempt["scripts/a.py"]) == [])
        case("a non-control needs no selftest",
             selftest_problems(parse(row.replace("selftest = true", "selftest = false")
                                     + 'not_a_control = "a demo"\n')["scripts/a.py"]) == [])
        dead = parse(row + 'selftest_exempt = "stale"\n')["scripts/a.py"]
        case("an exemption on a row with a selftest fails",
             any("dead exemption" in p for p in selftest_problems(dead)), selftest_problems(dead))

    live = load(REPO)
    case("this tree's registry loads", bool(live), None)
    found = problems(live, REPO)
    case("this tree's registry matches its scripts", not found, found)

    if failures:
        print(f"gate registry: SELFTEST FAILED ({failures})")
        return 1
    print("gate registry: selftest passed")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else 0)
