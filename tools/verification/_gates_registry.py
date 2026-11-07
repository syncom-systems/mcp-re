# SPDX-License-Identifier: Apache-2.0
"""Reading and validating the rows of `config/gates.toml`: the field sets, the `Gate` row,
and the loaders that raise `RegistryError` for anything that cannot be read as rows."""

from __future__ import annotations

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


def _check_fields(row: dict) -> None:
    unknown = sorted(row.keys() - FIELDS)
    missing = sorted(REQUIRED - row.keys())
    if unknown or missing:
        raise RegistryError(f"{row.get('path')}: unknown field(s) {unknown}, missing {missing}")


def _stage_numbers(stages: object) -> bool:
    return isinstance(stages, list) and all(
        isinstance(s, int) and not isinstance(s, bool) for s in stages
    )


def _workflow_jobs(ci: object) -> bool:
    return isinstance(ci, list) and all(isinstance(j, str) and ":" in j for j in ci)


def _check_path(row: dict) -> None:
    path = row["path"]
    if not isinstance(path, str) or not path:
        raise RegistryError(f"a row's `path` is not a path: {path!r}")


def _is_bool(value: object) -> bool:
    return isinstance(value, bool)


#: The value rules, checked in this order: the field, how to tell it is well formed, and the
#: refusal when it is not.
_VALUE_RULES = (
    ("stages", _stage_numbers, "`stages` must be a list of stage numbers"),
    ("ci", _workflow_jobs, "`ci` must be a list of `<workflow file>:<job key>`"),
    ("selftest", _is_bool, "`selftest` must be true or false"),
)


def _check_values(row: dict) -> None:
    _check_path(row)
    for field, well_formed, refusal in _VALUE_RULES:
        if not well_formed(row[field]):
            raise RegistryError(f"{row['path']}: {refusal}")


def _gate(row: dict) -> Gate:
    _check_fields(row)
    _check_values(row)
    return Gate(
        path=row["path"],
        stages=tuple(sorted(row["stages"])),
        ci=tuple(sorted(row["ci"])),
        selftest=row["selftest"],
        selftest_exempt=_reason(row, "selftest_exempt"),
        not_a_control=_reason(row, "not_a_control"),
        off_merge_path=_reason(row, "off_merge_path"),
    )


def _document(text: str) -> dict:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RegistryError(f"{REGISTRY} does not parse: {exc}") from exc
    unknown = sorted(data.keys() - {"script"})
    if unknown:
        raise RegistryError(f"{REGISTRY}: unknown table(s) {unknown}")
    return data


def parse(text: str) -> dict[str, Gate]:
    """The rows of a registry text, keyed by path. Raises `RegistryError`."""
    rows: dict[str, Gate] = {}
    for row in _document(text).get("script", []):
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
