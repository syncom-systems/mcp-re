# SPDX-License-Identifier: Apache-2.0
"""The `--selftest` of the toolchain lock reader."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _registries import ManifestError
from _toolchains_pins import ECOSYSTEMS, interpreters, pin_shape_cases
from _toolchains_read import load, path, unresolved_pins


class _Report:
    """Prints one line per case and counts the failures."""

    def __init__(self) -> None:
        self.failures = 0

    def case(self, label: str, ok: bool, detail: object = None) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            self.failures += 1
            if detail is not None:
                print(f"        got {detail!r}")


def _tree_cases(report: _Report) -> None:
    lock = load()
    report.case("the tree's lock loads", "schema_version" in lock)
    for ecosystem in ECOSYSTEMS:
        pinned, why = interpreters(lock.get(ecosystem), ecosystem)
        report.case(f"the tree's [{ecosystem}] pin is well formed", why is None and bool(pinned), why)


def _shape_cases(report: _Report) -> None:
    for ecosystem, good in (("python", ["3.13.9", "3.14.7"]), ("typescript", ["20.20.2", "22.23.2"])):
        for name, entry, must_refuse in pin_shape_cases(ecosystem, good):
            _, why = interpreters(entry, ecosystem)
            report.case(f"[{ecosystem}] {name}: {'refused' if must_refuse else 'accepted'}",
                        (why is not None) is must_refuse, why)

    python, _ = interpreters({"state": "resolved", "interpreters": ["3.13.9", "3.14.7"]}, "python")
    report.case("a CPython pin is keyed by minor", python == {(3, 13): "3.13.9", (3, 14): "3.14.7"}, python)
    node, _ = interpreters({"state": "resolved", "interpreters": ["20.20.2", "22.23.2"]}, "typescript")
    report.case("a Node pin is keyed by major", node == {(20,): "20.20.2", (22,): "22.23.2"}, node)

    report.case(
        "unresolved_pins names tables and sub-tables",
        unresolved_pins({"schema_version": 1, "a": {"state": "unresolved"},
                         "b": {"state": "resolved", "c": {"state": "unresolved"}}})
        == ["a", "b.c"],
    )


def _refuses(root: Path) -> bool:
    try:
        load(root)
    except ManifestError:
        return True
    return False


def _load_cases(report: _Report) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = path(root)
        target.parent.mkdir(parents=True)
        for label, body in (
            ("a lock with no schema_version is refused", '[a]\nstate = "resolved"\n'),
            ("a table with no state is refused", 'schema_version = 1\n[a]\nx = 1\n'),
            ("a sub-table with an unknown state is refused",
             'schema_version = 1\n[a]\nstate = "resolved"\n[a.b]\nstate = "pinned"\n'),
        ):
            target.write_text(body, encoding="utf-8")
            report.case(label, _refuses(root))
        target.unlink()
        report.case("an absent lock is refused, not read as empty", _refuses(root))


def selftest() -> int:
    report = _Report()
    _tree_cases(report)
    _shape_cases(report)
    _load_cases(report)
    if report.failures:
        print(f"toolchain lock: SELFTEST FAILED ({report.failures})")
        return 1
    print("toolchain lock: selftest passed")
    return 0
