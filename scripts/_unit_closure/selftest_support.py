"""Shared fixtures and the verdict recorder of the selftest."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _unit_closure.register import check_register, validate_register
from _unit_closure.rules import flag

#: A namespace file: nothing but a `mod` and a re-export.
NAMESPACE = "mod child;\npub use child::*;\n"

#: A unit whose `mod.rs` declares a sibling that no unit measures.
SPLIT = {
    "c/src/lib.rs": "pub mod sp;\n",
    "c/src/sp/mod.rs": "mod rotation;\npub fn advance() {}\n",
    "c/src/sp/rotation.rs": "",
}

#: The register entry that answers `SPLIT`'s unmeasured sibling.
ENTRY = {
    "c/src/sp/rotation.rs": {
        "path": "c/src/sp/rotation.rs",
        "rule": "UC-1",
        "baseline_sha": "0000000",
        "status": "reviewed-out-of-cone",
        "reason": "measured elsewhere",
        "review_ref": "REV-1 in docs/d.md",
    }
}


class Verdicts:
    """Collects selftest failures; `ok` is False once any property failed."""

    def __init__(self) -> None:
        self.ok = True

    def fail(self, message: str) -> None:
        print(message)
        self.ok = False

    def case(self, name: str, problems: list[str], expect: str | None) -> None:
        """`expect` is a substring one problem must contain, or None for "no problem"."""
        if expect is None:
            if problems:
                self.fail(f"SELFTEST FAILED [{name}]: expected nothing, got {problems}")
        elif not any(expect in p for p in problems):
            self.fail(
                f"SELFTEST FAILED [{name}]: expected a problem containing {expect!r}, "
                f"got {problems}"
            )


def unit(uid: str, *paths: str) -> dict:
    return {"id": uid, "paths": list(paths)}


def _tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def run(files: dict[str, str], units, register: dict[str, dict]) -> tuple[list[str], int, int]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _tree(root, files)
        findings, walked = flag(root, units)
        problems = validate_register(register, root) + check_register(findings, register)
        return problems, walked, len(units)


def problems_of(files: dict[str, str], units, register: dict[str, dict]) -> list[str]:
    return run(files, units, register)[0]
