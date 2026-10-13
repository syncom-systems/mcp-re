# SPDX-License-Identifier: Apache-2.0
"""The toolchain lock: the one reader of `verification/policy/toolchains.lock.toml`.

The lock pins every tool identity a lane, a gate or an installer depends on. Its readers
are of three kinds, and all of them read it here:

  * the assurance tooling, through `_manifest.load_toolchains`, which adds the extraction
    container's identity and artifact checks on top of `load`;
  * the gates that hold a support claim to its runtime pin (`node_runtime_gate.py`,
    `python_runtime_gate.py`) and the extraction-image gate, through `load` and
    `interpreters`;
  * the installers, which run before any environment is prepared: the Python ones import
    this module, and the shell ones ask the CLI below.

`interpreters` is the one statement of what a runtime pin must look like — resolved, every
entry an exact `major.minor.patch`, and one pinned version per support line — so the two
runtime gates refuse the same malformed pin with the same sentence, and the installers
prepare exactly the set those gates checked.

Stdlib only, at import and when run: the shell installers call it with whatever `python3`
the runner has before any repository environment exists.

Run:  python3 tools/verification/_toolchains.py interpreters <ecosystem>
      python3 tools/verification/_toolchains.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

import _registries
from _registries import REPO_ROOT
from _registries import ManifestError

WHERE = "toolchains.lock.toml"
STATES = frozenset({"resolved", "unresolved"})

#: Per ecosystem: what one pinned runtime is called, what a support line is called, and how
#: many leading version components name that line. CPython's support lines are minors;
#: Node's are majors.
ECOSYSTEMS = {
    "python": ("interpreter", "minor", 2),
    "typescript": ("runtime", "major", 1),
}


def path(root: Path = REPO_ROOT) -> Path:
    """The lock file, for a reader that edits or digests its bytes."""
    return _registries.path("toolchains", root)


def load(root: Path = REPO_ROOT) -> dict:
    """The lock parsed, with every table's `state` checked.

    A table or sub-table with no `state`, or with any value but `resolved` and
    `unresolved`, is a tool of unknown identity and is refused here rather than read as
    either.
    """
    doc = _registries.document("toolchains", root, required=True)
    if "schema_version" not in doc:
        raise ManifestError(f"{WHERE}: missing required key(s) ['schema_version']")
    for name, entry in doc.items():
        if name == "schema_version":
            continue
        if not isinstance(entry, dict):
            raise ManifestError(f"{WHERE}: [{name}] must be a table")
        state = entry.get("state")
        if state not in STATES:
            raise ManifestError(
                f"{WHERE}: [{name}] state must be 'resolved' or 'unresolved', got "
                f"{state!r}. A tool with no state is a tool of unknown identity."
            )
        for sub_name, sub in entry.items():
            if isinstance(sub, dict) and sub.get("state") not in STATES:
                raise ManifestError(
                    f"{WHERE}: [{name}.{sub_name}] state must be 'resolved' or 'unresolved'"
                )
    return doc


def unresolved_pins(toolchains: dict) -> list[str]:
    """Every toolchain identity that is not pinned, as dotted names.

    An unresolved pin means the tool's identity is unknown, and unknown is dirty. The
    lanes that depend on it refuse to run rather than running against whatever is on
    PATH — a proof checked by an unknown prover is not evidence.
    """
    out: list[str] = []
    for name, entry in toolchains.items():
        if name == "schema_version" or not isinstance(entry, dict):
            continue
        if entry.get("state") == "unresolved":
            out.append(name)
        for sub_name, sub in entry.items():
            if isinstance(sub, dict) and sub.get("state") == "unresolved":
                out.append(f"{name}.{sub_name}")
    return sorted(out)


def interpreters(entry, ecosystem: str) -> tuple[dict[tuple[int, ...], str], str | None]:
    """`({support line: exact version}, None)` for a well-formed runtime pin, else `({}, why)`.

    `entry` is the lock's `[<ecosystem>]` table, or None when the lock has none. The key of
    each pinned version is its support line: `(3, 14)` for CPython 3.14.7, `(22,)` for Node
    22.23.2.
    """
    noun, line, width = ECOSYSTEMS[ecosystem]
    if not isinstance(entry, dict):
        return {}, f"toolchains.lock.toml has no [{ecosystem}] runtime pin"
    if entry.get("state") != "resolved":
        return {}, f"[{ecosystem}] is unresolved, so no {noun} identity backs the claim"
    versions = entry.get("interpreters")
    if not isinstance(versions, list) or not versions:
        return {}, f"[{ecosystem}].interpreters names no {noun}"
    pinned: dict[tuple[int, ...], str] = {}
    for version in versions:
        parts = str(version).split(".")
        if len(parts) != 3 or not all(part.isascii() and part.isdigit() for part in parts):
            return {}, (
                f"[{ecosystem}].interpreters entry {version!r} is not an exact "
                f"major.minor.patch version. A {line} alone lets two different builds record "
                f"one identity"
            )
        key = tuple(int(part) for part in parts[:width])
        if key in pinned:
            label = ".".join(str(part) for part in key)
            return {}, (
                f"[{ecosystem}].interpreters names {line} {label} twice ({pinned[key]}, "
                f"{version}); one {line} is measured on one {noun}"
            )
        pinned[key] = str(version)
    return pinned, None


def pin_shape_cases(ecosystem: str, good: list[str]) -> list[tuple[str, dict | None, bool]]:
    """`(name, entry, must_refuse)`: the malformed pins both runtime gates must refuse.

    `good` is an exact pin set the calling gate's own claim accepts, with at least one
    entry; every case is a one-step corruption of it, plus `good` itself, which must pass.
    Both gates run these through their own `check`, so a pin-shape refusal one of them
    stopped making is caught by the fixture they share rather than by remembering to copy
    a case.
    """
    _, line, _ = ECOSYSTEMS[ecosystem]
    last = good[-1].split(".")
    truncated = ".".join(last[:2])
    same_line = ".".join([*last[:2], str(int(last[2]) + 1)])
    return [
        ("no runtime pin at all", None, True),
        ("an unresolved runtime pin", {"state": "unresolved"}, True),
        ("a resolved pin naming nothing", {"state": "resolved", "interpreters": []}, True),
        (
            f"a {line} pinned without a patch version",
            {"state": "resolved", "interpreters": [*good[:-1], truncated]},
            True,
        ),
        (
            f"a {line} whose patch is a non-ASCII digit",
            {"state": "resolved", "interpreters": [*good[:-1], ".".join([*last[:2], "\u00b2"])]},
            True,
        ),
        (
            f"one {line} pinned twice",
            {"state": "resolved", "interpreters": [*good, same_line]},
            True,
        ),
        ("the claim and the pin agreeing exactly", {"state": "resolved", "interpreters": list(good)}, False),
    ]


def selftest() -> int:
    failures = 0

    def case(label: str, ok: bool, detail: object = None) -> None:
        nonlocal failures
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            failures += 1
            if detail is not None:
                print(f"        got {detail!r}")

    lock = load()
    case("the tree's lock loads", "schema_version" in lock)
    for ecosystem in ECOSYSTEMS:
        pinned, why = interpreters(lock.get(ecosystem), ecosystem)
        case(f"the tree's [{ecosystem}] pin is well formed", why is None and bool(pinned), why)

    for ecosystem, good in (("python", ["3.13.9", "3.14.7"]), ("typescript", ["20.20.2", "22.23.2"])):
        for name, entry, must_refuse in pin_shape_cases(ecosystem, good):
            _, why = interpreters(entry, ecosystem)
            case(f"[{ecosystem}] {name}: {'refused' if must_refuse else 'accepted'}",
                 (why is not None) is must_refuse, why)

    python, _ = interpreters({"state": "resolved", "interpreters": ["3.13.9", "3.14.7"]}, "python")
    case("a CPython pin is keyed by minor", python == {(3, 13): "3.13.9", (3, 14): "3.14.7"}, python)
    node, _ = interpreters({"state": "resolved", "interpreters": ["20.20.2", "22.23.2"]}, "typescript")
    case("a Node pin is keyed by major", node == {(20,): "20.20.2", (22,): "22.23.2"}, node)

    case(
        "unresolved_pins names tables and sub-tables",
        unresolved_pins({"schema_version": 1, "a": {"state": "unresolved"},
                         "b": {"state": "resolved", "c": {"state": "unresolved"}}})
        == ["a", "b.c"],
    )

    import tempfile

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
            try:
                load(root)
                case(label, False)
            except ManifestError:
                case(label, True)
        target.unlink()
        try:
            load(root)
            case("an absent lock is refused, not read as empty", False)
        except ManifestError:
            case("an absent lock is refused, not read as empty", True)

    if failures:
        print(f"toolchain lock: SELFTEST FAILED ({failures})")
        return 1
    print("toolchain lock: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if len(argv) == 2 and argv[0] == "interpreters" and argv[1] in ECOSYSTEMS:
        try:
            lock = load()
        except ManifestError as exc:
            print(f"toolchain lock: {exc}", file=sys.stderr)
            return 1
        pinned, why = interpreters(lock.get(argv[1]), argv[1])
        if why is not None:
            print(f"toolchain lock: {why}", file=sys.stderr)
            return 1
        print("\n".join(sorted(pinned.values())))
        return 0
    print(
        "usage: _toolchains.py interpreters {" + ",".join(ECOSYSTEMS) + "} | --selftest",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
