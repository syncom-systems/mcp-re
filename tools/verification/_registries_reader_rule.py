# SPDX-License-Identifier: Apache-2.0
"""The reader rule: no production gate or tool spells a policy registry's path, or a guarded
generated table's path, when it can ask `_registries` instead.

A path to the policy directory, or to a guarded registry, is a violation when written as a
string or built with `/`. Prose is not a reader: a docstring, or a string with whitespace in
it, is a sentence about a registry rather than a path to one.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from _registries_reading import GUARDED, REGISTRIES, REPO_ROOT

#: Where a production reader can live: the gates and the assurance tooling.
_READER_ROOTS = ("scripts", "tools/verification")
_GUARDED_FILES = tuple(REGISTRIES[name] for name in sorted(GUARDED))
_POLICY_TAIL = re.compile(r"(?:^|/)verification/policy/?$")

#: Generated tables held to one reader the same way, each by the module that is its reader.
#: The owner may spell the path; every other production source asks the owner.
GENERATED_OWNERS = {"verification/generated/rust-targets.json": "_rust_targets.py"}


def _names_generated(value: str, exempt: frozenset[str]) -> bool:
    """A path-shaped string ending in a guarded generated table the source does not own."""
    if any(ch.isspace() for ch in value):
        return False
    return any(value.endswith(rel) for rel in GENERATED_OWNERS if rel not in exempt)


def _candidate_files(directory: Path) -> list[Path]:
    return sorted(directory.iterdir()) if directory.is_dir() else []


def _is_registries_module(name: str) -> bool:
    """`_registries` and the `_registries_*` modules it is assembled from: the one reader."""
    return name == "_registries.py" or name.startswith("_registries_")


def _is_reader_candidate(file: Path) -> bool:
    if not file.is_file() or file.name.startswith("test_"):
        return False
    return not _is_registries_module(file.name)


def _is_python_source(file: Path) -> bool:
    if file.suffix == ".py":
        return True
    if file.suffix:
        return False
    head = file.read_bytes()[:64]
    return head.startswith(b"#!") and b"python" in head


def _production_sources(root: Path) -> list[Path]:
    return [
        file
        for base in _READER_ROOTS
        for file in _candidate_files(root / base)
        if _is_reader_candidate(file) and _is_python_source(file)
    ]


def _docstring_constant(node: ast.AST) -> ast.expr | None:
    if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    body = getattr(node, "body", [])
    first = body[0] if body else None
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        return first.value
    return None


def _docstrings(tree: ast.AST) -> set[int]:
    constants = (_docstring_constant(node) for node in ast.walk(tree))
    return {id(constant) for constant in constants if constant is not None}


def _names_registry(value: str) -> bool:
    """A path-shaped string naming a guarded registry.

    The bare directory is not judged as a string: `startswith("verification/policy/")`
    classifies a changed path, which is not a read. Built into a path it is judged, below.
    """
    if any(ch.isspace() for ch in value):
        return False
    return "/" in value and value.endswith(_GUARDED_FILES)


def _is_div(node: ast.AST) -> bool:
    return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)


def _is_path_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Path" and bool(node.args)
    )


def _div_chain(node: ast.AST) -> list[str]:
    """The string constants of a `a / "b" / "c"` path expression, left to right."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _div_chain(node.left) + _div_chain(node.right)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if _is_path_call(node):
        return _div_chain(node.args[0])
    return []


@dataclass(frozen=True)
class _Scan:
    """What a walk over one source needs to judge each node."""

    label: str
    docstrings: set[int]
    #: The left operands of `/`: only a whole path expression is judged, and
    #: `a / "verification" / "policy"` is the left operand of `... / "toolchains.lock.toml"`,
    #: not a path of its own there.
    inner: set[int]
    exempt: frozenset[str]


def _scan_of(tree: ast.AST, label: str) -> _Scan:
    return _Scan(
        label=label,
        docstrings=_docstrings(tree),
        inner={id(node.left) for node in ast.walk(tree) if _is_div(node)},
        exempt=frozenset(
            rel for rel, owner in GENERATED_OWNERS.items() if Path(label).name == owner
        ),
    )


def _names_policy_path(joined: str, exempt: frozenset[str]) -> bool:
    return bool(
        _POLICY_TAIL.search(joined)
        or ("verification/policy/" in joined and joined.endswith(_GUARDED_FILES))
        or _names_generated(joined, exempt)
    )


def _names_policy_dir_or_table(value: str, exempt: frozenset[str]) -> bool:
    return bool(_POLICY_TAIL.search(value) or _names_generated(value, exempt))


def _div_problem(scan: _Scan, node: ast.AST) -> str | None:
    parts = _div_chain(node)
    joined = "/".join(part.strip("/") for part in parts)
    if parts and _names_policy_path(joined, scan.exempt):
        return f"{scan.label}:{node.lineno}: builds the path {joined!r}"
    return None


def _call_problem(scan: _Scan, node: ast.Call) -> str | None:
    parts = _div_chain(node.args[0])
    if len(parts) == 1 and _names_policy_dir_or_table(parts[0], scan.exempt):
        return f"{scan.label}:{node.lineno}: builds the path {parts[0]!r}"
    return None


def _constant_problem(scan: _Scan, node: ast.Constant) -> str | None:
    if _names_registry(node.value) or _names_generated(node.value, scan.exempt):
        return f"{scan.label}:{node.lineno}: names the path {node.value!r}"
    return None


def _node_problem(scan: _Scan, node: ast.AST) -> str | None:
    if _is_div(node):
        return None if id(node) in scan.inner else _div_problem(scan, node)
    if _is_path_call(node):
        return _call_problem(scan, node)
    is_text = isinstance(node, ast.Constant) and isinstance(node.value, str)
    if is_text and id(node) not in scan.docstrings:
        return _constant_problem(scan, node)
    return None


def source_problems(source: str, label: str) -> list[str]:
    """Where `source` spells a guarded registry's path instead of asking `_registries`.

    A path to the policy directory, or to a guarded registry, written as a string or built
    with `/`. Prose is not a reader: a docstring, or a string with whitespace in it, is a
    sentence about a registry rather than a path to one.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"{label}: unreadable Python ({exc.msg}, line {exc.lineno})"]
    scan = _scan_of(tree, label)
    found = (_node_problem(scan, node) for node in ast.walk(tree))
    return sorted({problem for problem in found if problem is not None})


def reader_problems(root: Path = REPO_ROOT) -> list[str]:
    """Every production reader that reaches a guarded registry around `_registries`, or a
    guarded generated table around its owner."""
    out: list[str] = []
    for file in _production_sources(root):
        label = file.relative_to(root).as_posix()
        out += source_problems(file.read_text(encoding="utf-8"), label)
    return out
