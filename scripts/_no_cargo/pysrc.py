# SPDX-License-Identifier: Apache-2.0
"""Cargo invocations in Python source: argv lists, shell strings and scripts handed to a shell."""

from __future__ import annotations

import ast

from _no_cargo.config import PY_CARGO_COMMAND_LINE, SPAWNS, Hit
from _no_cargo.shell import is_cargo_word, shell_hits


def _string_list(node: ast.AST) -> list[str] | None:
    """An argv-shaped literal: each element a string, or the source of a name standing
    for one. A tuple holding a call — a table of rules, say — is not an argv."""
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return None
    if any(isinstance(elt, (ast.Call, ast.Lambda, ast.Dict)) for elt in node.elts):
        return None
    return [elt.value if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            else ast.unparse(elt) for elt in node.elts]


def _comment_hits(text: str) -> list[Hit]:
    return [
        (n, "cargo command line in a docstring or comment", line.strip())
        for n, line in enumerate(text.splitlines(), 1)
        if PY_CARGO_COMMAND_LINE.match(line)
    ]


def _string_assignment(node: ast.AST) -> tuple[list[ast.expr], str] | None:
    """(targets, text) of an assignment of one string constant, else None."""
    if not isinstance(node, ast.Assign):
        return None
    value = node.value
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return node.targets, value.value
    return None


def _bound_scripts(tree: ast.AST) -> dict[str, str]:
    """A shell script held in a name and handed to a shell by that name — `["bash", "-c",
    SCRIPT]` — is read as the script it names. Only names bound to one string constant."""
    scripts: dict[str, str] = {}
    for node in ast.walk(tree):
        assigned = _string_assignment(node)
        if assigned is None:
            continue
        targets, text = assigned
        scripts.update({t.id: text for t in targets if isinstance(t, ast.Name)})
    return scripts


def _script_note(name: str, scripts: dict[str, str]) -> str:
    return f"{name}: {scripts[name].strip()[:100]}"


def _is_charon_cargo(values: list[str]) -> bool:
    return len(values) > 1 and "charon" in values[0] and values[1] == "cargo"


def _argv_head_hit(values: list[str], node: ast.AST, line: int) -> list[Hit]:
    if is_cargo_word(values[0]):
        return [(line, "cargo argv", ast.unparse(node)[:120])]
    if _is_charon_cargo(values):
        return [(line, "charon cargo", ast.unparse(node)[:120])]
    return []


def _runs_cargo_script(flag: str, operand: str, scripts: dict[str, str]) -> bool:
    return flag == "-c" and operand in scripts and bool(shell_hits(scripts[operand]))


def _argv_hits(node: ast.AST, line: int, scripts: dict[str, str]) -> list[Hit]:
    values = _string_list(node)
    if not values:
        return []
    out = _argv_head_hit(values, node, line)
    out += [
        (line, "cargo shell script", _script_note(operand, scripts))
        for flag, operand in zip(values, values[1:])
        if _runs_cargo_script(flag, operand, scripts)
    ]
    return out


def _spawn_name(node: ast.Call) -> str:
    func = node.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


def _is_string_constant(arg: ast.AST) -> bool:
    return isinstance(arg, ast.Constant) and isinstance(arg.value, str)


def _bound_script_name(arg: ast.AST, scripts: dict[str, str]) -> str | None:
    if isinstance(arg, ast.Name) and arg.id in scripts:
        return arg.id
    return None


def _spawned_hits(arg: ast.AST, line: int, scripts: dict[str, str]) -> list[Hit]:
    """A cargo command line handed to a shell, as a string literal or as a bound script."""
    if _is_string_constant(arg):
        text = arg.value  # type: ignore[attr-defined]
        return [(line, "cargo shell string", text[:120])] if shell_hits(text) else []
    name = _bound_script_name(arg, scripts)
    if name is not None and shell_hits(scripts[name]):
        return [(line, "cargo shell script", _script_note(name, scripts))]
    return []


def _spawn_args(node: ast.AST) -> list[ast.expr]:
    """The command argument of a call that runs a command line through a shell."""
    if not isinstance(node, ast.Call) or _spawn_name(node) not in SPAWNS:
        return []
    return node.args[:1]


def _call_hits(node: ast.AST, line: int, scripts: dict[str, str]) -> list[Hit]:
    return [hit for arg in _spawn_args(node) for hit in _spawned_hits(arg, line, scripts)]


def python_hits(text: str) -> list[Hit]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return shell_hits(text)
    out = _comment_hits(text)
    scripts = _bound_scripts(tree)
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        out += _argv_hits(node, line, scripts)
        out += _call_hits(node, line, scripts)
    return out
