# SPDX-License-Identifier: Apache-2.0
"""Provider findings and the repository files reached, for one Python file."""

from __future__ import annotations

import ast
from pathlib import Path

from _provider_neutral.config import (
    CLOUD_SDK_MODULES,
    CREDENTIAL_VARS,
    PROVIDER_CLIS,
    PY_IMPORT_DIRS,
    Result,
)
from _provider_neutral.shell import normalize

_PROCESS_MODULES = {"subprocess", "os", "shutil"}
_PROCESS_FUNCTIONS = {"run", "check_call", "check_output", "Popen", "call"}


def _is_process_call(func: ast.expr) -> bool:
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id in _PROCESS_MODULES
    return isinstance(func, ast.Name) and func.id in _PROCESS_FUNCTIONS


def _strings(node: ast.AST) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _is_environ(node: ast.expr) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "environ"


def _reads_environment(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "getenv":
        return True
    return isinstance(func, ast.Attribute) and func.attr == "get" and _is_environ(func.value)


def _is_cloud_sdk(name: str) -> bool:
    return any(name == m or name.startswith(m + ".") for m in CLOUD_SDK_MODULES)


def _import_edges(name: str, here: str, repo_files: set[str]) -> set[str]:
    candidates = (f"{base}/{name.replace('.', '/')}.py" for base in (here, *PY_IMPORT_DIRS))
    return {candidate for candidate in candidates if candidate in repo_files}


def _imported_names(node: ast.Import | ast.ImportFrom) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    return [node.module or ""]


def _import_result(node: ast.Import | ast.ImportFrom, here: str, repo_files: set[str]) -> Result:
    findings: list[str] = []
    edges: set[str] = set()
    for name in _imported_names(node):
        if _is_cloud_sdk(name):
            findings.append(f"cloud SDK import ({name})")
        edges |= _import_edges(name, here, repo_files)
    return findings, edges


def _program_of(values: list[str]) -> str:
    words = values[0].split() if values else []
    return words[0] if words else ""


def _process_result(call: ast.Call, repo_files: set[str]) -> Result:
    """A call that runs a program: is the program a provider CLI, and which repository files does it name."""
    values = _strings(call)
    program = _program_of(values)
    findings = []
    if program.rsplit("/", 1)[-1] in PROVIDER_CLIS:
        findings.append(f"provider CLI as a process ({program}) at line {call.lineno}")
    return findings, {found for value in values if (found := normalize(value, repo_files))}


def _credential_reads(node: ast.Call | ast.Subscript, values: list[str]) -> list[str]:
    return [
        f"cloud credential read ({value}) at line {node.lineno}"
        for value in values
        if CREDENTIAL_VARS.fullmatch(value)
    ]


def _call_result(call: ast.Call, repo_files: set[str]) -> Result:
    findings: list[str] = []
    edges: set[str] = set()
    if _is_process_call(call.func):
        findings, edges = _process_result(call, repo_files)
    if _reads_environment(call):
        findings += _credential_reads(call, _strings(call))
    return findings, edges


def _subscript_result(node: ast.Subscript) -> Result:
    if not _is_environ(node.value):
        return [], set()
    return _credential_reads(node, _strings(node.slice)), set()


def _node_result(node: ast.AST, here: str, repo_files: set[str]) -> Result:
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return _import_result(node, here, repo_files)
    if isinstance(node, ast.Call):
        return _call_result(node, repo_files)
    if isinstance(node, ast.Subscript):
        return _subscript_result(node)
    return [], set()


def python_findings_and_edges(text: str, path: str, repo_files: set[str]) -> Result:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return [f"cannot parse as Python ({exc.msg}); a closure file this gate cannot read is not neutral"], set()
    here = str(Path(path).parent)
    findings: list[str] = []
    edges: set[str] = set()
    for node in ast.walk(tree):
        node_findings, node_edges = _node_result(node, here, repo_files)
        findings += node_findings
        edges |= node_edges
    return findings, edges
