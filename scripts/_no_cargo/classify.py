# SPDX-License-Identifier: Apache-2.0
"""Which reader applies to which tracked file, and the scan that runs them."""

from __future__ import annotations

import subprocess
from collections.abc import Callable

from _no_cargo.config import COMMAND_DOCS, HISTORY, REPO, Hit
from _no_cargo.pysrc import python_hits
from _no_cargo.shell import markdown_hits, package_json_hits, shell_hits
from _no_cargo.sources import js_hits, rust_hits, toml_hits
from _no_cargo.workflow import workflow_hits

Reader = Callable[[str], list[Hit]]


def _is_workflow(path: str, name: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


def _is_shell_file(path: str, name: str) -> bool:
    named = name.startswith("Dockerfile") or name in ("Makefile", "justfile")
    return named or path.endswith((".sh", ".bash", ".sh.example"))


def _is_deploy_yaml(path: str, name: str) -> bool:
    return path.startswith("deploy/") and path.endswith((".yml", ".yaml"))


def _is_hook(path: str, name: str) -> bool:
    return name in (".pre-commit-config.yaml", "lefthook.yml") or path.startswith(".githooks/")


def _is_python(path: str, name: str) -> bool:
    return path.endswith(".py")


def _is_rust(path: str, name: str) -> bool:
    return path.endswith(".rs")


def _is_script_source(path: str, name: str) -> bool:
    return path.endswith((".js", ".mjs", ".cjs", ".ts", ".mts")) and not path.endswith(".d.ts")


def _is_package_json(path: str, name: str) -> bool:
    return name == "package.json"


def _is_registry_toml(path: str, name: str) -> bool:
    if not path.endswith(".toml"):
        return False
    return path.startswith(("verification/policy/", "config/")) or name == "pyproject.toml"


def _is_command_doc(path: str, name: str) -> bool:
    return path.endswith(".md") and bool(COMMAND_DOCS.match(path))


#: In order: the first predicate that holds names the reader.
_READERS = (
    (_is_workflow, workflow_hits),
    (_is_shell_file, shell_hits),
    (_is_deploy_yaml, shell_hits),
    (_is_hook, shell_hits),
    (_is_python, python_hits),
    (_is_rust, rust_hits),
    (_is_script_source, js_hits),
    (_is_package_json, package_json_hits),
    (_is_registry_toml, toml_hits),
    (_is_command_doc, markdown_hits),
)


def classify(path: str) -> Reader | None:
    if path.startswith(HISTORY):
        return None
    name = path.rsplit("/", 1)[-1]
    return next((reader for applies, reader in _READERS if applies(path, name)), None)


def _interpreter_reader(path: str) -> Reader | None:
    try:
        first = (REPO / path).read_text(errors="replace").split("\n", 1)[0]
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    return python_hits if "python" in first else shell_hits


def executable_scripts(files: list[str]) -> dict[str, Reader]:
    """Extensionless executables are read by their interpreter line."""
    out: dict[str, Reader] = {}
    for path in files:
        if "." in path.rsplit("/", 1)[-1] or path.startswith(HISTORY):
            continue
        reader = _interpreter_reader(path)
        if reader is not None:
            out[path] = reader
    return out


def _git_files(*args: str) -> set[str]:
    out = subprocess.run(["git", "ls-files", "-z", *args], cwd=REPO,
                         capture_output=True, text=True, check=True).stdout
    return {f for f in out.split("\0") if f}


def tracked_files() -> list[str]:
    names = _git_files("--cached", "--others", "--exclude-standard")
    # `.claude/` is ignored except the files this repository deliberately tracks, and the
    # remediation and audit skills live there; read those too.
    return sorted(names | _git_files("--cached", ".claude"))


def _path_problems(path: str, reader: Reader, read: Callable[[str], str]) -> list[str]:
    try:
        text = read(path)
    except (OSError, UnicodeDecodeError):
        return []
    out = []
    for line, rule, snippet in reader(text):
        where = f"{path}:{line}" if line else path
        out.append(f"{where}: {rule} — {snippet}")
    return out


def scan(files: list[str], read: Callable[[str], str]) -> list[str]:
    readers = executable_scripts(files)
    problems: list[str] = []
    for path in files:
        reader = classify(path) or readers.get(path)
        if reader is not None:
            problems += _path_problems(path, reader, read)
    return problems
