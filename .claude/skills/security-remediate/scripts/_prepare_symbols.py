"""The top-level public names a file defines, and which of them findings mention."""
from __future__ import annotations

import ast
import re

# Column-0 items only: an indented `pub fn new` is a method, not a name another file binds.
_RUST_DECL = re.compile(r"^pub(?:\([^)]*\))?\s+(?:struct|enum|trait|fn|type|const|static)\s+([A-Za-z_]\w*)", re.M)
RUST_TEST_REGION = re.compile(r"^#\[cfg\((?:all\()?test", re.M)


def _assigned_names(node: ast.AST) -> list[str]:
    """Constants and type aliases bind across files; `logger` does not."""
    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return []
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [t.id for t in targets if isinstance(t, ast.Name) and t.id[:1].isupper()]


def _python_names(src: str) -> list[str]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    names: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(node.name)
        names += _assigned_names(node)
    return names


def defined_symbols(path: str, src: str) -> list[str]:
    """Top-level public names the file defines — what other files can bind to."""
    names: list[str] = []
    if path.endswith(".py"):
        names = _python_names(src)
    elif path.endswith(".rs"):
        m = RUST_TEST_REGION.search(src)
        names = _RUST_DECL.findall(src[:m.start()] if m else src)
    seen: set[str] = set()
    return [n for n in names if not n.startswith("_") and not (n in seen or seen.add(n))]


def prioritise(symbols: list[str], findings: list[dict]) -> list[str]:
    """Symbols a finding mentions come first: those are the ones being judged."""
    text = " ".join(" ".join(str(f.get(k) or "") for k in ("title", "claim", "evidence_anchor"))
                    for f in findings)
    named = [s for s in symbols if re.search(r"\b%s\b" % re.escape(s), text)]
    return named + [s for s in symbols if s not in named]
