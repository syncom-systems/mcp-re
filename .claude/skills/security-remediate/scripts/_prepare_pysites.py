"""Python use sites: where a file binds a symbol from a package, read from the AST."""
from __future__ import annotations

import ast


def _from_pkg(node: ast.ImportFrom, pkg: str, same_pkg: bool) -> bool:
    mod = node.module or ""
    return mod == pkg or mod.startswith(pkg + ".") or (node.level > 0 and same_pkg)


def _bound_name(tree: ast.AST, sym: str, pkg: str, same_pkg: bool) -> tuple[str | None, list[int]]:
    """The local name `sym` is bound to by an import from `pkg`, and the import lines."""
    local = None
    imports: list[int] = []
    package_imports = [n for n in ast.walk(tree)
                       if isinstance(n, ast.ImportFrom) and _from_pkg(n, pkg, same_pkg)]
    for node in package_imports:
        for al in [a for a in node.names if a.name == sym]:
            local = al.asname or sym
            imports.append(node.lineno)
    return local, imports


def _name_ids(tree: ast.AST, local: str) -> set[int]:
    return {id(n) for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == local}


def _call_func_id(node: ast.AST, local: str) -> set[int]:
    """The id of the callee Name when `node` is a call of `local`, else nothing."""
    func = node.func if isinstance(node, ast.Call) else None
    return {id(func)} if isinstance(func, ast.Name) and func.id == local else set()


def _base_and_call_ids(tree: ast.AST, local: str) -> tuple[set[int], set[int]]:
    bases: set[int] = set()
    calls: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases.update(*(_name_ids(b, local) for b in node.bases))
        else:
            calls |= _call_func_id(node, local)
    return bases, calls


def py_sites(sym: str, cand: str, pkg: str, src: str) -> list[tuple[str, int]]:
    """(kind, line) for every use of `sym` in `cand` — IF `cand` binds it from `pkg`.

    A bare name match is not a use: `Scope` is also Starlette's, and `grep -w`
    counted 155 unrelated production sites for it. A file is bound only by an
    import of the name from this package (absolute, a barrel, or relative inside
    the package); only then are its Name/Attribute nodes this symbol. Mentions in
    docstrings and comments are not nodes, so they no longer count as uses.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    local, imports = _bound_name(tree, sym, pkg, ("/src/%s/" % pkg) in cand)
    if local is None:
        return []
    out = [("import", ln) for ln in imports]
    bases, calls = _base_and_call_ids(tree, local)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == local:
            kind = "subclass" if id(node) in bases else "construct" if id(node) in calls else "ref"
            out.append((kind, node.lineno))
    return out
