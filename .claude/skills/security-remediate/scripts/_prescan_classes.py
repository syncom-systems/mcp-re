"""Class shape for the Python pass: base names, abstractness and methods that only
raise NotImplementedError."""

import ast

from _prescan_pyast import terminal_name

_ABSTRACT_BASES = {"ABC", "ABCMeta", "Protocol"}
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def py_class_bases(node):
    """Names of a ClassDef's base classes (best-effort, dotted attr -> attr)."""
    return {name for name in map(terminal_name, node.bases) if name}


def py_class_is_abstract(node):
    if any(terminal_name(base) in _ABSTRACT_BASES for base in node.bases):
        return True
    if any(kw.arg == "metaclass" for kw in node.keywords):
        return True
    return any(terminal_name(deco) == "abstractmethod"
               for item in node.body for deco in getattr(item, "decorator_list", []))


def _raised_name(exc):
    if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
        return exc.func.id
    if isinstance(exc, ast.Name):
        return exc.id
    return ""


def _raises_only_not_implemented(fn):
    body = [b for b in fn.body
            if not (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant))]
    return (len(body) == 1 and isinstance(body[0], ast.Raise)
            and _raised_name(body[0].exc) == "NotImplementedError")


def py_nie_methods(node):
    return [item.name for item in node.body
            if isinstance(item, _FUNCTIONS) and _raises_only_not_implemented(item)]
