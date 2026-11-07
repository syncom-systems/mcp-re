"""Which instances a composition root drives as long-running tasks, and whether a
Noop it constructs sits under a documented production-refusal guard."""

import ast

from _prescan_pyast import callee_name, terminal_name

_TASK_DRIVER_METHODS = {"run", "start", "serve", "run_forever", "main", "loop"}
_TEARDOWN_METHODS = {"stop", "shutdown"}
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _task_target(inner):
    """(driven_expr, wrapper_name, wrapper_first_arg) for the argument of a
    ``create_task(...)`` call:
      - ``create_task(X.run())``       -> (X, None, None)
      - ``create_task(wrap(inst,..))`` -> (None, "wrap", inst)
      - ``create_task(Cls(...).run())``-> (Cls(...)-call, None, None)
    """
    if not isinstance(inner, ast.Call):
        return inner, None, None
    fn = inner.func
    if isinstance(fn, ast.Attribute) and fn.attr in _TASK_DRIVER_METHODS:
        return fn.value, None, None
    return None, callee_name(inner), inner.args[0] if inner.args else None


def _is_create_task(node):
    return (isinstance(node, ast.Call) and node.args
            and callee_name(node) == "create_task")


def _create_task_driven_exprs(tree):
    for node in ast.walk(tree):
        if _is_create_task(node):
            yield _task_target(node.args[0])


def _driven_identifier(driven, wrapper, wrapper_arg):
    """(is_class, identifier) of what one create_task drives. A construction inside
    the task (``create_task(Cls().run())``) names the class directly; a wrapper
    coroutine drives its first argument."""
    if driven is not None:
        if isinstance(driven, ast.Call):
            return True, callee_name(driven)
        return False, terminal_name(driven)
    if wrapper_arg is not None and wrapper is not None:
        return False, terminal_name(wrapper_arg)
    return False, None


def _is_teardown_call(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in _TEARDOWN_METHODS)


def _task_driven(tree):
    """(names, classes) behind every ``create_task(...)``."""
    names, classes = set(), set()
    for target in _create_task_driven_exprs(tree):
        is_class, identifier = _driven_identifier(*target)
        if identifier:
            (classes if is_class else names).add(identifier)
    return names, classes


def _torn_down(tree):
    """Names of every ``X.stop()`` / ``X.shutdown()`` receiver."""
    receivers = (terminal_name(node.func.value)
                 for node in ast.walk(tree) if _is_teardown_call(node))
    return {name for name in receivers if name}


def py_lifecycle_driven_names(tree):
    """(names, classes) this comproot module *drives* as a long-running task: the
    instance behind every ``create_task(...)``, plus every ``await X.stop()``
    (lifecycle teardown is start-symmetric evidence)."""
    names, classes = _task_driven(tree)
    return names | _torn_down(tree), classes


def _constructs(fn, cls_name):
    return any(callee_name(c) == cls_name for c in ast.walk(fn))


def _has_raise(fn):
    return any(isinstance(r, ast.Raise) for r in ast.walk(fn))


def comproot_construction_guard(tree, cls_name):
    """True iff every textual *construction* of ``cls_name`` in this module sits
    under a documented production-refusal guard — i.e. the same function body
    that constructs it also ``raise``s (the fail-closed `is_production()` path
    that refuses the Noop). Such a Noop is an explicitly-refused fallback, NOT
    the production wiring, so it must not BLOCK."""
    functions = (fn for fn in ast.walk(tree) if isinstance(fn, _FUNCTIONS))
    return all(_has_raise(fn) for fn in functions if _constructs(fn, cls_name))
