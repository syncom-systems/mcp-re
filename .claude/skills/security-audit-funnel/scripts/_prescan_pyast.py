"""Name resolution and binding helpers of the Python pass: terminal and callee names,
construction bindings and aliasing assignments."""

import ast


def terminal_name(expr):
    """Terminal identifier of a name/attribute chain, for binding lookup.

    ``ingestion.persister`` -> ``persister``; ``checkpoint_scheduler`` ->
    ``checkpoint_scheduler``; ``a.b.c`` -> ``c``. Returns None for anything else.
    """
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    return None


def callee_name(call):
    """Resolve the simple callee name of an ast.Call (``Foo(...)`` -> ``Foo``,
    ``mod.Foo(...)`` -> ``Foo``)."""
    if not isinstance(call, ast.Call):
        return None
    return terminal_name(call.func)


def _assignment_parts(node):
    """(targets, value) of ``name = v`` and ``name: T = v``; empty otherwise."""
    if isinstance(node, ast.Assign):
        return node.targets, node.value
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return [node.target], node.value
    return [], None


def _assignment_constructions(node):
    """(target, class) for ``name = Cls(...)`` and ``name: T = Cls(...)``."""
    targets, value = _assignment_parts(node)
    cls = callee_name(value)
    return [(terminal_name(target), cls) for target in targets] if cls else []


def _keyword_constructions(node):
    """(keyword, class) for ``f(field=Cls(...))``: a field or parameter name bound to
    a construction, as in ``Wrapper(persister=AuditStreamPersister(...))``."""
    if not isinstance(node, ast.Call):
        return []
    return [(kw.arg, callee_name(kw.value)) for kw in node.keywords
            if kw.arg and isinstance(kw.value, ast.Call)]


def _construction_pairs(tree):
    for node in ast.walk(tree):
        yield from _assignment_constructions(node)
        yield from _keyword_constructions(node)


def py_construction_bindings(tree, known_classes):
    """Map identifier -> set of known class names it is bound to a *construction*
    of, anywhere in this module. Captures the indirection forms the wiring uses to
    hand a long-runner instance to the comproot:

      name = Cls(...)                         (local assignment)
      ...(field=Cls(...))                     (keyword: attr/param name -> Cls)
      return Wrapper(field=Cls(...))          (object attribute -> Cls)

    so a comproot ``create_task(obj.field.run())`` / ``wrapper(obj.field)`` can be
    resolved back to the long-runner class ``Cls`` even when the construction
    lives in a separate builder file.
    """
    bindings = {}
    for identifier, cls in _construction_pairs(tree):
        if identifier and cls in known_classes:
            bindings.setdefault(identifier, set()).add(cls)
    return bindings


def _alias_pair(node):
    if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
        return None
    target, rhs = terminal_name(node.targets[0]), terminal_name(node.value)
    return (target, rhs) if target and rhs and target != rhs else None


def py_alias_bindings(tree):
    """Map identifier -> terminal name of its RHS for simple aliasing assigns:
        checkpoint_scheduler = checkpoint_seal_components.scheduler   (-> scheduler)
        p = ingestion.persister                                       (-> persister)
    Lets a comproot ``create_task(checkpoint_scheduler.run())`` resolve through the
    alias to the binder name (``scheduler``) and on to its long-runner class."""
    pairs = (_alias_pair(node) for node in ast.walk(tree))
    return dict(pair for pair in pairs if pair)
