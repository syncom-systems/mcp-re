"""Python service analyzer: composition-root, dead-wiring, Noop-in-comproot and
inbound-auth checks. Gated so they only BLOCK when the tree is a service."""

import ast
import os
from dataclasses import dataclass, field

from _prescan_allow import Allowlist
from _prescan_lifecycle import comproot_construction_guard, py_lifecycle_driven_names
from _prescan_classes import py_class_bases, py_class_is_abstract, py_nie_methods
from _prescan_pyast import (
    callee_name, py_alias_bindings, py_construction_bindings, terminal_name)
from _prescan_sink import Sink
from _prescan_vocab import (
    NON_PROD_ROLES, PY_AUTH_FILE_HINT, PY_AUTH_MARKERS, PY_COMPROOT_HINT,
    PY_COMPROOT_NAMES, PY_ENDPOINT_MARKERS, PY_INBOUND_AUTH_WIRING,
    PY_LONG_RUNNER, PY_NOOP, PY_WIREABLE)


@dataclass
class _Survey:
    """What the first sweep over the parsed files learned about the tree."""
    class_defs: dict = field(default_factory=dict)
    comproot_files: list = field(default_factory=list)
    parsed: list = field(default_factory=list)
    has_endpoints: bool = False
    has_auth: bool = False

    @property
    def is_service(self):
        # The tree is a SERVICE iff it has a comproot or an HTTP surface. For a pure
        # library, dead-wiring is advisory (consumers wire it), mirroring Rust libs.
        return bool(self.comproot_files) or self.has_endpoints

    def production(self):
        for path, src, role, tree in self.parsed:
            if role not in NON_PROD_ROLES:
                yield path, src, tree

    def comproot(self):
        for path, src, tree in self.production():
            if path in self.comproot_files:
                yield path, src, tree


def _class_record(path, node):
    return {"file": path, "abstract": py_class_is_abstract(node),
            "noop": bool(PY_NOOP.match(node.name)),
            "bases": py_class_bases(node), "nie": py_nie_methods(node)}


def _note_production_file(survey, path, src, tree):
    base = os.path.basename(path)
    if base in PY_COMPROOT_NAMES or PY_COMPROOT_HINT.search(src):
        survey.comproot_files.append(path)
    if PY_ENDPOINT_MARKERS.search(src):
        survey.has_endpoints = True
    if PY_AUTH_FILE_HINT.search(base) and PY_AUTH_MARKERS.search(src):
        survey.has_auth = True
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            survey.class_defs.setdefault(node.name, _class_record(path, node))


def _survey(py_files):
    survey = _Survey()
    for path, src, role in py_files:
        try:
            tree = ast.parse(src, filename=path)
        except (SyntaxError, ValueError):
            continue
        survey.parsed.append((path, src, role, tree))
        if role not in NON_PROD_ROLES:
            _note_production_file(survey, path, src, tree)
    return survey


def _interfaces(bases):
    """The I-prefixed interface names among a class's bases."""
    return {b for b in bases if b.startswith("I") and len(b) > 1 and b[1:2].isupper()}


def _constructed_classes(tree, class_defs):
    return {cls for cls in map(callee_name, ast.walk(tree)) if cls in class_defs}


def _real_interfaces_in(tree, class_defs):
    real = set()
    for cls in _constructed_classes(tree, class_defs):
        if not class_defs[cls]["noop"]:
            real |= _interfaces(class_defs[cls]["bases"])
    return real


def _comproot_real_interfaces(survey):
    """Interfaces with a real (non-Noop) impl constructed in the comproot set. A Noop
    of such an interface is the refused fallback, not the production wiring."""
    real = set()
    for _path, _src, tree in survey.comproot():
        real |= _real_interfaces_in(tree, survey.class_defs)
    return real


def _construction_bindings(survey, long_runners):
    """Identifier -> long-runner classes it is bound to a construction of, across ALL
    production files: the instance a comproot drives is often reached through a
    builder's returned-object attribute, so the class name never appears there."""
    bindings = {}
    for _path, _src, tree in survey.production():
        for ident, classes in py_construction_bindings(tree, long_runners).items():
            bindings.setdefault(ident, set()).update(classes)
    return bindings


def _bound_classes(bindings, aliases, name):
    """Classes a driven name resolves to, directly or through one alias hop."""
    bound = set()
    for candidate in (name, aliases.get(name)):
        if candidate:
            bound |= bindings.get(candidate, set())
    return bound


def _started_long_runners(survey, long_runners):
    """Long-runner classes a comproot starts as a task or stops on teardown."""
    bindings = _construction_bindings(survey, long_runners)
    started = set()
    for _path, _src, tree in survey.comproot():
        names, classes = py_lifecycle_driven_names(tree)
        aliases = py_alias_bindings(tree)
        started |= classes & long_runners
        for name in names:
            started |= _bound_classes(bindings, aliases, name) & long_runners
    return started


def _referenced_names(tree):
    return {name for name in map(terminal_name, ast.walk(tree)) if name}


@dataclass
class _Wiring:
    """How each class is reached from production files and from the comproot."""
    prod_refs: dict       # class -> production files referencing it elsewhere
    comproot_refs: dict   # class -> reference count inside the comproot files
    started: set          # long-runners the comproot starts
    is_service: bool
    sink: Sink

    @property
    def severity(self):
        return "block" if self.is_service else "warn"

    def unreferenced(self, name, info):
        rel = os.path.relpath(info["file"], self.sink.root)
        return not self.prod_refs[name] and not self.sink.allows(
            "dead-wired", rel, name, None)

    def never_started(self, name):
        return (self.comproot_refs[name] == 0 and bool(PY_LONG_RUNNER.search(name))
                and name not in self.started)


def _reference_counts(survey):
    class_defs = survey.class_defs
    prod_refs = {n: set() for n in class_defs}
    comproot_refs = {n: 0 for n in class_defs}
    for path, _src, tree in survey.production():
        for name in _referenced_names(tree) & class_defs.keys():
            if path != class_defs[name]["file"]:
                prod_refs[name].add(path)
            if path in survey.comproot_files:
                comproot_refs[name] += 1
    return prod_refs, comproot_refs


def _is_substituting_noop(info, tree, name, real_ifaces):
    """A Noop CONSTRUCTED (not merely imported or annotated) in a comproot is the
    production wiring unless a documented refusal guard raises around it or a real
    impl of the same interface is constructed there."""
    return (info["noop"] and not comproot_construction_guard(tree, name)
            and not _interfaces(info["bases"]) & real_ifaces)


def _noop_wirings(survey, real_ifaces, root):
    class_defs = survey.class_defs
    return [(name, os.path.relpath(path, root))
            for path, _src, tree in survey.comproot()
            for name in _constructed_classes(tree, class_defs)
            if _is_substituting_noop(class_defs[name], tree, name, real_ifaces)]


def _report_class(name, info, wiring):
    sink = wiring.sink
    if PY_WIREABLE.search(name):
        if wiring.unreferenced(name, info):
            sink.add("dead-wired", wiring.severity, name, info["file"], None,
                     "Orchestration class is never referenced in any production file "
                     "outside its own definition." + ("" if wiring.is_service else
                     " (advisory: this tree is a library; consumers may wire it.)"))
        elif wiring.never_started(name):
            sink.add("not-in-comproot", wiring.severity, name, info["file"], None,
                     "Long-running class referenced in production but never in the "
                     "composition root / lifespan — likely constructed but never "
                     "started.")
    if info["nie"]:
        sink.add("stub-method", "warn", name, info["file"], None,
                 "Concrete class has NotImplementedError-only method(s): "
                 + ", ".join(info["nie"]))


def _report_noops(wired, sink):
    for name, rel in sorted(set(wired)):
        sink.add("noop-in-comproot", "block", name, os.path.join(sink.root, rel),
                 None,
                 "Noop/Null/InMemory implementation instantiated and wired as the "
                 "production implementation in the composition root, with no real "
                 "alternative of the same interface and no documented prod-refusal "
                 "guard — a real implementation is likely being silently "
                 "substituted.")


def _inbound_auth_wired(survey):
    """A PEP install / scope guard / auth-verification-scope middleware anywhere in
    the comproot set counts, whatever the file is called (services wire their inbound
    PEP from main.py/app.py, not from a file literally named `*auth*`)."""
    return survey.has_auth or any(
        PY_INBOUND_AUTH_WIRING.search(src) for _path, src, _tree in survey.comproot())


def _report_http_surface(survey, sink):
    if not survey.has_endpoints:
        return
    if not _inbound_auth_wired(survey):
        sink.add("no-inbound-auth", "block", "<http surface>", None, None,
                 "Service exposes HTTP endpoints but no inbound authentication is "
                 "wired in any middleware or composition-root file.")
    else:
        sink.add("auth-manual-verify", "warn", "<http surface>", None, None,
                 "Auth wiring present, but Stage 1 cannot tell it actually enforces. "
                 "Stage 2 must confirm endpoints are genuinely gated.")


def python_pass(py_files, root, add, allow):
    """py_files: list of (path, src, role). Mirrors the original prescan; gated so
    composition-root/dead-wiring checks only BLOCK when the tree is a service."""
    sink = Sink(root, add, Allowlist(allow))
    survey = _survey(py_files)
    class_defs = survey.class_defs
    long_runners = {n for n, i in class_defs.items()
                    if PY_LONG_RUNNER.search(n) and not i["abstract"]}
    prod_refs, comproot_refs = _reference_counts(survey)
    wiring = _Wiring(prod_refs, comproot_refs,
                     _started_long_runners(survey, long_runners),
                     survey.is_service, sink)
    wired = _noop_wirings(survey, _comproot_real_interfaces(survey), root)
    for name, info in sorted(class_defs.items()):
        if not (info["abstract"] or info["noop"]):
            _report_class(name, info, wiring)
    _report_noops(wired, sink)
    _report_http_surface(survey, sink)
