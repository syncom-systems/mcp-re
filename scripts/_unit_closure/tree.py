"""The module tree: which files a unit measures and which module declares which."""

from __future__ import annotations

from pathlib import Path

from _module_tree import children, is_mod_rs_name
from _rust_source import production_view
from _unit_closure.config import ITEM


def expand(root: Path, patterns) -> set[str]:
    """The repo-relative files a `paths` list names, with its globs expanded.

    Mirrors `tools/verification/_boundary_crossings.py::expand_paths`, which is not reused directly
    because it resolves against a module-level `REPO_ROOT` and this gate must run against a
    synthetic tree. The two are held to the same answer by `expansion_disagreements`, which
    runs on every real invocation — a mirror checked by measurement rather than by promise.
    """
    out: set[str] = set()
    for pattern in patterns:
        for path in root.glob(pattern):
            if path.is_file():
                out.add(path.relative_to(root).as_posix())
    return out


def closure(root: Path, units) -> dict[str, list[str]]:
    """Every file inside some unit's expanded `paths`, with the units that measure it."""
    covered: dict[str, list[str]] = {}
    for unit in units:
        for rel in sorted(expand(root, unit["paths"])):
            covered.setdefault(rel, []).append(unit["id"])
    return covered


def module_children(root: Path, rel: str) -> list[tuple[str, str]]:
    """`(module name, file)` for every `mod <name>;` in `rel` that resolves on disk.

    A declaration that resolves to no file is not this gate's finding: rustc cannot
    compile it either, and `bazel_srcs_gate.py` is the control that says so.
    """
    path = root / rel
    return [
        (child.declaration.name, child.file.relative_to(root).as_posix())
        for child in children(path, mod_rs=is_mod_rs_name(path))
        if child.file is not None
    ]


def _container_and_name(path: Path) -> tuple[Path, str] | None:
    """The directory whose module declares `path`, and the name it declares; None for a
    crate root, which no module declares."""
    if path.name in ("lib.rs", "main.rs"):
        return None
    is_mod_rs = path.name == "mod.rs"
    container = path.parent.parent if is_mod_rs else path.parent
    if container.name == "bin":
        return None  # `src/bin/*.rs` are crate roots of their own
    return container, path.parent.name if is_mod_rs else path.stem


def _declarer_candidates(container: Path) -> list[Path]:
    if container.name == "src":
        return [container / "lib.rs", container / "main.rs"]
    return [container / "mod.rs", container.parent / f"{container.name}.rs"]


def _declares_file(root: Path, candidate: Path, rel: str) -> bool:
    """Whether `candidate`'s own `mod` declarations resolve to the file `rel`."""
    if not candidate.is_file():
        return False
    target = (root / rel).resolve()
    return any(
        child.file is not None and child.file.resolve() == target
        for child in children(candidate, mod_rs=is_mod_rs_name(candidate))
    )


def parent_module(root: Path, rel: str) -> str | None:
    """The module file that declares `rel`, or None when nothing does.

    Resolution is rustc's, then CONFIRMED by reading the candidate's own `mod`
    declarations. Confirming matters where a crate has both `lib.rs` and `main.rs`: which
    of the two declares a given top-level module is a fact in the source, not one the
    directory layout reveals, and a gate that guessed would flag a parent that declares
    nothing.
    """
    located = _container_and_name(Path(rel))
    if located is None:
        return None
    for candidate in _declarer_candidates(located[0]):
        if not candidate.is_absolute():
            candidate = root / candidate
        if _declares_file(root, candidate, rel):
            return candidate.relative_to(root).as_posix()
    return None


def declares_items(root: Path, rel: str) -> bool:
    """Whether `rel` declares an item of its own outside a test region.

    False for a namespace — a file whose whole body is `mod` and `pub use`. The test region
    is excluded through `_rust_source.production_view`, the one owner of where a region
    ends, and comments and string literals are blanked so that an item named in prose is
    not an item.
    """
    text = (root / rel).read_text(errors="replace")
    return bool(ITEM.search(production_view(text).code()))
