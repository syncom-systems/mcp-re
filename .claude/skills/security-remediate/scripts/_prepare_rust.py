"""What `prepare` knows about a Rust file: module, crate, re-exports, tests, size."""
from __future__ import annotations

import importlib.util
import os
import re

from _prepare_symbols import RUST_TEST_REGION

SIZE_GATE = "scripts/module_size_gate.py"


def rust_module(path: str) -> str:
    """The module name other files write in a path to `path`'s items."""
    stem = os.path.splitext(os.path.basename(path))[0]
    return os.path.basename(os.path.dirname(path)) if stem in ("mod", "lib", "main") else stem


def component_root(path: str) -> str:
    """The component/application directory: the parent of the `src` segment."""
    parts = path.split("/")
    if "src" in parts:
        return "/".join(parts[:parts.index("src")])
    return os.path.dirname(path)


def rust_crate(path: str) -> str | None:
    """The crate `path` belongs to, as the Bazel library targets name it."""
    from rust_resolver import RustResolver  # noqa: PLC0415
    return RustResolver(".").crate_of(path)


def rs_binds(cand: str, own: str, src: str) -> bool:
    """Whether `cand` can name `own`'s items: it sits in the same module directory
    (`super::` / sibling access) or spells the module in a path. A heuristic, not
    name resolution — a glob re-export through a third module is missed."""
    if os.path.dirname(cand) == os.path.dirname(own):
        return True
    mod = rust_module(own)
    if re.search(r"\b%s::|::%s\b" % (re.escape(mod), re.escape(mod)), src):
        return True
    # Another crate reaching the item through the crate root's re-export.
    crate = rust_crate(own) or ""
    return bool(crate) and not cand.startswith(component_root(own) + "/src/") \
        and re.search(r"\b%s::" % re.escape(crate), src) is not None


def _reexported_names(src: str, mod: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(r"pub use (?:crate::|self::)?%s::(\{[^}]*\}|\w+)" % mod, src):
        for item in m.group(1).strip("{}").split(","):
            name = item.strip().split(" as ")[-1].strip()
            if re.fullmatch(r"[A-Za-z_]\w*", name) and name != "self":
                out.append(name)
    return out


def root_reexports(path: str) -> list[str]:
    """Names the crate root (`src/lib.rs` or `src/main.rs`) re-exports from `path`'s
    module: `pub use <module>::Name;` and `pub use <module>::{A, B as C};`."""
    root = component_root(path) or "."
    mod = re.escape(rust_module(path))
    out: list[str] = []
    for crate_root in ("src/lib.rs", "src/main.rs"):
        try:
            src = open(os.path.join(root, crate_root), encoding="utf-8").read()
        except OSError:
            continue
        out += _reexported_names(src, mod)
    return sorted(set(out))


def all_ignored(test_file: str) -> bool:
    """Whether every test in `test_file` carries `#[ignore]` (a live-infrastructure
    suite): naming its target as `--it` compiles it and runs zero tests."""
    try:
        src = open(test_file, encoding="utf-8").read()
    except OSError:
        return False
    tests = len(re.findall(r"#\[(?:tokio::)?test\b", src))
    return tests > 0 and len(re.findall(r"#\[ignore\b", src)) >= tests


def it_target(root: str, test_file: str) -> str:
    """The Bazel test target(s) a file under `<root>/tests/` is compiled into, as the
    labels `--it` takes. A shared module (`tests/<dir>/…`) can belong to several."""
    import rust_gate  # noqa: PLC0415 — only the Rust branch needs the build graph
    labels = [t for t in rust_gate.compiling_targets([test_file])
              if t in set(rust_gate.query('kind("^rust_test rule$", //%s/...)' % root))]
    return ",".join(labels) or "(no Bazel test target compiles it)"


def rust_inline_tests(src: str) -> int:
    """`#[test]` functions inside the file's own test region."""
    m = RUST_TEST_REGION.search(src)
    return len(re.findall(r"#\[(?:tokio::)?test\b", src[m.start():])) if m else 0


def _size_gate():
    spec = importlib.util.spec_from_file_location("module_size_gate", SIZE_GATE)
    if spec is None or spec.loader is None:
        return None
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate


def module_size(path: str, src: str) -> str | None:
    """The module-size ratchet's view of this file, from the gate's own counter —
    so a fix is sized against the limit the per-file gate will enforce."""
    if not os.path.isfile(SIZE_GATE):
        return None
    gate = _size_gate()
    if gate is None:
        return None
    loc = gate.production_lines(src)
    entry = gate.load_registry(gate.REGISTRY).get(path)
    if entry:
        base = entry.get("baseline_prod_loc")
        return ("%d production lines; registered %s at baseline %s — headroom %d, and the "
                "gate fails the file if it grows past the baseline"
                % (loc, entry.get("status"), base, (base or 0) - loc))
    return ("%d production lines; threshold %d — headroom %d%s"
            % (loc, gate.THRESHOLD, gate.THRESHOLD - loc,
               "" if loc <= gate.THRESHOLD else " (OVER: already failing?)"))
