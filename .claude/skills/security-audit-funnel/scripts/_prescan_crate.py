"""Rust crate discovery and role resolution for the structural pre-scan."""

import os

from _prescan_classify import base_role


def find_crate_root(path):
    d = os.path.dirname(os.path.abspath(path))
    while True:
        if os.path.isfile(os.path.join(d, "Cargo.toml")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def _is_bin_crate(crate_root):
    if os.path.isfile(os.path.join(crate_root, "src", "main.rs")) or \
            os.path.isdir(os.path.join(crate_root, "src", "bin")):
        return True
    try:
        with open(os.path.join(crate_root, "Cargo.toml"), encoding="utf-8") as fh:
            return "[[bin]]" in fh.read()
    except OSError:
        return False


def crate_info(crate_root, cache):
    if crate_root not in cache:
        name = os.path.basename(crate_root)
        cache[crate_root] = {
            "name": name, "is_bin": _is_bin_crate(crate_root),
            "is_demo": "demo" in name or "example" in name,
            "has_serve": False, "has_verify": False, "serve_file": None}
    return cache[crate_root]


def rust_role(path, crate_root, crates):
    pr = base_role(path)
    if pr:
        return pr
    # ONLY the binary entry points are composition roots. A crate that is lib+bin
    # (e.g. mcps-proxy) still has mostly LIBRARY files — they must NOT inherit the
    # binary's comproot checks, or every reference impl defined in the crate would
    # falsely look "wired in the comproot".
    base = os.path.basename(path)
    p = path.replace(os.sep, "/")
    if base == "main.rs" or "/src/bin/" in p:
        return "comproot"
    # Production library code lives under `<crate>/src/`. Anything else (generators,
    # benches, examples, fixture builders under conformance/, build.rs) is tooling,
    # not a shipped path — exclude it from the production floor.
    if "/src/" not in p or base == "build.rs":
        return "script"
    return "library"
