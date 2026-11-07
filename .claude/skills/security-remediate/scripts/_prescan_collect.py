"""Source discovery: walk the tree, read each Python and Rust file once, resolve its
role and keep the production slice of Rust sources."""

import os
from dataclasses import dataclass, field

from _prescan_classify import language, python_role
from _prescan_crate import crate_info, find_crate_root, rust_role
from _prescan_rust_text import rust_prod_slice
from _prescan_vocab import NON_PROD_ROLES, VENDOR_DIRS


@dataclass
class Sources:
    py_files: list = field(default_factory=list)    # (path, src, role)
    rs_files: list = field(default_factory=list)    # (path, prod_src, role, crate_root)
    crates: dict = field(default_factory=dict)
    roles_seen: dict = field(default_factory=dict)

    def see(self, role):
        self.roles_seen[role] = self.roles_seen.get(role, 0) + 1


def _read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def _is_first_party_dir(name):
    return (name not in VENDOR_DIRS and not name.startswith(".venv")
            and not name.startswith("bazel-"))


def _add_python(sources, path, src):
    role = python_role(path, src)
    sources.see(role)
    sources.py_files.append((path, src, role))


def _add_rust(sources, path, src):
    crate_root = find_crate_root(path)
    if crate_root:
        crate_info(crate_root, sources.crates)
    role = rust_role(path, crate_root, sources.crates)
    sources.see(role)
    if role not in NON_PROD_ROLES:
        sources.rs_files.append((path, rust_prod_slice(src), role, crate_root))


def collect_sources(root):
    sources = Sources()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if _is_first_party_dir(d)]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            lang = language(path)
            src = _read(path) if lang else None
            if src is None:
                continue
            (_add_python if lang == "python" else _add_rust)(sources, path, src)
    return sources
