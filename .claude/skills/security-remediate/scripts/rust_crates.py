"""The workspace's Rust crates and module files, read from the Bazel library targets."""
from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterator

#: One Rust library target's attribute block in a BUILD file.
_LIBRARY = re.compile(r"^(?:nt_)?rust_library\((.*?)^\)", re.M | re.S)
_CRATE_NAME = re.compile(r'\bcrate_name\s*=\s*"([^"]+)"')
_TARGET_NAME = re.compile(r'\bname\s*=\s*"([^"]+)"')


def _library_crates(root: str, build: str) -> Iterator[tuple[str, str]]:
    """(crate ident, crate dir) for each library in `build`, rooted at its `src/lib.rs`."""
    d = os.path.dirname(build)
    if not os.path.isfile(os.path.join(root, d, "src", "lib.rs")):
        return
    with open(os.path.join(root, build), encoding="utf-8") as fh:
        text = fh.read()
    for block in _LIBRARY.findall(text):
        m = _CRATE_NAME.search(block) or _TARGET_NAME.search(block)
        if m:
            yield m.group(1).replace("-", "_"), d


class CrateIndex:
    """Crate ident -> crate dir (repo-relative), plus module path <-> file lookups.

    A library's crate is its `crate_name` (or its target name), rooted at its package's
    `src/lib.rs`. Every flavor of one library names the same crate.
    """

    def __init__(self, root: str) -> None:
        self.root = root
        self.crates: dict[str, str] = {}
        listing = subprocess.run(["git", "ls-files", "*BUILD.bazel", "*BUILD"], cwd=root,
                                 capture_output=True, text=True)
        for build in listing.stdout.split():
            for ident, d in _library_crates(root, build):
                self.crates.setdefault(ident, d)

    def crate_of(self, path: str) -> str | None:
        """The crate whose `src/` holds `path`; the deepest wins."""
        owners = [(ident, d) for ident, d in self.crates.items() if path.startswith(d + "/src/")]
        return max(owners, key=lambda owner: len(owner[1]))[0] if owners else None

    def module_path(self, path: str) -> list[str]:
        ident = self.crate_of(path)
        rel = path[len(self.crates[ident]) + len("/src/"):] if ident else path
        parts = rel[:-3].split("/")
        if parts[-1] in ("lib", "main", "mod"):
            parts = parts[:-1]
        return parts

    def module_file(self, crate: str, mod: list[str]) -> str | None:
        src = os.path.join(self.crates[crate], "src")
        base = os.path.join(src, *mod)
        cands = [os.path.join(src, "lib.rs")] if not mod else \
            [base + ".rs", os.path.join(base, "mod.rs")]
        return next((c for c in cands if os.path.isfile(os.path.join(self.root, c))), None)
