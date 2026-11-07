# SPDX-License-Identifier: Apache-2.0
"""The gate must refuse an unreviewed spawn wherever it hides and exempt only what it names."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Callable

from _owned_worker.check import check

NESTED_PRODUCTION_SPAWN = "fn go() { std::thread::spawn(|| {}); }\n"


class Fixture:
    """A temporary repository: one proxy crate with its owner module and a `plane.rs`."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.crate = root / "mcp-re-proxy"
        (self.crate / "src").mkdir(parents=True)
        (self.crate / "Cargo.toml").write_text('[package]\nname = "mcp-re-proxy"\n')
        # The owner is a subtree, so the fixture lays it out the way the tree does: the
        # exemption is `src/managed_worker/mod.rs`, not a bare file name that would keep
        # passing after the module became a directory.
        owner = self.crate / "src" / "managed_worker" / "mod.rs"
        owner.parent.mkdir(parents=True)
        owner.write_text("pub fn spawn() { std::thread::spawn(|| {}); }\n")
        self.plane = self.crate / "src" / "plane.rs"
        self.allowed = self.crate / "src" / "signing_plane" / "bounded_root_issuer.rs"
        self.nested = root / "sdk" / "python"


Step = Callable[[Fixture], str | None]


def _permitted(fx: Fixture) -> str | None:
    # Test code, doc comments and string literals are all fine.
    fx.plane.write_text(
        "//! Do not use std::thread::spawn here.\n"
        "fn note() -> &'static str { \"thread::spawn is banned\" }\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    #[test]\n"
        "    fn t() { let h = std::thread::spawn(|| {}); h.join().unwrap(); }\n"
        "}\n"
    )
    return "selftest FAIL: permitted arrangement was rejected" if check(fx.root) else None


def _production_spawn(fx: Fixture) -> str | None:
    fx.plane.write_text(
        "fn materialize() {\n"
        "    std::thread::spawn(move || loop {});\n"
        "}\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    #[test]\n"
        "    fn t() { std::thread::spawn(|| {}); }\n"
        "}\n"
    )
    found = check(fx.root)
    if len(found) != 1 or ":2 " not in found[0]:
        return f"selftest FAIL: production spawn not caught exactly once: {found}"
    return None


def _spawn_after_tests(fx: Fixture) -> str | None:
    # ...including one placed AFTER the test module, which a "everything below
    # #[cfg(test)] is tests" heuristic would have missed.
    fx.plane.write_text(
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    #[test]\n"
        "    fn t() { std::thread::spawn(|| {}); }\n"
        "}\n"
        "fn late() { std::thread::spawn(move || loop {}); }\n"
    )
    found = check(fx.root)
    if len(found) != 1 or ":6 " not in found[0]:
        return f"selftest FAIL: spawn after the test module not caught: {found}"
    return None


def _allowlisted_at_count(fx: Fixture) -> str | None:
    # An allowlisted file is exempt at its reviewed site count.
    fx.plane.unlink()
    fx.allowed.parent.mkdir(parents=True)
    fx.allowed.write_text("fn call() { std::thread::spawn(|| {}); }\n")
    if check(fx.root):
        return "selftest FAIL: an allowlisted file was rejected at its reviewed count"
    return None


def _allowlisted_only_at_count(fx: Fixture) -> str | None:
    # ...and only at that count: a SECOND spawn in the same file is a new thread
    # nobody reviewed, which a file-granular exemption would have waved through.
    fx.allowed.write_text(
        "fn call() { std::thread::spawn(|| {}); }\n"
        "fn extra() { std::thread::spawn(move || loop {}); }\n"
    )
    found = check(fx.root)
    fx.allowed.write_text("fn call() { std::thread::spawn(|| {}); }\n")
    if len(found) != 1 or "allowlisted for 1 reviewed spawn site" not in found[0]:
        return f"selftest FAIL: extra spawn in an allowlisted file not caught: {found}"
    return None


def _nested_crate(fx: Fixture) -> str | None:
    # A crate BELOW the top level is scanned. The SDK bindings live at sdk/<lang>,
    # and a depth-1 crate walk reports a clean tree having read none of them.
    (fx.nested / "src").mkdir(parents=True)
    (fx.nested / "Cargo.toml").write_text('[package]\nname = "mcp-re-sdk-python"\n')
    (fx.nested / "src" / "lib.rs").write_text(NESTED_PRODUCTION_SPAWN)
    found = check(fx.root)
    if len(found) != 1 or not found[0].startswith("sdk/python/src/lib.rs:1"):
        return f"selftest FAIL: nested crate not scanned: {found}"
    return None


def _vendored_crate(fx: Fixture) -> str | None:
    # Vendored fixture crates under node_modules are not this repo's production code.
    vendored = fx.root / "sdk" / "typescript" / "node_modules" / "pkg"
    (vendored / "src").mkdir(parents=True)
    (vendored / "Cargo.toml").write_text('[package]\nname = "vendored"\n')
    (vendored / "src" / "lib.rs").write_text(NESTED_PRODUCTION_SPAWN)
    (fx.nested / "src" / "lib.rs").write_text("fn go() {}\n")
    return "selftest FAIL: a vendored node_modules crate was scanned" if check(fx.root) else None


STEPS: tuple[Step, ...] = (
    _permitted,
    _production_spawn,
    _spawn_after_tests,
    _allowlisted_at_count,
    _allowlisted_only_at_count,
    _nested_crate,
    _vendored_crate,
)


def selftest() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(Path(tmp))
        for step in STEPS:
            failure = step(fixture)
            if failure:
                print(failure)
                return 1
    print("owned-worker gate selftest: PASS")
    return 0
