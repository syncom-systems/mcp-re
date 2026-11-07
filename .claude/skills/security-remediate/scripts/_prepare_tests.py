"""The owning BUILD file and the candidate test modules for a file."""
from __future__ import annotations

import os
import re
import subprocess

from _prepare_rust import all_ignored, component_root, it_target, root_reexports, rust_module
from _prepare_usage import is_test


def owning_build(path: str) -> str | None:
    d = os.path.dirname(path)
    while d:
        cand = os.path.join(d, "BUILD.bazel")
        if os.path.exists(cand):
            return cand
        d = os.path.dirname(d)
    return None


def _rust_test_candidates(path: str) -> list[str]:
    # Integration tests reach a crate's items through a module path, so a test
    # file is a candidate when it spells this file's module, whatever it is named.
    # They also reach it through the names the crate root re-exports from it
    # (`pub use aws_kms_keysource::AwsKmsEd25519Backend;` → `mcp_re_proxy::AwsKms…`),
    # which spell no module at all.
    root = component_root(path) or "."
    names = [re.escape(rust_module(path)) + "::"] + [re.escape(n) for n in root_reexports(path)]
    pattern = r"(^|[^A-Za-z0-9_])(%s)([^A-Za-z0-9_]|$)" % "|".join(names)
    p = subprocess.run(["git", "grep", "-l", "-E", pattern,
                        "--", os.path.join(root, "tests")], capture_output=True, text=True)
    hits = sorted(p.stdout.split())
    return ["%s [%s]" % (f, "every test #[ignore]d — measures nothing in a local gate"
                         if all_ignored(f) else "--it " + it_target(root, f))
            for f in hits[:10]] + \
        (["… %d more, truncated" % (len(hits) - 10)] if len(hits) > 10 else [])


def test_candidates(path: str) -> list[str]:
    if path.endswith(".rs"):
        return _rust_test_candidates(path)
    stem = os.path.splitext(os.path.basename(path))[0]
    root = component_root(path) or "."
    p = subprocess.run(["git", "ls-files", "--", root], capture_output=True, text=True)
    out = []
    for f in p.stdout.splitlines():
        if not is_test(f) or f == path:
            continue
        b = os.path.basename(f)
        if stem in b:
            out.append(f)
    return sorted(out)[:10]
