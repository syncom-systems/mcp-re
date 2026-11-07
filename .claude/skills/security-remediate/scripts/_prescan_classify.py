"""Language, role and crate classification for the structural pre-scan."""

import os

from _prescan_vocab import PY_COMPROOT_HINT, PY_COMPROOT_NAMES


def language(path):
    if path.endswith(".py"):
        return "python"
    if path.endswith(".rs"):
        return "rust"
    return None


def is_test_path(path):
    p = path.replace(os.sep, "/")
    base = os.path.basename(p)
    return ("/tests/" in p or "/test/" in p or base.startswith("test_")
            or base.endswith("_test.rs"))


# (path fragments, role) in precedence order; the first fragment found wins.
_PATH_ROLES = (
    (("/generated/",), "generated"),
    (("/migrations/", "/migration/"), "migration"),
    (("/scripts/", "/examples/"), "script"),
    (("/adapters/", "/adapter/"), "adapter"),
)


def base_role(path):
    """Role determinable from the path alone (language-agnostic)."""
    p = path.replace(os.sep, "/")
    if is_test_path(p):
        return "test"
    for fragments, role in _PATH_ROLES:
        if any(fragment in p for fragment in fragments):
            return role
    return None  # decided by language-specific logic


def python_role(path, src):
    pr = base_role(path)
    if pr:
        return pr
    base = os.path.basename(path)
    if base in PY_COMPROOT_NAMES or PY_COMPROOT_HINT.search(src):
        return "comproot"
    if "__name__" in src and "__main__" in src:
        return "binary"
    return "library"
