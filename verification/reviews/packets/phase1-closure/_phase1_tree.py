"""The tree the derivation runs in: where it is, how to read a registry, how to ask git."""
import pathlib
import subprocess
import sys

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

REPO = pathlib.Path(subprocess.run(["git", "rev-parse", "--show-toplevel"],
                                   capture_output=True, text=True, check=True).stdout.strip())
sys.path.insert(0, str(REPO / "tools" / "verification"))


def load(rel):
    return tomllib.loads((REPO / rel).read_text())


def sh(*args):
    return subprocess.run(args, cwd=REPO, capture_output=True, text=True)
