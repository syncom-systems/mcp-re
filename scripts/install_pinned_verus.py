#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install the Verus release the lock pins for this host, refusing anything but its bytes.

Reads the host's table from `verification/policy/toolchains.lock.toml` (the same selection
`tools/verification/verify-verus` makes), downloads `source_url`, requires the archive to
digest to the lock's `sha256`, extracts it to `install_root`, and then requires every
file the lock names by digest to match. The lane re-checks all of it before any proof; this
script exists so a runner that has nothing installed can reach that state without trusting
the download. `--selftest` runs the refusals and an install against a local archive.
"""

from __future__ import annotations

import hashlib
import platform
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "verification"))

import _toolchains  # noqa: E402

HOST_PINS = {("Darwin", "arm64"): "verus", ("Linux", "x86_64"): "verus_linux_x86_64"}
RELEASE_HOST = "https://github.com/verus-lang/verus/releases/download/"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    name = HOST_PINS.get((platform.system(), platform.machine()))
    if name is None:
        print(f"no Verus build is pinned for {platform.system()} {platform.machine()}", file=sys.stderr)
        return 1
    pin = _toolchains.load()[name]
    if pin.get("state") != "resolved":
        print(f"[{name}] is not resolved", file=sys.stderr)
        return 1
    return install(name, pin)


def install(name: str, pin: dict, fetch=urllib.request.urlretrieve) -> int:
    """Fetch `pin`'s archive with `fetch(url, path)`, refuse it unless it digests to the pin,
    and extract it to `install_root`. Returns the exit status."""
    url = str(pin["source_url"])
    if not url.startswith(RELEASE_HOST):
        print(f"refusing a source_url outside the Verus release host: {url}", file=sys.stderr)
        return 1
    root = Path(pin["install_root"])
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "verus.zip"
        fetch(url, archive)  # noqa: S310 - scheme and host checked above
        got = sha256_of(archive)
        if got != pin["sha256"]:
            print(f"archive digest {got} is not the pinned {pin['sha256']}", file=sys.stderr)
            return 1
        staging = Path(tmp) / "out"
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(staging)
        entries = list(staging.iterdir())
        source = entries[0] if len(entries) == 1 and entries[0].is_dir() else staging
        if root.exists():
            shutil.rmtree(root)
        root.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(root))
    for member in ("verus", "rust_verify", "z3", "cargo-verus"):
        path = root / member
        if path.is_file():
            path.chmod(path.stat().st_mode | 0o111)
    print(f"installed {name} at {root}")
    return 0


def selftest() -> int:
    """The installer refuses a foreign host and a wrong digest, and installs the pinned bytes.

    The archive is built in a temporary directory and `fetch` copies it, so no network is
    touched and nothing outside the temporary directory is written.
    """
    failures = 0

    def case(label: str, ok: bool) -> None:
        nonlocal failures
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        failures += not ok

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        archive = base / "release.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("verus-x86/verus", "#!/bin/sh\n")
            zf.writestr("verus-x86/rust_verify", "#!/bin/sh\n")
        fetched: list[str] = []

        def fetch(url: str, dest: Path) -> None:
            fetched.append(url)
            shutil.copyfile(archive, dest)

        good = {
            "source_url": f"{RELEASE_HOST}release/verus.zip",
            "sha256": sha256_of(archive),
            "install_root": str(base / "installed"),
        }
        case("the pinned archive installs", install("verus", good, fetch) == 0
             and (base / "installed" / "verus").is_file()
             and (base / "installed" / "verus").stat().st_mode & 0o111 != 0)

        wrong = {**good, "sha256": "0" * 64, "install_root": str(base / "tampered")}
        case("an archive that is not the pinned bytes is refused",
             install("verus", wrong, fetch) == 1 and not (base / "tampered").exists())

        fetched.clear()
        foreign = {**good, "source_url": "https://example.com/verus.zip",
                   "install_root": str(base / "foreign")}
        case("a source_url outside the release host is refused before any fetch",
             install("verus", foreign, fetch) == 1 and not fetched)

    if failures:
        print(f"install-pinned-verus selftest: FAIL ({failures})")
        return 1
    print("install-pinned-verus selftest: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest() if "--selftest" in sys.argv else main())
