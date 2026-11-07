# SPDX-License-Identifier: Apache-2.0
"""What the extraction image's definition must pin, and where the pins live."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DOCKERFILE = REPO / "verification" / "extraction" / "Dockerfile"

#: Build argument -> (lock table, lock key). Digests are recorded `sha256:<hex>` in the lock
#: and bare hex in the definition, where `sha256sum -c` reads them.
PINNED_ARGS = {
    "CHARON_COMMIT": ("charon", "commit"),
    "CHARON_URL": ("charon", "linux_arm64_url"),
    "CHARON_SHA256": ("charon", "linux_arm64_sha256"),
    "CHARON_BIN_SHA256": ("charon", "charon_sha256"),
    "CHARON_DRIVER_SHA256": ("charon", "charon_driver_sha256"),
    "RUST_NIGHTLY": ("charon", "rust_toolchain"),
    "AENEAS_COMMIT": ("aeneas", "commit"),
    "AENEAS_URL": ("aeneas", "linux_arm64_url"),
    "AENEAS_SHA256": ("aeneas", "linux_arm64_sha256"),
    "AENEAS_BIN_SHA256": ("aeneas", "aeneas_sha256"),
}
#: Each release archive, and the digest its download must be checked against.
ARCHIVES = {"CHARON_URL": "CHARON_SHA256", "AENEAS_URL": "AENEAS_SHA256"}
#: Each binary the lane executes, and the digest it must be checked against.
BINARIES = {
    "/opt/charon/bin/charon": "CHARON_BIN_SHA256",
    "/opt/charon/bin/charon-driver": "CHARON_DRIVER_SHA256",
    "/opt/aeneas/bin/aeneas": "AENEAS_BIN_SHA256",
}
EXECUTABLES = {"CHARON_EXE": "/opt/charon/bin/charon", "AENEAS_EXE": "/opt/aeneas/bin/aeneas"}
#: Tools that build a program from source. None of them may appear in an instruction.
BUILD_TOOLS = re.compile(r"(?<![\w./-])(git\s+clone|make|dune|opam|cargo)(?![\w-])")
UPSTREAM = re.compile(r"(?:github\.com|githubusercontent\.com)/AeneasVerif/(aeneas|charon)[^\s\"']*")
#: The one fetch from those repositories that is not a release: the compatibility pin.
CHARON_PIN_FETCH = "githubusercontent.com/AeneasVerif/aeneas/${AENEAS_COMMIT}/charon-pin"
