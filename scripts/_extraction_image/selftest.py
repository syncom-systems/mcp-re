# SPDX-License-Identifier: Apache-2.0
"""The gate refuses each way the definition can drift, and accepts the tree's own."""

from __future__ import annotations

import re

import _toolchains
from _extraction_image.checks import problems
from _extraction_image.config import DOCKERFILE


def _mutations(good: str, lock: dict) -> dict[str, tuple[str, dict]]:
    """Each mutation of the definition (or lock) the gate must refuse."""
    source_build = good.replace(
        "RUN curl -fsSL -o /tmp/aeneas.tar.gz",
        "RUN git clone https://github.com/AeneasVerif/aeneas /opt/src && make -C /opt/src\n"
        "RUN curl -fsSL -o /tmp/aeneas.tar.gz",
        1,
    )
    unchecked = re.sub(
        r'echo "\$\{CHARON_SHA256\}  /tmp/charon.tar.gz" \| sha256sum -c - \\\n\s*&& ',
        "", good, count=1)
    raw_source = good.replace(
        "/charon-pin\" | tail -1)",
        "/charon-pin\" | tail -1) && curl -fsSL "
        "https://raw.githubusercontent.com/AeneasVerif/charon/main/Makefile -o /tmp/M",
        1,
    )
    return {
        "a source clone and make": (source_build, lock),
        "an archive downloaded without its digest check": (unchecked, lock),
        "a Charon that is not the one Aeneas pins":
            (good, {**lock, "aeneas": {**lock["aeneas"], "charon_pin": "0" * 40}}),
        "a build argument that disagrees with the lock":
            (re.sub(r"ARG AENEAS_SHA256=\w+", "ARG AENEAS_SHA256=" + "0" * 64, good, count=1),
             lock),
        "an executable that is not the installed release":
            (good.replace("CHARON_EXE=/opt/charon/bin/charon",
                          "CHARON_EXE=/usr/local/bin/charon", 1), lock),
        "a source file fetched outside a release": (raw_source, lock),
    }


def selftest() -> int:
    good = DOCKERFILE.read_text(encoding="utf-8")
    lock = _toolchains.load()
    if problems(good, lock):
        print("extraction-image gate selftest: FAIL — the tree's own definition is refused: "
              f"{problems(good, lock)}")
        return 1
    cases = _mutations(good, lock)
    for name, (text, table) in cases.items():
        if text == good and table is lock:
            print(f"extraction-image gate selftest: FAIL — the '{name}' mutation did not apply")
            return 1
        if not problems(text, table):
            print(f"extraction-image gate selftest: FAIL — {name} was not refused")
            return 1
    print(f"extraction-image gate selftest: PASS ({len(cases) + 1} cases)")
    return 0
