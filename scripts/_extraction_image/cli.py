# SPDX-License-Identifier: Apache-2.0
"""The gate's verdict over the real definition."""

from __future__ import annotations

import _toolchains
from _extraction_image.checks import problems
from _extraction_image.config import DOCKERFILE


def verdict() -> int:
    found = problems(DOCKERFILE.read_text(encoding="utf-8"), _toolchains.load())
    if found:
        print(f"extraction-image gate: FAIL — {len(found)} problem(s)")
        for problem in found:
            print(f"  - {problem}")
        return 1
    print(
        "extraction-image gate: OK — Aeneas and Charon enter the image only as the pinned, "
        "digest-checked release binaries, and the definition builds neither."
    )
    return 0
