# SPDX-License-Identifier: Apache-2.0
"""Paths, the keySource-to-feature table, and the readers every text check shares."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))

import _rust_targets  # noqa: E402

TABLE_RELATIVE = _rust_targets.TABLE_RELATIVE
rows_at = _rust_targets.rows_at

CHART = REPO / "deploy" / "helm" / "mcp-re-proxy"
DOCKERFILE = REPO / "deploy" / "docker" / "Dockerfile"
#: Stages the binaries the image copies in, each named by its Bazel label.
STAGE_SCRIPT = REPO / "scripts" / "stage_image_binaries.sh"

#: `keySource` value -> the cargo feature the binary needs to serve it. A mode the
#: chart accepts but the default image was not built with does not degrade: the CLI
#: arm behind `#[cfg(not(feature = ...))]` returns a KeyError at startup, so the pod
#: CrashLoopBackOffs after the operator has already provisioned a KMS key, an IAM
#: role and an OIDC provider. The chart validating a mode in detail is not the same
#: as the artifact being able to run it, and only this check couples the two.
KEY_SOURCE_FEATURES: dict[str, str] = {
    "gcpKms": "gcp_kms_keysource",
    "awsKms": "aws_kms_keysource",
}


def chart_text(root: Path, relative: str) -> str:
    """A file of the chart under `root`, read as text."""
    return (root / CHART.relative_to(REPO) / relative).read_text(encoding="utf-8")


def prose(raw: str) -> str:
    """`raw` with comment markers and line wrapping normalised away.

    The phrases the checks assert are long enough to straddle a wrap, so they read the
    sentence rather than the layout.
    """
    return " ".join(raw.replace("#", " ").split())
