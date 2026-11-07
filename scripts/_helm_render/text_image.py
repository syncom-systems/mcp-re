# SPDX-License-Identifier: Apache-2.0
"""Text checks that couple the chart to the image it points at."""

from __future__ import annotations

from pathlib import Path

from _helm_render.config import (
    DOCKERFILE,
    KEY_SOURCE_FEATURES,
    REPO,
    STAGE_SCRIPT,
    chart_text,
    rows_at,
)


def _staged_proxy_label(script_text: str) -> str:
    """The Bazel label the staging script builds `mcp-re-proxy` from (the last one named)."""
    label = ""
    for line in script_text.splitlines():
        stripped = line.strip().strip('"')
        if stripped.startswith("mcp-re-proxy //"):
            label = stripped.split()[1]
    return label


def default_image_features(root: Path = REPO) -> set[str]:
    """The crate features of the proxy binary the image the chart points at carries.

    The image copies a Bazel-built `mcp-re-proxy`; `stage_image_binaries.sh` names the
    label it is built from, and the build graph's target table states that target's
    features. Empty when either cannot be read, which the caller refuses.
    """
    script = (root / STAGE_SCRIPT.relative_to(REPO)).read_text(encoding="utf-8")
    label = _staged_proxy_label(script)
    if not label:
        return set()
    row = rows_at(root).get(label)
    return set(row["features"]) if row else set()


def _declared_users(dockerfile: str) -> dict[str, str]:
    """The `USER` each named build stage of the Dockerfile declares."""
    stage, declared = None, {}
    for line in dockerfile.splitlines():
        stripped = line.strip()
        if stripped.startswith("FROM ") and " AS " in stripped:
            stage = stripped.rsplit(" AS ", 1)[1].strip()
        elif stripped.startswith("USER ") and stage:
            declared[stage] = stripped.split(None, 1)[1].strip()
    return declared


def _user_problem(declared: dict[str, str]) -> str:
    """Why the `proxy` stage's USER cannot be admitted as non-root, or empty."""
    if "proxy" not in declared:
        return (f"{DOCKERFILE.name}: the `proxy` stage declares no USER, so the image "
                "that mounts the signing seed and the TLS key runs as uid 0")
    uid = declared["proxy"].split(":")[0]
    if not uid.isdigit() or uid == "0":
        return (f"{DOCKERFILE.name}: the `proxy` stage runs as {declared['proxy']!r}; "
                "it must be a NUMERIC non-root uid for runAsNonRoot to admit against")
    return ""


def _pin_conflict(values: str, uid: str) -> str:
    """The first chart-pinned id field that differs from the image's `uid`, or empty."""
    for field in ("runAsUser", "runAsGroup", "fsGroup"):
        expected = [ln.split(":", 1)[1].strip() for ln in values.splitlines()
                    if ln.strip().startswith(f"{field}:")]
        if expected and expected[0] != uid:
            return (f"the image runs as uid {uid} but the chart pins {field}: "
                    f"{expected[0]} — the mounted key Secret would be unreadable")
    return ""


def check_image_declares_non_root(root: Path = REPO) -> list[str]:
    """The proxy IMAGE must declare the same non-root uid the chart pins.

    Carried by the chart alone, the non-root posture is a property of one deployment
    description rather than of the artifact: `docker run`, a plain manifest, a kind
    side-load or a chart fork start the process that mounts the response-signing seed
    and the TLS private key as uid 0. `runAsNonRoot: true` also cannot act as an
    admission-time backstop unless the image declares a numeric uid for the kubelet
    to read. Equality with `runAsUser` is asserted too, because the material Secret is
    delivered 0440 owned by `fsGroup` and the proxy reads it through group membership
    — a drift between the two numbers is a pod that cannot read its own key.
    """
    declared = _declared_users((root / DOCKERFILE.relative_to(REPO)).read_text(encoding="utf-8"))
    problem = _user_problem(declared) or _pin_conflict(
        chart_text(root, "values.yaml"), declared["proxy"].split(":")[0]
    )
    return [problem] if problem else []


def check_image_serves_every_key_source(root: Path = REPO) -> list[str]:
    """Every custody mode the chart's `keySource` comment offers must be compiled in."""
    features = default_image_features(root)
    if not features:
        return [
            f"{STAGE_SCRIPT.name} names no proxy target the build graph holds; cannot tell "
            "what the image serves"
        ]
    values = chart_text(root, "values.yaml")
    offered = [mode for mode in KEY_SOURCE_FEATURES if mode in values]
    if not offered:
        return ["values.yaml offers no KMS keySource; this check has stopped measuring anything"]
    return [
        f"values.yaml offers keySource: {mode} but the default image is built "
        f"without `{KEY_SOURCE_FEATURES[mode]}` — that install fails closed at startup"
        for mode in offered
        if KEY_SOURCE_FEATURES[mode] not in features
    ]
