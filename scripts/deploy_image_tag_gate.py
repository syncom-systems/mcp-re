#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deploy image-tag gate — every image reference must name the version in VERSION.

The deploy surface names container images in several places that must agree:
`deploy/cloudbuild/*.yaml` BUILDS and PUSHES the tags, `deploy/k8s/*.yaml` and the
Helm chart REFERENCE them, and the runbooks + live-validation harnesses under
`docs/security/` and `tools/` DEPLOY them. Nothing tied those together, so they
drifted: the multi-replica harness pinned `0.12.1` while Cloud Build had moved to
`0.13.0`, and the SLO Job runner pinned `0.12.1` against a `0.13.0` bench image.

That failure mode is expensive and late. Every pin is syntactically fine and every
file reads correctly on its own; the mismatch only surfaces as ImagePullBackOff on a
cluster that is already billing, after `gcloud builds submit` has run. It also has a
silent variant: a `sed` that rewrites `image: <name>:<tag>` stops matching when the
manifest's tag moves, leaving the un-rewritten bare local name in the applied YAML.

So: any `mcp-re-*:<literal semver>` in the deploy surface must equal VERSION. The fix
when this gate fires is usually NOT to retype the number — it is to read the tag from
VERSION at run time, which is what the harnesses now do.

Run:  python3 scripts/deploy_image_tag_gate.py
      python3 scripts/deploy_image_tag_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Files whose image references are DEPLOYED or PUSHED. Docs that merely narrate a past
# run are excluded — a historical "the v0.12.1 run" is a fact, not a pin.
#
# A Dockerfile has no extension, so no suffix glob in this tuple reaches one, and
# `deploy/docker/` holds four. `scripts/bump_version.sh:53-54` does not close that hole
# either: it selects by grepping for the OLD version string, so a file that misses one
# bump stops matching and is never swept again. The two runbooks are named individually
# rather than by `docs/security/*.md`, which is what keeps dated narration out.
SCAN_GLOBS = (
    "deploy/**/*.yaml",
    "deploy/**/*.yml",
    "deploy/**/*.tpl",
    "deploy/docker/Dockerfile*",
    "docs/security/*.sh",
    "docs/security/gke-slo-baseline-runbook.md",
    "docs/security/eks-slo-baseline-runbook.md",
    "tools/**/*.sh",
    ".github/workflows/*.yml",
)

# `mcp-re-proxy:0.13.0`, `.../mcp-re-slo-bench:0.13.0` — a LITERAL semver tag on one of
# this project's images. A tag that is a shell/Helm expansion (`$TAG`, `${_TAG}`,
# `{{ .Values… }}`) is exactly the fix this gate wants and must not match.
IMAGE_TAG = re.compile(r"\b(mcp-re-[a-z0-9-]+):(\d+\.\d+\.\d+)\b")

# ANY reference to one of this project's images, whether the tag is a literal semver or
# a shell expansion. The coverage check needs this wider net precisely BECAUSE the drift
# fix works: once `run_slo_job.sh` derives its tag from VERSION (`mcp-re-slo-bench:
# $BENCH_TAG`), a literal-only pattern no longer sees the image at all — so the check
# for "deployed but never built" would go blind on exactly the files the other check
# just fixed. A port is not a tag, so `mcp-re-redis:6379` and
# `mcp-re-inner-fastmcp:8620` are excluded by construction.
IMAGE_REF = re.compile(
    r"\b(mcp-re-[a-z0-9-]+):(\d+\.\d+\.\d+|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)"
)


def expected_version() -> str:
    return (REPO / "VERSION").read_text().strip()


# A Helm chart writes its image tag as a BARE `tag:` value, split from the repository it
# belongs to, so `IMAGE_TAG` (which needs `name:tag` on one line) cannot see it. That is
# not a theoretical gap: `deploy/helm/mcp-re-proxy/values.yaml` carries the tag the FLEET
# ACTUALLY PULLS, and a stale one there deploys the previous image under a release that
# claims to be the new one — with every file still validating and this gate still green.
BARE_TAG = re.compile(r"^\s*tag:\s*\"?(\d+\.\d+\.\d+)\"?\s*$")


def _scanned_files(root: Path) -> Iterator[Path]:
    for glob in SCAN_GLOBS:
        yield from (path for path in sorted(root.glob(glob)) if path.is_file())


def _line_findings(where: str, line: str, version: str) -> list[str]:
    findings = [
        f"{where}: {image}:{tag} != VERSION {version} — read the tag from VERSION "
        f"rather than restating it"
        for image, tag in IMAGE_TAG.findall(line)
        if tag != version
    ]
    bare = BARE_TAG.match(line)
    if bare and bare.group(1) != version:
        findings.append(
            f"{where}: image tag {bare.group(1)} != VERSION {version} — this is the tag "
            f"the chart deploys; see docs/dev/version-bump.md"
        )
    return findings


def scan(root: Path, version: str) -> list[str]:
    """Return one finding per image reference whose literal tag != version."""
    findings: list[str] = []
    for path in _scanned_files(root):
        lines = path.read_text(errors="replace").splitlines()
        for lineno, line in enumerate(lines, 1):
            findings += _line_findings(f"{path.relative_to(root)}:{lineno}", line, version)
    return findings


def _expect_one_in(root: Path, name: str, what: str) -> str | None:
    findings = scan(root, "9.9.9")
    if len(findings) != 1 or name not in findings[0]:
        return f"{what}, got {findings}"
    return None


def _expect_clean(root: Path, what: str) -> str | None:
    return f"{what} still reported findings" if scan(root, "9.9.9") else None


def _selftest_literal_pin(root: Path) -> str | None:
    good = root / "deploy" / "good.yaml"
    bad = root / "deploy" / "bad.yaml"
    good.write_text("image: mcp-re-proxy:9.9.9\nimage: mcp-re-inner-fastmcp:${TAG}\n")
    bad.write_text("image: mcp-re-proxy:0.12.1\n")
    failure = _expect_one_in(root, "bad.yaml", "expected exactly one finding in bad.yaml")
    bad.write_text("image: mcp-re-proxy:9.9.9\n")
    return failure or _expect_clean(root, "a correctly-pinned tree")


def _selftest_bare_tag(root: Path) -> str | None:
    # A Helm-style BARE `tag:` must be caught too. Its own fixture, because the
    # name:tag matcher cannot see this form at all — the check that missed it looked
    # exactly as green as one that covers it.
    values = root / "deploy" / "values.yaml"
    values.write_text("image:\n  repository: mcp-re-proxy\n  tag: \"0.12.1\"\n")
    failure = _expect_one_in(root, "values.yaml", "a drifted bare `tag:` was not caught")
    values.write_text("image:\n  repository: mcp-re-proxy\n  tag: \"9.9.9\"\n")
    failure = failure or _expect_clean(root, "a correct bare `tag:`")
    values.unlink()
    return failure


def _selftest_dockerfile(root: Path) -> str | None:
    # An extensionless Dockerfile. Its own fixture, because no suffix glob can reach
    # one at all — the scan that missed four of them looked exactly as green as one
    # that covers them, and the tag drifted five versions behind under a rule that
    # forbids retyped tags.
    (root / "deploy" / "docker").mkdir()
    dockerfile = root / "deploy" / "docker" / "Dockerfile.x"
    build = "FROM debian:bookworm-slim\n#   docker build -f deploy/docker/Dockerfile.x -t {}:{} .\n"
    dockerfile.write_text(build.format("mcp-re-proxy", "0.12.1"))
    failure = _expect_one_in(root, "Dockerfile.x", "a drifted Dockerfile pin was not caught")
    dockerfile.write_text(build.format("mcp-re-proxy", "9.9.9"))
    failure = failure or _expect_clean(root, "a correctly-pinned Dockerfile")
    dockerfile.unlink()
    return failure


def _selftest_coverage(root: Path) -> str | None:
    # Coverage: an image something DEPLOYS but no cloudbuild config BUILDS. Its own
    # fixture, so the two checks cannot mask each other. The orphan is asserted with an
    # EXPANSION tag, not a literal — that is the form the drift fix produces, and a
    # literal-only matcher would go blind on exactly the files the drift fix touches.
    (root / "deploy" / "cloudbuild").mkdir(parents=True)
    (root / "tools").mkdir()
    cb = root / "deploy" / "cloudbuild" / "images.yaml"
    cb.write_text('args: [build, -t, "${_AR}/mcp-re-proxy:9.9.9", .]\n')
    (root / "tools" / "run_job.sh").write_text('IMG="${_AR}/mcp-re-slo-bench:$BENCH_TAG"\n')
    orphans = unbuilt_images(root)
    if orphans != ["mcp-re-slo-bench"]:
        return f"expected ['mcp-re-slo-bench'] unbuilt, got {orphans}"
    cb.write_text(
        'args: [build, -t, "${_AR}/mcp-re-proxy:9.9.9", .]\n'
        'args: [build, -t, "${_AR}/mcp-re-slo-bench:9.9.9", .]\n'
    )
    return "a fully-built tree still reported unbuilt images" if unbuilt_images(root) else None


def selftest() -> int:
    """The gate must FAIL on a drifted pin. A gate that only ever passes proves nothing."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "VERSION").write_text("9.9.9\n")
        (root / "deploy").mkdir()
        for case in (_selftest_literal_pin, _selftest_bare_tag, _selftest_dockerfile):
            if failure := case(root):
                print(f"SELFTEST FAILED: {failure}")
                return 1
    with tempfile.TemporaryDirectory() as tmp:
        if failure := _selftest_coverage(Path(tmp)):
            print(f"SELFTEST FAILED: {failure}")
            return 1
    print("deploy image-tag gate selftest: PASS")
    return 0


def _images_named_in(path: Path) -> set[str]:
    return {image for image, _ in IMAGE_REF.findall(path.read_text(errors="replace"))}


def unbuilt_images(root: Path) -> list[str]:
    """Images something DEPLOYS that no Cloud Build config BUILDS.

    Matching tags to VERSION is not enough: a pin can be perfectly current and still
    name an image nobody ever pushed. That is how the SLO bench went missing — it lived
    in a second build config, so submitting the main one produced a registry that looked
    complete, and `run_slo_job.sh` pinned a tag Artifact Registry did not hold. The
    failure surfaced as ImagePullBackOff on a running cluster, after the proofs had
    passed. Deployed-but-never-built is its own defect, so it gets its own check.
    """
    built: set[str] = set()
    for cfg in sorted((root / "deploy" / "cloudbuild").glob("*.yaml")):
        built |= _images_named_in(cfg)
    deployed: set[str] = set()
    for path in _scanned_files(root):
        if "cloudbuild" not in path.parts:
            deployed |= _images_named_in(path)
    return sorted(deployed - built)


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    version = expected_version()
    findings = scan(REPO, version)
    orphans = unbuilt_images(REPO)
    if findings or orphans:
        print(f"deploy image-tag gate: FAIL (VERSION={version})")
        for f in findings:
            print(f"  {f}")
        for o in orphans:
            print(f"  {o} is deployed but no deploy/cloudbuild/*.yaml builds it")
        return 1
    print(f"deploy image-tag gate: PASS (every deployed image tag == VERSION {version}, and every one is built)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
