#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Stage the Lightsail ceiling run LOCALLY: two archives and one identity record, written to
# work/lightsail/<run-id>/ (git-ignored). No cloud is contacted and no second checkout is
# made — `git archive` reads the object store and writes one compressed file per identity.
#
#   SUBJECT  the released product, exactly the tagged tree: `git archive <tag>`. The host
#            builds the measured binaries from THIS and nothing else, and proves it by
#            re-deriving the git tree id from the extracted files (bootstrap.sh).
#   TOOLING  the measurement orchestration at the CURRENT commit (post-release fixes are
#            tooling, never product): tools/perf/lightsail + the port registry.
#
# The two are recorded separately and never merged: a number from this run is a number
# about the subject's binaries, measured by the tooling revision.
#
# Usage: tools/perf/lightsail/stage_artifacts.sh <run-id> [tag]   (tag defaults to v0.18.0)
set -euo pipefail
cd "$(dirname "$0")/../../.."

RUN_ID="${1:?usage: stage_artifacts.sh <run-id> [tag]}"
TAG="${2:-v0.18.0}"
EXPECT_COMMIT="${EXPECT_COMMIT:-9dab7082f7fa02dbaf6024fde9ba3556ed3ad2e2}"
OUT="work/lightsail/$RUN_ID"

[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$ ]] || { echo "bad run id: $RUN_ID" >&2; exit 2; }
[[ -z "$(git status --porcelain)" ]] || { echo "the tooling tree must be clean: a dirty tree has no commit to name" >&2; exit 1; }
git check-ignore -q "$OUT" || { echo "$OUT is not git-ignored" >&2; exit 1; }
[[ ! -e "$OUT" ]] || { echo "$OUT exists; a staged run is never overwritten" >&2; exit 1; }

[[ "$(git cat-file -t "$TAG")" == tag ]] || { echo "$TAG is not an annotated tag" >&2; exit 1; }
PRODUCT_COMMIT="$(git rev-parse "$TAG^{commit}")"
[[ "$PRODUCT_COMMIT" == "$EXPECT_COMMIT" ]] \
  || { echo "$TAG resolves to $PRODUCT_COMMIT, not the declared subject $EXPECT_COMMIT" >&2; exit 1; }
TOOLING_COMMIT="$(git rev-parse HEAD)"
mkdir -p "$OUT"

git archive --format=tar --prefix=subject/ "$TAG" | gzip -n > "$OUT/subject.tar.gz"
[[ "$(gzip -dc "$OUT/subject.tar.gz" | git get-tar-commit-id)" == "$PRODUCT_COMMIT" ]] \
  || { echo "the subject archive does not carry the subject commit" >&2; exit 1; }
git archive --format=tar --prefix=tooling/ HEAD tools/perf/lightsail config/ports.toml \
  | gzip -n > "$OUT/tooling.tar.gz"

python3 - "$OUT" "$TAG" "$PRODUCT_COMMIT" "$TOOLING_COMMIT" <<'PY'
import hashlib, json, subprocess, sys
out, tag, product, tooling = sys.argv[1:5]
def git(*a):
    return subprocess.run(["git", *a], capture_output=True, text=True, check=True).stdout.strip()
def sha(p):
    return "sha256:" + hashlib.sha256(open(p, "rb").read()).hexdigest()
sys.path.insert(0, "scripts")
import slo_evidence_identity as ident
identity = {
    "schema": "mcp-re-lightsail-identity/v1",
    "release_tag": tag,
    "tag_object": git("rev-parse", tag),
    "product_commit": product,
    "product_tree": git("rev-parse", f"{tag}^{{tree}}"),
    "subject_archive": "subject.tar.gz",
    "subject_archive_sha256": sha(f"{out}/subject.tar.gz"),
    "tooling_commit": tooling,
    "tooling_tree": git("rev-parse", "HEAD^{tree}"),
    "tooling_archive": "tooling.tar.gz",
    "tooling_archive_sha256": sha(f"{out}/tooling.tar.gz"),
    "tooling_tree_performance_surface": ident.performance_surface()[0],
    "note": "product_performance_surface and the binary SHA-256s are measured on the host from the subject tree",
}
json.dump(identity, open(f"{out}/identity.json", "w"), indent=2, sort_keys=True)
print(json.dumps(identity, indent=2, sort_keys=True))
PY
( cd "$OUT" && shasum -a 256 subject.tar.gz tooling.tar.gz identity.json > SHA256SUMS )
echo "staged -> $OUT"
