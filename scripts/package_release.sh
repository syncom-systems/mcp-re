#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build one release archive with Bazel:
#
#   scripts/package_release.sh --target linux-amd64  --out dist/
#   scripts/package_release.sh --target darwin-arm64 --out dist/
#   scripts/package_release.sh --target linux-amd64  --out dist/ --source /path/to/checkout
#
# Output: <out>/mcp-re-<version>-<target>.tar.gz, one top-level directory of the same name:
#
#   bin/mcp-re-proxy     //mcp-re-proxy:mcp_re_proxy_deploy_bin — the shipped server proxy
#   bin/mcp-re-client    //mcp-re-client:mcp_re_client_cli — the client-side ambassador
#   RELEASE.json         version, source revision, target, and each binary's SHA-256
#   LICENSE NOTICE.md THIRD_PARTY.md
#
# The proxy is the server half and the client is the host half of the signed-call path, so
# an installation carries both. The linux targets are cross-compiled from a macOS host with
# the hermetic zig toolchain `.bazelrc` registers there (glibc 2.28 floor, the same binaries
# the container image carries). linux-arm64 is not offered: the zig linker rejects
# `--fix-cortex-a53-843419`, which rustc passes for aarch64-unknown-linux-gnu. darwin-arm64 is the host build. Both use the toolchains
# MODULE.bazel pins, `-c opt`, and no stamping, so the archive is a function of the source.
#
# `--source` builds a checkout other than the one this script lives in: the release
# workflow checks the tagged revision out beside a current copy of this script, so a
# backfill packages the tagged SOURCE with today's packaging recipe and names both revisions.
set -euo pipefail

TARGET="" OUT="" SOURCE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:?--target needs linux-amd64 or darwin-arm64}"; shift 2 ;;
    --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
    --source) SOURCE="${2:?--source needs a checkout}"; shift 2 ;;
    -h|--help) sed -n '3,22p' "$0"; exit 0 ;;
    *) echo "package-release: unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$TARGET" in
  linux-amd64) PLATFORM=(--platforms=//platforms:linux_x86_64) ;;
  darwin-arm64) PLATFORM=() ;;
  *) echo "package-release: --target linux-amd64|darwin-arm64 is required" >&2; exit 2 ;;
esac
[[ -n "$OUT" ]] || { echo "package-release: --out is required" >&2; exit 2; }

TOOLS="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$(cd "${SOURCE:-$TOOLS}" && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

host="$(uname -s)-$(uname -m)"
if [[ "$TARGET" == darwin-arm64 && "$host" != Darwin-arm64 ]] \
  || [[ "$TARGET" == linux-* && "$(uname -s)" != Darwin ]]; then
  echo "package-release: $TARGET is built on a macOS arm64 host (this one is $host)" >&2
  exit 2
fi

cd "$SOURCE"
[[ -z "$(git status --porcelain)" ]] || { echo "package-release: $SOURCE has uncommitted changes" >&2; exit 1; }
VERSION="$(tr -d '[:space:]' < VERSION)"
REVISION="$(git rev-parse HEAD)"
PACKAGING_REVISION="$(git -C "$TOOLS" rev-parse HEAD)"
NAME="mcp-re-$VERSION-$TARGET"

FLAGS=(-c opt "${PLATFORM[@]}")
# <installed name> <label>
BINARIES=(
  "mcp-re-proxy //mcp-re-proxy:mcp_re_proxy_deploy_bin"
  "mcp-re-client //mcp-re-client:mcp_re_client_cli"
)
labels=()
for b in "${BINARIES[@]}"; do labels+=("${b#* }"); done
echo "package-release: building ${labels[*]} for $TARGET at $REVISION"
bazel build "${FLAGS[@]}" "${labels[@]}"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME/bin"
for b in "${BINARIES[@]}"; do
  name="${b%% *}" label="${b#* }"
  # The configured output path, not bazel-bin: bazel-bin names whichever configuration
  # built last, which is not necessarily this one.
  file="$(bazel cquery "${FLAGS[@]}" --output=files "$label" 2>/dev/null | head -1)"
  [[ -f "$file" ]] || { echo "package-release: $label produced no file" >&2; exit 1; }
  install -m 0755 "$file" "$STAGE/$NAME/bin/$name"
done
for doc in LICENSE NOTICE.md THIRD_PARTY.md; do
  install -m 0644 "$doc" "$STAGE/$NAME/$doc"
done

# A binary that can be run here is asked for its version, and must name this archive's.
# A tree that predates the flag cannot be asked: its archive says so in RELEASE.json and is
# identified by RELEASE.json and the attestation instead. Detected from the source, never
# assumed from a version number.
VERSION_FLAG=false
if grep -q '"--version"' mcp-re-client/src/startup.rs; then VERSION_FLAG=true; fi
if [[ "$TARGET" == darwin-arm64 && "$VERSION_FLAG" == true ]]; then
  for name in mcp-re-proxy mcp-re-client; do
    got="$("$STAGE/$NAME/bin/$name" --version)"
    [[ "$got" == "$name $VERSION" ]] || { echo "package-release: $name reports '$got', expected '$name $VERSION'" >&2; exit 1; }
  done
fi

python3 -I - "$STAGE" "$NAME" "$VERSION" "$REVISION" "$PACKAGING_REVISION" "$TARGET" "$OUT" "$VERSION_FLAG" <<'PY'
import gzip, hashlib, io, json, os, sys, tarfile
stage, name, version, revision, packaging, target, out, version_flag = sys.argv[1:]
root = os.path.join(stage, name)
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
release = {
    "name": "mcp-re",
    "version": version,
    "target": target,
    "source_revision": revision,
    "packaging_revision": packaging,
    "version_flag": version_flag == "true",
    "binaries": {b: sha(os.path.join(root, "bin", b)) for b in sorted(os.listdir(os.path.join(root, "bin")))},
}
with open(os.path.join(root, "RELEASE.json"), "w") as f:
    json.dump(release, f, indent=2, sort_keys=True)
    f.write("\n")
members = []
for dirpath, dirs, files in os.walk(root):
    dirs.sort()
    members.append(dirpath)
    members.extend(os.path.join(dirpath, n) for n in sorted(files))
archive = os.path.join(out, name + ".tar.gz")
buf = io.BytesIO()
# Fixed owner, mode and timestamps and an unnamed gzip stream: the same inputs give the same bytes.
with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
    for path in members:
        info = tar.gettarinfo(path, arcname=os.path.relpath(path, stage))
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        info.mode = 0o755 if (info.isdir() or info.mode & 0o111) else 0o644
        info.pax_headers = {}
        tar.addfile(info, open(path, "rb") if info.isfile() else None)
with open(archive, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
    gz.write(buf.getvalue())
print(f"package-release: wrote {archive} sha256={sha(archive)}")
PY
