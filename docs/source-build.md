<!-- SPDX-License-Identifier: Apache-2.0 -->

# Building MCP-RE from source

Bazel is the build authority. There is no supported Cargo build, and the toolchains are the
ones `MODULE.bazel` pins (Rust included), not whatever is installed on the machine.

## Prerequisites

- [Bazelisk](https://github.com/bazelbuild/bazelisk) (`brew install bazelisk`), which reads
  `.bazelversion` and fetches that Bazel. Nothing else needs to be installed: Rust, the C
  toolchain used for cross-compilation and every crate are fetched and checked by hash.
- macOS arm64 or Linux x86-64 as the build host, with a working C compiler front end (the
  Xcode command line tools on macOS).
- Network access to the Bazel module and crate registries on the first build.

## Build and identify the binaries

```sh
git clone https://github.com/syncom-systems/mcp-re && cd mcp-re
git checkout v0.19.0                      # a release tag; never build a release from a branch

bazel build -c opt //mcp-re-proxy:mcp_re_proxy_deploy_bin //mcp-re-client:mcp_re_client_cli
bazel cquery -c opt --output=files //mcp-re-proxy:mcp_re_proxy_deploy_bin
bazel cquery -c opt --output=files //mcp-re-client:mcp_re_client_cli
```

`mcp_re_proxy_deploy_bin` is the shipped proxy: registration, the shared Redis replay tier and
both cloud KMS signers. (`mcp_re_proxy_cli` is the lean development flavor.) The two paths
`cquery` prints are the executables; copy them out of `bazel-out`, which Bazel rewrites on the
next build.

To reproduce a release archive as the release workflow builds it:

```sh
scripts/package_release.sh --target darwin-arm64 --out dist     # on Apple Silicon
scripts/package_release.sh --target linux-amd64  --out dist     # also from macOS arm64
shasum -a 256 dist/*.tar.gz                                     # compare with the release's SHA256SUMS
```

The archive contains `RELEASE.json`, naming the version, the source revision and the SHA-256
of each binary; `--version` on a binary built from a release after 0.19.0 prints the version.
The Linux target is cross-compiled from a macOS host by the hermetic zig toolchain, which
`.bazelrc` registers on macOS only; that is what keeps it runnable on glibc 2.28 and newer.

## Tests

```sh
bazel test //...                      # every non-manual test
bazel build --config=lint //...       # clippy, warnings as errors
```

`scripts/local_gate.sh` is the full pre-PR battery; see
[`dev/local-gate-order.md`](dev/local-gate-order.md).
