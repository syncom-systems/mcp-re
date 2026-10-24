<!-- SPDX-License-Identifier: Apache-2.0 -->

# Installing MCP-RE

An official release installs without cloning the repository, compiling Rust or running
Bazel. Each release publishes the same two executables:

| executable | role |
| --- | --- |
| `mcp-re-proxy` | server side: the policy-enforcement proxy in front of a Streamable-HTTP MCP server |
| `mcp-re-client` | client side: the ambassador that signs calls under the operator's identity and verifies signed responses |

| platform | channel | artifact |
| --- | --- | --- |
| macOS, Apple Silicon (arm64) | Homebrew | `syncom-systems/mcp-re/mcp-re` |
| Linux x86-64 | binary archive | `mcp-re-<version>-linux-amd64.tar.gz` (glibc 2.28 or newer) |
| Linux x86-64 | container image | `ghcr.io/syncom-systems/mcp-re-proxy:<version>` (the proxy) |

Not offered: Intel macOS, Windows, Linux arm64, DEB/RPM. Linux arm64 cannot be built reliably
today: the hermetic cross toolchain's linker rejects an option `rustc` passes for
`aarch64-unknown-linux-gnu`. To run somewhere else, [build from source](source-build.md).

Versions are immutable: a release's assets and image tag are published once and never
replaced. Every archive and image carries a build-provenance attestation, and `RELEASE.json`
inside each archive names the version, the exact source revision and the SHA-256 of each
binary.

## macOS (Homebrew)

```sh
brew install syncom-systems/mcp-re/mcp-re
mcp-re-client --help
brew upgrade mcp-re
brew uninstall mcp-re
```

The formula installs the released binary; Homebrew does not compile MCP-RE. The tap's `update`
workflow renders it from [`packaging/homebrew/mcp-re.rb.in`](../packaging/homebrew/mcp-re.rb.in)
and the SHA-256 of the release's Apple Silicon archive, after checking that archive's
attestation, and commits it only once it has passed `brew audit --strict` and installed,
upgraded and uninstalled on a clean runner. The tap follows a new release within about three
hours (the workflow's schedule).

## Linux (binary archive)

```sh
VERSION=0.19.0
BASE=https://github.com/syncom-systems/mcp-re/releases/download/v$VERSION
curl -fsSLO "$BASE/mcp-re-$VERSION-linux-amd64.tar.gz"
curl -fsSLO "$BASE/SHA256SUMS"

# Integrity, then provenance (needs the GitHub CLI: https://cli.github.com).
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "mcp-re-$VERSION-linux-amd64.tar.gz" --repo syncom-systems/mcp-re

tar -xzf "mcp-re-$VERSION-linux-amd64.tar.gz"
sudo install -m 0755 "mcp-re-$VERSION-linux-amd64"/bin/mcp-re-* /usr/local/bin/
```

The archive holds `bin/`, `RELEASE.json`, `LICENSE`, `NOTICE.md` and `THIRD_PARTY.md`. Upgrade
by installing the new archive over the old binaries; uninstall with
`sudo rm /usr/local/bin/mcp-re-proxy /usr/local/bin/mcp-re-client`. The binaries link only
glibc.

## Linux (container image)

```sh
docker pull ghcr.io/syncom-systems/mcp-re-proxy:0.19.0
gh attestation verify oci://ghcr.io/syncom-systems/mcp-re-proxy:0.19.0 --repo syncom-systems/mcp-re
```

Pin a digest in anything you keep (`ghcr.io/syncom-systems/mcp-re-proxy@sha256:…`; the digest is
shown by `docker inspect` and in the release workflow run). The image runs as uid/gid 65532,
carries the proxy and CA certificates, and labels its version and source revision
(`org.opencontainers.image.version`, `.revision`). The reference deployment is
[`deploy/compose`](../deploy/compose/README.md); the Kubernetes reference is the
[Helm chart](fleet-deployment-guide.md).

## Configuration and startup

Neither executable has a default posture to start in. Each refuses to start until its required
configuration is present, and refuses unsafe values by name.

- **`mcp-re-proxy`** is configured entirely by flags. The required set, the secret files it
  reads (signing seed, TLS key, client CA, trust document) and every refusal are in the
  [sidecar deployment guide](sidecar-deployment-guide.md). Key files must be readable by their
  owner only. It needs a Redis replay store running `noeviction`; the compose deployment shows
  the smallest working arrangement.
- **`mcp-re-client`** reads one JSON document: `mcp-re-client --config client.json`. `--check`
  loads the configuration and the trust anchors and exits, which validates a change before a
  restart ([client guide](client-sidecar-deployment-guide.md)).
- Production trust anchors, signing keys and certificates are yours to provision. Nothing here
  generates them; the compose directory's `dev-pki.sh` makes throwaway material for evaluation
  only and says so.

To run the proxy under systemd on Linux:

```ini
# /etc/systemd/system/mcp-re-proxy.service
[Service]
User=mcp-re
ExecStart=/usr/local/bin/mcp-re-proxy --bind 127.0.0.1:8600 …   # flags from the sidecar guide
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/etc/mcp-re
```

## Identify what is installed

Both executables answer `--version` with `<name> <version>`, for example
`mcp-re-client --version`, and the release workflow refuses to publish a build whose output
differs from the tag. The flag exists from the first release after 0.19.0. For 0.19.0 itself,
which predates it, the identity is `RELEASE.json` (in the archive, and under
`$(brew --prefix)/share/mcp-re` for Homebrew) together with the attestation.

## Maintainers: how a release is distributed

`.github/workflows/distribute.yml` runs when a release is published, or by dispatch for an
existing tag (`tag` and `confirm` must both name it). It refuses a tag unless the tagged commit
is on `main`, `VERSION` equals the tag, and `docs/releases/<tag>-release-assurance.json` on
`main` records `PASS` for exactly that commit (`scripts/distribution_gate.py`). It builds the
tagged source with `scripts/package_release.sh`, publishes, then verifies the public artifacts
on clean runners. Its `verdict` job passes only when every mandatory check ran and
succeeded, and then adds a "Distribution verified" line to the release notes; a release without
that line is published but not verified. A failed verification is retried with `mode: verify`,
which re-checks the public artifacts and changes nothing. The first image push creates the
GHCR package private; an organization owner makes it public once (package settings, "Change
visibility"). The release-assurance record therefore has to be committed to `main` before
the release is published, or the workflow dispatched afterwards.
