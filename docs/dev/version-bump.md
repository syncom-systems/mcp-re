# Version bump — what has to move, in what order, and what proves it

`VERSION` is not just a label. It is the **image tag** every deploy artefact names, so a
bump that lands unevenly does not fail at build time — it fails as `ImagePullBackOff` when
the deploy surface is next used. That is the failure this document exists to prevent, and
`scripts/deploy_image_tag_gate.py` is the gate that catches it.

Run `scripts/bump_version.sh <new-version>` rather than editing by hand. This document
says what it does and why, so the gate output is readable when something drifts.

This covers the MECHANICS only. Whether the project is ready to release at all —
licensing, claim wording, conformance evidence, security review — is
[`docs/RELEASE_CHECKLIST.md`](../RELEASE_CHECKLIST.md).

## What carries a version

| surface | file(s) | moves with a bump? |
| --- | --- | --- |
| the canonical version | `VERSION` | **yes** — the single source |
| Rust workspace | `Cargo.toml` (`[workspace.package] version`) | **yes** |
| Rust crates | 12 × `*/Cargo.toml` with a literal `version = ` | **yes** |
| image tags | `deploy/cloudbuild/mcp-re-images.yaml` | **yes** |
| k8s manifests | `deploy/k8s/*.yaml` | **yes** |
| Helm **appVersion** | `deploy/helm/mcp-re-proxy/Chart.yaml` | **yes** — it names the image |
| Helm **chart version** | `deploy/helm/mcp-re-proxy/Chart.yaml` | **only if the chart changed** |
| changelog | `CHANGELOG.md` | **yes** |
| Bazel lock | `MODULE.bazel.lock` | **yes** — it hashes every `Cargo.toml` |
| Python SDK | `sdk/python/pyproject.toml` | **no** — independent cadence |
| TypeScript SDK | `sdk/typescript/package.json` | **no** — independent cadence |

Three of these are routinely got wrong:

* **`MODULE.bazel.lock` records a content hash of every `Cargo.toml`**, so a bump
  invalidates all twelve of them. Nothing fails when it is left stale: Bazel's default
  lockfile mode is `update`, so the next `bazel` invocation silently rewrites the file and
  leaves the tree dirty, and whoever notices it days later reads it as unrelated noise.
  v0.15.0 shipped this way — the lock in git predated its own version bump. Stage 3 of
  `local_gate.sh` regenerates it; commit what it produces.

* **Chart version vs appVersion.** `appVersion` names the image and tracks `VERSION`. The
  chart's own `version` is the chart's semver and moves only when the templates change. A
  bump that moves both in lockstep makes the chart version meaningless; a bump that moves
  neither ships a chart pointing at an image tag that does not exist.
* **The SDKs are NOT the proxy.** They version independently (currently 0.1.x against the
  proxy's 0.17.x) because they are published to PyPI/npm on their own cadence and their
  compatibility surface is the wire profile, not the proxy build. Bumping them in sympathy
  publishes a release with no changes in it.

## Order

1. **Land the work first.** A bump is not a change; it names one. Every functional commit
   should already be merged, and the tree clean.
2. **`scripts/bump_version.sh <new-version>`** — rewrites `VERSION`, the workspace and
   crate versions, the deploy surface and `Chart.yaml`'s `appVersion`. It refuses a
   non-semver argument, refuses a version that is not greater than the current one, and
   refuses to run on a dirty tree.
3. **Write the CHANGELOG entry.** By hand — this is the one part that is judgement, not
   substitution. Say what changed for a reader deciding whether to upgrade, not what the
   commits were.
4. **Bump the Helm chart version** *only* if `deploy/helm/` changed in this release.
5. **`scripts/local_gate.sh --with-kind`** — the full battery. Stage 1 runs the image-tag
   gate; stage 5 deploys the chart against freshly built images, which is what proves the
   tag actually resolves. Stage 4 is a local performance regression measurement; its result
   is performance evidence, not a release-qualification input.
6. **Commit the regenerated `MODULE.bazel.lock`.** Stage 3 rewrites it because the crate
   `Cargo.toml` hashes it records all moved. Leaving it out is invisible until someone
   diffs the tree in an unrelated branch.
7. **Commit, PR, merge.** Then qualify the merged commit (below) and tag it on `main`.
   No cloud operation is a step of releasing: no image build, no registry push, no SLO run.

## Choosing the number

Pre-1.0, so the middle number carries the weight:

* **minor** (`0.15.0` → `0.16.0`) — behaviour a deployment can notice: a changed default,
  a new flag, a serving-path change, a new refusal. Most releases here.
* **patch** (`0.15.0` → `0.15.1`) — fixes with no configuration or behavioural surface.
* A **default change is a minor bump even when the code change is small.** ADR-MCPRE-051
  §1's runtime topology is the worked example: a few lines, but every deployment gets a
  different thread layout on upgrade.

## What the gates check, and what they do not

`scripts/deploy_image_tag_gate.py` (stage 1) asserts that every literal `mcp-re-*:<semver>`
equals `VERSION` across the files its `SCAN_GLOBS` name: all of `deploy/` reachable as
`*.yaml`, `*.yml`, `*.tpl` or `deploy/docker/Dockerfile*`; under `docs/security/`, the
`*.sh` harnesses and the two SLO baseline runbooks named individually; `tools/**/*.sh`; and
`.github/workflows/*.yml`. When it fires, the fix is usually **not** to retype the number —
it is to read the tag from `VERSION` at run time, which the harnesses do
(`BENCH_TAG="$(cat VERSION)"`).

It **does** check that some `deploy/cloudbuild/*.yaml` builds every image the deploy
surface references — `unbuilt_images()`, the deployed-but-never-built defect.

It does **not** check:

* that any registry holds images at the tag — no release step builds or pushes them (see
  below);
* the SDK versions, deliberately (see above);
* the Helm chart's own `version`, which is a human judgement about whether templates moved.

## Deploy images are not release artifacts

The deploy surface (`deploy/cloudbuild/`, `deploy/k8s/`, the Helm chart, the GKE and EKS
runbooks) is infrastructure for a cloud deployment or performance run, and AWS and Google
Cloud are used only for such runs when the owner authorizes that specific run. No release
step builds, pushes or inspects cloud images, and a release is not held because a registry
lacks images at its tag. A run that needs them builds them as part of its own authorized
plan.

The kind lane (`local_gate.sh --with-kind`) builds its own images locally and stamps them with
the git revision, so a green kind stage proves the source builds and deploys at the tag; it
says nothing about any registry.

## Release assurance — the binding closure run

Qualifying a release is a separate act from bumping a version, and it has exactly one
authority:

```sh
tools/verification/release-assurance
```

It composes the release-level verdict from the authorities that already own each question —
`verify --aggregate --gate`, `check-assumptions`, `review --require-root-complete` and
`claim_surface_gate.py` — and writes a machine-readable record naming the repository, the
commit, the tree, the root-completeness verdict and the overall verdict. It refuses a dirty
working tree and refuses a `--target` that is not the checked-out commit, because a release
record is about one immutable thing.

**Release qualification does not include performance.** `ReleaseQualified(R)` and
`PerformanceMeasured(R, context)` are independent propositions: release assurance asks no
SLO question, and absent or stale performance evidence never fails it. A performance
*claim* about a release does need performance evidence, which comes from
`scripts/local_slo_lane.sh` — a measurement facility that an owner or operator runs on
dev1 when a measurement is wanted, never as a step of qualifying a release.

`review --require-root-complete` is the **binding** closure mode. Ordinary CI runs the
report-only form deliberately (ADR-MCPRE-059 §28.8): an honest unresolved GAP under a
declared root must not fail everyday work. This is the lane where it is binding.

In Actions the lane is `.github/workflows/release-assurance.yml`, dispatched with the ref to
qualify and the `verification` run whose evidence records it composes. It runs on a
GitHub-hosted runner and refuses a target that is not reachable from `main`.

**The verification run comes first, and it must close assurance.** Dispatch
`verification.yml` on the exact release candidate. A dispatched run is a complete run, so
after its aggregate succeeds its `assurance-closure` job attests the run's evidence and
requires every active theorem to be REVIEW_CURRENT, EVIDENCE_ESTABLISHED and
CURRENTLY_VERIFIED, with every root complete. Only a run whose job printed
`ASSURANCE CLOSURE: PASS` is the run to hand to release assurance. Commit its
`closure-record.json` as `verification/closures/<commit>.json`; see
[`epic-close.md`](epic-close.md).

**Cutting the release then commits the record.** Copy the run's
`release-assurance.json` to `docs/releases/<version>-release-assurance.json`, check its
provenance with `python3 scripts/release_assurance_gate.py --verify-run <that file>` (GitHub
must report the producing run as `release-assurance.yml` on `main`, a successful dispatch,
whose uploaded record is byte-identical to the file), register the
provenance document as `mechanized` in `scripts/release_assurance_gate.py`, and paste the
block the gate renders into it. The gate then checks the document against the record on
every CI run, which is the point: a provenance document may explain a result, but it may not
be the authority for what the command returned.

The v0.16.0 and v0.17.0 documents are registered `pre-mechanism` — they were written before
this command existed and are dated measurements, not retroactively falsified. A new document
may not join that class.
