# Verification on GitHub-hosted Linux — design, measurements, and what remains

Measured 2026-10-11 on standard GitHub-hosted runners with a read-only token, no secrets and
no self-hosted runner. Workflow: `.github/workflows/verification.yml`.

## Execution architecture

| job | runner | does |
|---|---|---|
| `scope` | `ubuntu-24.04` | `select-units`: the units this change affects, or every unit |
| `host` | `ubuntu-24.04` (x86-64) | `verify --phase host`: tests, mutations, structural probes, measured lane, Verus lane against the pinned Linux x86-64 prover |
| `extraction` | `ubuntu-24.04-arm` | `verify --phase extraction`: Charon, Aeneas and Lean in the pinned linux/arm64 image, loaded from its digest-verified preserved archive |
| `negative-controls` | `ubuntu-24.04` | hostile edits the production lanes must refuse |
| `aggregate` | `ubuntu-24.04` | `verify --aggregate --gate` over every record; uploads `verification-evidence-*` |

Pull requests and pushes measure the affected units. A change `select-units` cannot scope (the
platform itself, an oversized scope) measures every unit before merge; the weekly schedule and a
dispatch measure every unit. Evidence travels between jobs as immutable artifacts.

## Measurements

| quantity | x86-64 `ubuntu-24.04` | arm64 `ubuntu-24.04-arm` |
|---|---|---|
| shape | 4 vCPU, 16 GB RAM, 3 GB swap, `/` 145 GB (86 GB free) | 4 vCPU, 16 GB RAM, `/` 145 GB (108 GB free) |
| complete lane run | host phase 3950 s and 4990 s on two green runs (test ~6 min, mutation 56 to 81 min, structural ~2 min, Verus < 10 s warm / 144 s cold) | extraction phase 18 s; whole job ~5 min |
| peak memory | 4.5 GB used | within the 12 GB container limit |
| peak disk added | ~32 GB (69.0 GB used from a 37 GB base) | 21.7 GB (archive 4.5 GB + image 13.65 GB + load) |

The 14 GB disk ceiling assumed earlier does not apply to these runners.

Self-hosted baseline for the same lanes: the weekly full run on dev1 on 2026-10-11 took 56
minutes and failed on the same two units this branch repairs (below), so hosted is roughly 1.2
to 1.5 times slower on the mutation lane and otherwise equivalent in verdict.

## Verus

Release 0.2026.08.09.92f466f ships `x86-linux` and no arm64-linux build. The lock pins it as
`[verus_linux_x86_64]` (zip digest, `verus`, `rust_verify`, `z3`, `vstd.vir`, `libvstd.rlib`),
read by `verify-verus` and `bazel/verus/repo.bzl` by host. The Linux prover is part of every unit
fingerprint, as the macOS one is, so unit proof evidence is re-established on the new
instrument. Specification reviews bind theorem fingerprints (claim, dependency claims, review
requirement), which exclude toolchain identity, so the 129 reviews stay valid. All six Verus
units verify on Linux. Records carry `prover.pin` and `prover.host`.

Negative controls on the hosted runner (`scripts/hosted_negative_controls.py`): a tampered
Linux `rust_verify` digest is refused with an identity mismatch; a falsified `ensures` fails
`verify-verus`; an aggregate over no records exits non-zero.

## Extraction image

The approved image is preserved, not rebuilt. Archive digest `sha256:469f5776…`, image
`sha256:ce0df16f…` (manifest digest, tag `tc-ac2daa3af3dcc7c4`), verified on the host that
held it with `tools/verification/extraction-image verify` and re-verified on a hosted runner.

| method | time | peak disk added | credentials |
|---|---|---|---|
| pull from GHCR by digest | 82 s | 17.4 GB | repository token (package is private) |
| download the digest-checked archive from its release, then `docker load` | 117 to 135 s | 21.7 GB | none |
| rebuild from the Dockerfile | 178 s | 13.1 GB | none, but a different instrument |

Selected: the archive route. It is the only one a fork pull request can use without
credentials. GHCR is faster but the package is private and package visibility is not settable
through the API. The published GHCR image carries the identical manifest digest, so switching is
a one-line change once the package is made public. The Docker daemon runs with the containerd
image store so an image id is the manifest digest the lock records. A rebuild is not used: its
inputs (apt, rustup, mathlib cache) resolve at build time, so a same-Dockerfile image is a
different instrument.

## Defects the hosted runs surfaced (repaired on this branch)

1. `proxy.scrapi_registration_leaf` and `proxy.capsule_anchor_registration_leaf` (and probes
   M275, M277) declared their tests against `proxy_unit_test`, the default flavor, which does
   not compile the leaf. 32 declared tests could never run, so the weekly full run on dev1 was
   red on 2026-10-04 and 2026-10-11. They now name `proxy_auditor_unit_test`.
2. A Rust test whose result line was split by interleaved log output read as "never ran", so a
   mutation probe whose weakening had broken its control failed as a measurement failure on
   about a third of runs (M164 hosted and local, M152 on dev1). The result is now also read
   from libtest's failure summary, which can only add `FAILED`.
3. `prepare_python_matrix.sh` used a BSD-only `mktemp -t` template.

## Remaining self-hosted use

| workload | reason, measured or structural |
|---|---|
| `slo.yml` (manual, `workflow_dispatch`) | takes the host exclusively and records absolute throughput; a shared hosted VM cannot give a controlled-host measurement. Not triggerable by PR code. |
| `release-assurance.yml` (manual) | reads the attested SLO evidence store `/opt/verification/slo`, which only the SLO runs on dev1 produce. It can move to hosted when SLO evidence is published as an artifact. |

`extraction-image.yml` is now a manual hosted arm64 build that uploads its archive; a rebuild
mints a new instrument and its lock record is a separate reviewed commit.

## Branch protection

`Protect main` (ruleset 17503350) has an `update` rule and no bypass actor, so no pull request
can merge, including #1093, whose required checks are green. Least-privileged correction:
remove the `update` rule (`pull_request`, the three required status checks, `deletion` and
`non_fast_forward` stay), or add one bypass actor limited to mode `pull_request`.

## For Dev Platform

Reusable: per-platform prover pin selected by host; a digest-checked preserved archive as the
instrument store, loaded under the containerd image store; evidence passed between jobs as
artifacts and composed once; negative controls that edit the tree and require a refusal.
