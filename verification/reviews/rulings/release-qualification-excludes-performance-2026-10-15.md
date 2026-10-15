<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release qualification excludes performance measurement, owner ruling, 2026-10-15

A read-only review of the three manually disabled workflows (`release-assurance.yml`,
`slo.yml`, `extraction-image.yml`) found that `tools/verification/release-assurance` ran
`scripts/slo_evidence_identity.py --decide` as a binding step. Both of its runs in Actions
(2026-09-15) passed every assurance step and failed only there.

## The ruling

> **SLO / performance measurement is not part of MCP-RE release qualification.**
>
> `ReleaseQualified(R)` and `PerformanceMeasured(R, context)` are independent propositions.
>
> A release may be published without a performance measurement.
>
> A performance claim about a release requires appropriate performance evidence, but absence or
> staleness of performance evidence is never itself a release-assurance failure.
>
> Do not repair defect 2 by teaching release assurance how to impersonate the SLO context.
>
> Remove the question from release assurance entirely.

The ruling supersedes a proposed `--slo-requirement {NOT_REQUIRED,REQUIRED}` switch, which was
not implemented.

## The two defects it records

1. **`REMEASURE` blocked a release.** `slo_evidence_identity.py --decide` was a binding
   release-assurance step, so a moved performance surface, a missing record or an expired one
   failed the release verdict. That was never the release policy.
2. **The question could not be answered where it was asked.** `--decide` derives the
   measurement context from the machine and the Docker daemon it runs on.
   `release-assurance.yml` set neither `MCP_RE_LOADGEN_HW_CLASS` nor the `dev1-slo-v1` Docker
   endpoint, so it computed the workstation anchor's class and the ambient daemon, while
   `slo.yml` records under `dev1-slo-v1` on its dedicated daemon. Release assurance could
   therefore never have reused a result the SLO lane recorded, and on a hosted runner it would
   have answered `REMEASURE` every time.

## What follows

- Release assurance composes verification evidence, attestation issuance, trusted-premise
  accounting, binding root completeness and published-claim currency, and nothing else. Its
  selftest refuses a step that invokes an SLO evidence tool. Record schema 2.
- `release-assurance.yml` runs on a GitHub-hosted runner, `workflow_dispatch` only, and still
  refuses a target that is not reachable from `main`.
- `slo.yml` stays manual, privileged, self-hosted and host-exclusive, unchanged in what it
  measures. It is an independent performance-measurement facility, not a pull-request, push
  or release gate.
  **Amended later on 2026-10-15 (owner):** `slo.yml` was removed, with the CI steps that
  checked it. No workflow runs the SLO; the lane runs locally on dev1
  (`scripts/local_slo_lane.sh`) and is part of none of pre-merge, post-merge or release.
