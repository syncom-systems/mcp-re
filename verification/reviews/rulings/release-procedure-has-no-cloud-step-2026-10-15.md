<!-- SPDX-License-Identifier: Apache-2.0 -->

# The release procedure has no cloud step, owner ruling, 2026-10-15

`docs/RELEASE_CHECKLIST.md`, `docs/dev/version-bump.md` and `scripts/bump_version.sh` still
listed `gcloud builds submit --config deploy/cloudbuild/mcp-re-images.yaml .` as a step of
cutting a release, and v0.18.0's provenance record held the tag until four images existed in
a Google Cloud registry. Following that text, one Cloud Build submission was attempted for
v0.18.0; it was refused before the build started because the former temporary project's
billing account is closed. That attempt was outside policy.

## The ruling

> 1. SLO/performance measurement is not part of release qualification.
> 2. AWS and Google Cloud are used by MCP-RE only for deliberately authorized SLO/performance
>    runs.
> 3. Therefore no AWS or Google Cloud operation belongs in the normal release procedure.
>
> The current release rule is:
>
> - source/repository release qualification is established by verification, assurance
>   closure, release assurance and provenance;
> - publication of AWS/GCP deployment artifacts is not a release prerequisite;
> - cloud deployment/performance work occurs separately when explicitly authorized.
>
> Existing GCP/AWS deployment/runbook material may remain as infrastructure for future
> authorized SLO runs.

No agent runs any AWS or Google Cloud operation, read-only ones included, without the owner's
explicit authorization for that specific operation. Existing credentials, runbooks, accounts,
enabled workflows or earlier use are not authorization.

## What follows

- The checklist, the version-bump document and the bump script name no cloud step. A release
  is the qualified commit, its annotated tag and its GitHub release.
- `scripts/deploy_image_tag_gate.py` is unchanged: it keeps the deploy surface's tags equal to
  `VERSION` and every deployed image built by some config, which is a consistency property of
  the tree and needs no registry.
- The v0.16.0 and v0.17.0 provenance records are unchanged. They record the procedure used
  then, which published images.
- Companion ruling: [`release-qualification-excludes-performance-2026-10-15.md`](release-qualification-excludes-performance-2026-10-15.md).
