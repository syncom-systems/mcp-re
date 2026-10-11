# Verification toolchains on GitHub-hosted Linux — measurements

Source: `hosted-probe` run 38144113537 (PR #1094), 2026-10-11. Standard runners, read-only
token, no secrets, no self-hosted runner.

| runner | shape | observed |
|---|---|---|
| `ubuntu-24.04` (x86-64) | 4 vCPU, 16 GB RAM, 3 GB swap, `/` 145 GB with 86 GB free | Verus: both `verus_verify` targets exit 0 in 144 s; peak memory 3.4 GB; Bazel client RSS 161 MB |
| `ubuntu-24.04-arm` (arm64) | 4 vCPU, 16 GB RAM, `/` 145 GB with 108 GB free | extraction image builds from `verification/extraction/Dockerfile` in 178 s; image 13.2 GB; peak disk delta 13.1 GB |

## Findings

- The ~14 GB disk ceiling no longer applies to these standard runners: the 18 GB extraction
  image fits with about 95 GB to spare. No disk-reduction work is needed to run it.
- Verus 0.2026.08.09.92f466f ships `x86-linux` and no arm64-linux build, so the Verus lane
  runs on x86-64. The release's declared toolchain is `1.97.1-x86_64-unknown-linux-gnu`,
  equal to the pinned Rust channel. Zip digest from the release matches
  `2f5a41c553f424aacdd732339e9d125563716a0b003c27730f75d6f81a282cef`.
- Linux identities the lock does not yet record (macOS values are in the lock today):
  `verus` d97501a8…12d2, `rust_verify` 433399ab…6c62, `z3` e583c418…b765,
  `vstd.vir` 214c4167…ad68, `libvstd.rlib` 47eb8205…7a26.
- The probe built the Verus targets directly with Bazel against a scratch install. It did not
  run `verify-verus`, whose identity check rightly refuses these digests until they are pinned.

## Constraints that need an owner decision

1. **Verus Linux pin.** Every scalar in `[verus]` and every `[verus.*]` table enters every
   unit's fingerprint, and `verify-verus` is a `VERUS_LANE_INPUTS` member. A per-platform pin
   therefore moves all fingerprints and re-stales the Verus units' reviews.
2. **Extraction image.** The pinned image cannot be rebuilt (apt, rustup and the mathlib
   cache resolve at build time) and its preserved archive exists only on dev1 under
   `/opt/verification/extraction-artifacts`. Hosted execution needs either that archive
   published to an immutable store (GHCR) and loaded by `archive_digest`, or a new image
   built on hosted ARM and re-pinned, which is a different instrument and moves the Lean
   units' fingerprints.
3. **PR #1093 cannot merge.** The `Protect main` ruleset has an `update` rule with no bypass
   actors. All required checks are green on #1093.
