<!-- SPDX-License-Identifier: Apache-2.0 -->

# v0.18.1 assurance closure — owner ruling, 2026-10-17

The re-review of the five theorems whose specification review went stale between the v0.18.0
closure (`9dab7082`) and the v0.18.1 candidate (`60a2257f`) is in
`verification/reviews/packets/v0181-assurance-closure-2026-10-17.md`. This is the owner's disposition of that packet. It is signed in
`docs/security/owner-approvals-2026-10-17.jsonl` as `owner-signature:v0181-assurance-closure-2026-10-17`, whose `text` is the
ruling below.

## The ruling

> **OWNER RULING — APPROVED**
>
> I ratify the five re-reviews documented in `verification/reviews/packets/v0181-assurance-closure-2026-10-17.md`:
>
> - THM-0077
> - THM-0086
> - THM-0092
> - THM-0106
> - THM-0111
>
> This approval is based on the reported substantive re-review: four CLEAN, one CLEAN-NOTE, zero false claims and zero discrepancies.
>
> **Conditions:**
>
> 1. Record each review against its exact current theorem fingerprint and review digest. If either has changed, stop and re-review the affected item.
> 2. Do not change theorem claims, dependencies or security scope merely to regain review currency.
> 3. THM-0077's ratification does not include NP-281. That proposition remains explicitly unratified and outside the approved theorem support.
> 4. Record the CLEAN-NOTE and the NP-281 exclusion in the permanent review evidence.
> 5. Preserve the existing owner-approval ledger mechanism and link each updated specification record to this ruling and the reviewed packet.
>
> You are authorized to write the owner approval, update the five specification records and commit and push the packet with those records to PR #1199.
>
> Then allow the required verification and assurance checks to execute against the resulting exact commit.
>
> **Required result:** REVIEW_CURRENT, EVIDENCE_ESTABLISHED and CURRENTLY_VERIFIED must each reach 133/133, with successful root-completeness and assurance-closure verdicts.
>
> A missing, stale or failed review must remain a failure. No manual overrides or weakening of verification requirements.
>
> This ratification authorizes the review-record update and PR verification. It does not independently authorize merging or publishing v0.18.1 before the required release checks have passed.
>
> Proceed.

## Identities recorded

Each record is written at the identity below, computed by `tools/verification/review --fingerprint`
at `60a2257f`, the commit the packet read. Every theorem fingerprint equals the one its
previous record named, so no claim, dependency, review requirement or scope moved (condition 2).
The only review components that moved are the supporting-unit components the packet read:

- THM-0077: `proxy.replay_configuration_state` source_inputs + test_selection,
  `proxy.startup_plan_legality` source_inputs, `proxy.startup_plan_provenance` source_inputs +
  test_selection;
- THM-0086: `proxy.replay_materialization` source_inputs;
- THM-0092: `proxy.replay_configuration_state` source_inputs + test_selection;
- THM-0106: `proxy.redis_replay_adapter` source_inputs;
- THM-0111: `conformance.scanned_tree_declaration` source_inputs,
  `conformance.verdict_vocabulary_scope` source_inputs.

| theorem | verdict | theorem fingerprint | review digest |
|---|---|---|---|
| THM-0077 | CLEAN-NOTE | `sha256:9412e9593b1981a0f89dba3de90cd81583948d38b5775185d3de2b7ce289316f` | `sha256:29785e9d2b188b14407b715c9023508d6660467c98fc45ea0c467421e9b8b6fb` |
| THM-0086 | CLEAN | `sha256:dbd5a9b589552f5154ea4a3ab32b01074a99c53ae158fb97f4521ba06ba50352` | `sha256:8e805f4f1bb19691825dd7e908f5fb2a53dafaaaa0b8af388c403e24671f9349` |
| THM-0092 | CLEAN | `sha256:49569e318ea23f11449d3e262a2be902b477bb8e2c189576ed6271cc62b1f4db` | `sha256:c5d69d5243ac427933a5ef9d7a819e2d45258c87c659b62a11e50a9c2e33b8b0` |
| THM-0106 | CLEAN | `sha256:6f9c2db935e10844da0dd25e7d41c1617f0541c5003bbf92d76e7f5c6e93c196` | `sha256:0a11a3e57e9cb95c2f83631990ed9debdc23cac8f190e8961e972a54510373bf` |
| THM-0111 | CLEAN | `sha256:f3f5713603a624cc6836ed1928f42ebbb45a5401b1a111194ced0f6e6a1f7d3c` | `sha256:8f384158d7537c518b46cb20b1a5eab209141ce00eae1e9c15f94bed034c6cef` |

## THM-0077's note, and what its ratification excludes

THM-0077 is CLEAN-NOTE. Its proposition holds at `60a2257f`. The note: the Redis replay pool
size's own refusals (a size outside 1..=128, and a size stated beside no Redis replay store) are
recorded as **NP-281** in `verification/policy/control-dispositions.toml`, with the root
relationship "under THM-0077". Their carriers,
`mcp-re-proxy/src/deployment_request/storage/replay_redis_pool_size.rs` and
`mcp-re-proxy/src/cli/storage_flags.rs`, are in no supporting unit of THM-0077.

**NP-281 is not ratified by this ruling** (condition 3). It remains an unratified proposition
outside THM-0077's approved support. THM-0077's record states the same.
