<!-- SPDX-License-Identifier: Apache-2.0 -->

# v0.18.1 assurance-closure re-review packet — 5 stale theorem reviews (2026-10-17)

Layer 1 (measurement). Release candidate `release/v0.18.1-prep @ 60a2257f`. Baseline: the
v0.18.0 closure record `verification/closures/9dab7082f7fa02dbaf6024fde9ba3556ed3ad2e2.json`
(133/133/133). At `60a2257f`, `tools/verification/review` reports **128 of 133 REVIEW_CURRENT**;
the five below are `STALE_SEMANTICS`. No specification record, ruling or ledger line has been
written for them. This packet is for the owner to ratify or reject.

## Method

Every specification review was current at `9dab7082` (closure record), and no stale theorem's
claim, premises or dependency claims changed since. Only supporting-unit semantics moved, so
each re-review reads exactly the semantic-input diff of its moved units over
`9dab7082..60a2257f`. The paths come from the unit's `paths` in
`verification/policy/verification.toml`, and the moved components come from `review`'s
STALE_SEMANTICS line. Each diff was read against the theorem text (statement, scope,
`supported_by`, `depends_on`) and the unit's declared evidence. No claim was edited.

Verdicts:
- **CLEAN**: the proposition holds and the evidence still bears.
- **CLEAN-NOTE**: the proposition holds, and there is something the owner should see.
- **DISCREPANCY**: the claim or its evidence closure is no longer accurate.

**Result: 0 claims false. 0 discrepancies. 4 CLEAN, 1 CLEAN-NOTE (THM-0077).** No formal-proof
input moved: the `proved_symbols`, `proof_dependencies`, `lean_theorems` and `mutation_probes`
components are unchanged for every moved unit. Only `source_inputs`, and for two units
`test_selection`, moved.

## The change behind four of the five

`--replay-redis-pool-size` (cad6dccb, 17d7e249) carries a validated pool size into the Redis
replay store:

- **Type.** `ReplayRedisPoolSize(NonZeroUsize)` has a private field. `new` admits only `1..=128`
  and `DEFAULT` = 8 (`deployment_request/storage/replay_redis_pool_size.rs`).
- **Request.** `ReplayStoreRequest::Redis { store, pool_size }` holds the pool INSIDE the Redis
  variant, so a pool cannot be represented beside an etcd store or with no store.
- **Parser.** `cli/storage_flags.rs::replay` refuses `--replay-redis-pool-size` without
  `--replay-redis-url`, and therefore beside `--cpstore-etcd-endpoint` alone.
- **Projection.** `config_state/replay.rs` resolves the default once (`unwrap_or(DEFAULT)`) and
  carries `pool` through `ReplayKind::SharedRedis` → `PlannedBackend::Redis` →
  `PlannedStore::Redis`. The tier is computed exactly as before, from the same `self.kind`.
- **Materialization.** `replay_plane/backends.rs::establish_redis` now calls
  `RedisAsyncAtomicReplayStore::connect_pooled(url, clock, wait_quorum, pool)` where it called
  `connect_with_wait_quorum(url, clock, wait_quorum)`. At `9dab7082` the latter was already
  `connect_pooled(.., DEFAULT_POOL_SIZE)` (unchanged in this diff). The connect path, the
  per-connection `maxmemory-policy` assertion, the shared `WaitQuorum` and the response timeout
  are therefore byte-identical in mechanism. Only the loop count can now differ from 8.
- **Startup transcript.** A new line states the effective pool.

Adversarial checks, each against the code at `60a2257f`:

| question | answer |
|---|---|
| Can a pool weaken fail-closed handling? | No. Every connection is built with the same `ConnectionManagerConfig` (the same timeouts) and the same `wait_quorum`. `insert` paths are untouched (`async_redis_store.rs` diff = `DEFAULT_POOL_SIZE` now reads `ReplayRedisPoolSize::DEFAULT.get()`, value 8, unchanged). |
| Can it change the selected tier? | No. `materialization_plan` computes `tier` from `durability_tier()` before the match. The new tests `a_declared_pool_size_reaches_the_plan_and_changes_nothing_else` and `a_declared_replay_pool_size_reaches_the_plan` assert that the tier is identical with and without a pool. |
| Can it change quorum/WAIT? | No. `wait_quorum` is still `tier.wait_quorum_params()` and is shared by every connection. The test `the_redis_arm_connects_with_the_planned_pool_and_reports_it` asserts `(1, 100)` with pool 32. |
| Can a pool exist without a Redis URL? | Not representable past the parser, which refuses it. The test `a_replay_pool_size_beside_the_cp_store_is_refused` is in `startup_plan.rs`, so it is in the test selection of `proxy.startup_plan_legality` / `_provenance`, and the parser unit tests are in `storage_flags.rs`. |
| More connections, more eviction exposure? | No. `assert_no_eviction` runs on EVERY pooled connection (unchanged loop body), so a larger pool asks more servers, not fewer. `connect_pooled`'s `max(1)` is unreachable from deployment (`NonZeroUsize`). |

## Per-theorem verdicts

### THM-0077 — No deployment serves a posture nobody selected — **CLEAN-NOTE**

The moved units are `proxy.replay_configuration_state` (source_inputs, test_selection),
`proxy.startup_plan_legality` (source_inputs) and `proxy.startup_plan_provenance`
(source_inputs, test_selection).

- `replay.rs` carries a validated, range-checked pool into the plan. Nothing is reinterpreted:
  an unset pool is the stated default, and the startup line states the effective size.
- The `startup_plan.rs` diff is test-only: two new tests and two pattern updates.

The proposition holds.

**Note:** the pool's own refusals are recorded as unratified proposition **NP-281** in
`control-dispositions.toml`, "under THM-0077": out of range, and stated beside no Redis store.
Their carriers (`replay_redis_pool_size.rs`, `cli/storage_flags.rs`) are not in any supporting
unit's `paths`. The claim does not depend on them: a pool size is not a security capability,
and the tier, quorum and eviction refusals are unaffected. So this is a coverage observation
for a future proposition decision, not a gap in THM-0077.

### THM-0092 — A request whose replay state was not established does not dispatch — **CLEAN**

The moved unit is `proxy.replay_configuration_state` (source_inputs, test_selection), the
configuration-boundary locus ratified on 2026-10-14. The undeclared-tier refusal in
`classify_and_validate` / `locator_violations` is unchanged (only the pattern
`ReplayStoreRequest::Redis(_)` → `Redis { .. }`). `build` still requires the requested state
and the store kind to agree. Admission, the store class and the outage path are untouched.

### THM-0086 — The established replay tier is the selected one — **CLEAN**

The moved unit is `proxy.replay_materialization` (source_inputs: `backends.rs`,
`materialized.rs`).

- `materialize` still matches `plan.store()` and calls `Self::accept(established, tier.clone())`
  with the plan's tier.
- The Redis arm additionally passes `pool.get()`.
- The volatile-reference refusal and the not-carried-backend refusal are unchanged.

### THM-0106 — The Redis replay backend refuses a server that may drop a nonce — **CLEAN**

The moved unit is `proxy.redis_replay_adapter` (source_inputs: `async_redis_store.rs`). The
only change is that `DEFAULT_POOL_SIZE` reads `ReplayRedisPoolSize::DEFAULT.get()` (still 8)
plus doc text.

- The scope already states the per-connection assertion: "each pooled connection asks the
  server it reached".
- `connect_pooled`, `eviction_policy_verdict`, the TTL/window code and WAIT are unchanged.
- The test `every_pooled_connection_is_asked_for_its_eviction_policy` is unchanged.

### THM-0111 — Two vocabularies decide what an mcp-re.* verdict token says — **CLEAN**

The moved units are `conformance.scanned_tree_declaration` and
`conformance.verdict_vocabulary_scope` (source_inputs).

- `mcp-re-conformance/BUILD.bazel`: two comments now name `.github/workflows/pre-merge.yml`
  instead of `ci.yml` (0fb4672f), with no rule change.
- `verification/generated/rust-targets.json`: the proxy's source lists gain
  `deployment_request/storage/replay_redis_pool_size.rs`. The workspace walk therefore scans
  one more file, which widens the measured estate. That file holds no `mcp-re.` literal
  (`grep -c` = 0).

## Unit fingerprints and the CI evidence

Review records, rulings, ledger lines and this packet enter no unit fingerprint:

- `tools/verification/_fingerprint.py` reads none of `verification/reviews/`,
  `docs/security/owner-approvals-*.jsonl` or `theorems.toml` for a unit.
- No unit `paths` names them.
- All 308 unit fingerprints were computed at `60a2257f` before and after this packet was
  written, and are identical.

So a complete `verification.yml` run on the release candidate stays valid evidence after the
records land, as it did for v0.18.0 (#1175). The closure is then re-evaluated with
`assurance-closure.yml` (`run_id` = that run) on the commit carrying the records.

## Ratification — who does what

The precedent is #1175: `verification/reviews/rulings/mcpre-218-assurance-closure-2026-10-14.md`
and `docs/security/owner-approvals-2026-10-14.jsonl`.

The "signature" is a ledger line in `docs/security/owner-approvals-<date>.jsonl` with these
fields:
- `ruling`: `owner-signature:<slug>`
- `approved_by`: `mats@sundvall.name`
- `approved`: the date
- `authority`
- `source`: the ruling document
- `surfaces`: the theorem ids
- `text`: the owner's ruling, verbatim
- `sha256`: `sha256(text)`, checked by `tools/verification/_approvals.py`; a line that does not
  hash refuses the whole ledger

There is no cryptographic key. The owner act is the ruling text itself.

- **Owner only:** read this packet and state the ruling, for example "APPROVED: ratify the five
  re-reviews in v0181-assurance-closure-2026-10-17.md; write the specification records at the
  exact current fingerprints and review digests; fail and re-read any item whose digest moved".
  The ruling, not the agent, is the review.
- **Agent, after the ruling:**
  1. write `verification/reviews/rulings/v0181-assurance-closure-2026-10-17.md` quoting it;
  2. append its ledger line to `docs/security/owner-approvals-2026-10-17.jsonl`;
  3. for each of THM-0077, 0086, 0092, 0106 and 0111, rewrite
     `verification/reviews/specification/<THM>.json` from
     `tools/verification/review --fingerprint <THM>` (`components`, `fingerprint` →
     `reviewed_fingerprint`, `review_components`, `review_digest`), keeping `axis`, `subject`
     and `reviewer` and extending `notes` with this packet and the ruling;
  4. re-check that `tools/verification/review` reports 133 of 133 REVIEW_CURRENT.
