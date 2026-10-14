<!-- SPDX-License-Identifier: Apache-2.0 -->

# Assurance-closure re-review packet — 92 stale theorem reviews (2026-10-14)

Layer 1 (measurement). Campaign #1171 (MCPRE-218). Baseline `main @ 72127a07`; evidence run
38513625401 (all lanes green; attestations issued from its `verification-evidence` artifact make
all 284 supporting units FRESH, EVIDENCE_ESTABLISHED 133/133).

## Method

Every specification review was current at `a0b944c4` (133/133), and no stale theorem's record
changed since, so the change each re-review had to read is exactly the semantic-input diff of its
supporting units over `a0b944c4..72127a07` (per unit and fingerprint component, from
`tools/verification/fingerprint --components` at both commits). Eight groups were read
independently against the theorem text (statement, consequence, scope), the bearing diffs, the
units' evidence (tests, mutation and structural probes, proofs), premises and `depends_on`.
No claim was edited by the re-review itself. Verdicts: CLEAN, CLEAN-NOTE (proposition holds; something cosmetic the owner
should see), DISCREPANCY (claim or its evidence closure no longer accurate).

Result: **0 claims found false. 87 ratifiable. 1 evidence-closure discrepancy held (THM-0092).
4 held for claim-prose that is now literally inaccurate (THM-0049, THM-0082, THM-0094,
THM-0095).** No formal-proof gap: proved, extracted and Lean-theorem sets, formal-model revision
and prover toolchain are unchanged; the one moved proof dependency (`clock_skew.rs`: doc,
`MaxClockSkew::ZERO`, a test) alters no proved proposition.

## Owner disposition

Ruled 2026-10-14 (`verification/reviews/rulings/mcpre-218-assurance-closure-2026-10-14.md`): the 87
are ratified; THM-0092 takes option 1 (the configuration owner joins its support and the claim
names both loci); THM-0049, THM-0082, THM-0094 and THM-0095 are corrected before their reviews
are recorded; the #1119 `ClaimWindow` edges are confirmed. The notes below are the re-review as
it was read before that ruling.

## Batch for ratification — 87 theorems

| packet | theorems |
|---|---|
| A — http_profile request & admission (Verus-backed) | THM-0001†, 0002, 0003, 0004, 0005, 0006, 0007, 0009, 0010, 0014, 0015, 0128 |
| B — http_profile response, delegation, JOSE | THM-0016, 0017, 0018, 0019†, 0020†, 0021, 0022, 0039†, 0042, 0053, 0065, 0129 |
| C1 — proxy TLS identity, revocation, currency | THM-0013†, 0024, 0026, 0027†, 0031, 0032, 0054, 0102, 0131 |
| C2 — proxy trust plan, composition root, snapshot | THM-0037, 0038, 0066, 0067†, 0097, 0098, 0099, 0100, 0133 |
| D — proxy dispatch, refusal, audit | THM-0040, 0045, 0046, 0051, 0052, 0069, 0070, 0071, 0074‡, 0075‡, 0078, 0081, 0085, 0088 |
| E1 — proxy posture, lifecycle, replay, continuation | THM-0012, 0048, 0077†‡, 0083, 0086, 0093, 0096, 0101, 0104, 0132 |
| E2 — proxy signing credentials, identity, KMS, retention | THM-0062, 0073†, 0080, 0087, 0089, 0112, 0113, 0116 |
| F — client, SDKs, conformance | THM-0058, 0059, 0061, 0076, 0084, 0091, 0111, 0120, 0122, 0123, 0124, 0126, 0127 |

† CLEAN-NOTE (notes below). ‡ depends on THM-0092: REVIEW_CURRENT on ratification, CURRENTLY_VERIFIED
only once THM-0092 is resolved.

Ratifying the batch gives REVIEW_CURRENT 128/133 and CURRENTLY_VERIFIED 125/133 with run
38513625401's evidence (fingerprints byte-identical; records do not enter unit fingerprints).

### Notes on the CLEAN-NOTE items (no decision required)

- THM-0001: `out_of_bounds_configuration_fails_closed` lost its negative/over-bound skew cases;
  that refusal is now `MaxClockSkew::new`'s (core), outside this unit's test selection. The scope
  already disclaims skew boundedness.
- THM-0013: #1157 deleted the "THM-0013 evidence, half one" doc comment; the test is intact.
- THM-0019 / THM-0020: since #1144 the delegation window is the shared JOSE rule
  `nbf<exp ∧ nbf−s ≤ now < exp+s ∧ iat ≤ now+s` (was `nbf−s ≤ now ≤ exp+s`). It only refuses
  more; neither claim states the edge. This is the #1119 default taken without a ruling (decision
  item C below asks you to confirm it).
- THM-0027: #1113 changed structural probe S06's description to "both fields"; the type has three.
  S38 has the same error. Description text only.
- THM-0039: mutation probe M71's conjunct label now overstates it (it kills only the
  `IssuerUntrusted` mapping); resolution and signature moved into the shared codec, guarded by
  M573 and `an_unresolvable_issuer_is_untrusted_not_a_bad_signature`.
- THM-0067: the `ORDINARY` inventory reason for `limits` (`composition_raw_read_test.rs:66-70`)
  names only `max_connection_age` as owned; #1157 made `ConnectionBounds` own five members.
- THM-0073: the scope's pairing of M432 with the provenance test is out of date; M432 now weakens
  the chain read in `channel_credential.rs`, caught by `an_unreadable_channel_chain_refuses_establishment`.
- THM-0077: the delegated depth-1 refusal moved to configuration (X10, #1154); every validated path
  reaches it. Its controls live in `proxy.delegated_tls_depth_refusal`, not in THM-0077's support
  (already so at a0b944c4). After #1149 `CorePool::for_core` raises a stated depth 1 under delegated
  custody, so X10 is the only guard on a stated 1.

## Held — decisions for the owner

### A. DISCREPANCY — THM-0092 evidence closure (held; blocks THM-0074, 0075, 0077 from CURRENTLY_VERIFIED)

The statement: "Under the fleet-strict posture, replay admission refuses before any store side
effect when the deployment declares no replay tier, …". Since #1113 an undeclared tier cannot
reach replay admission: `ReplayPosture::FleetStrict(ReplayDurabilityTier)` carries a mandatory
tier, the one production `ReplayAdmission::new` (`replay_plane/materialized.rs:99`) always passes
`FleetStrict(plan.tier())`, and an undeclared tier is refused at layer A by
`proxy.replay_configuration_state` (`no_declared_tier_yields_no_state`,
`a_shared_store_with_no_declared_tier_names_no_state`). The test that pinned the old refusal,
`fleet_strict_refuses_undeclared_tier`, was deleted. So the PROPERTY holds and is stronger, but
(1) the statement attributes the refusal to replay admission, which no longer performs it, and
(2) none of THM-0092's three supporting units holds a control for that conjunct.
Options:
1. Correct the claim: add `unit://proxy.replay_configuration_state` to `supported_by` and say the
   undeclared tier is refused before replay admission is reachable (claim fingerprint moves; your
   specification approval at the new text).
2. Narrow the claim to the two conjuncts its units establish (sub-minimum tier, single-process
   store class) and leave the undeclared tier to THM-0077, whose support already includes
   `proxy.replay_configuration_state`.
Recommendation: 1 — it keeps the operator-facing promise in the theorem readers look for.

### B. Claim prose now literally inaccurate (proposition holds; held so nothing false is ratified)

- THM-0082 statement: "reads it through the role-separation witness's one borrowed projection".
  #1111 deleted that projection (`key_source()`); the root reads `channel_credential()` and the
  response key through the witness's own `ResponseSigner` impl, and the source never leaves the
  witness. Stronger, but the sentence names a mechanism that no longer exists.
- THM-0049 scope: "Three are live — X2a, X6, X9 — and those are what a validated deployment is held
  to." X10 is now live too, so the scope understates what the classifier refuses.
- THM-0094 / THM-0095 scope: "`sdk_{python,typescript}.native_binding` owns what the binding does
  with the values … and the core's verdict." Since #1151 `sdk_binding_core.adapter` owns that; both
  units are in `supported_by`.
Options per item: (a) ratify the semantic re-review and correct the sentence in a claim
correction (claim fingerprint moves, your approval at the new text), or (b) ratify as is.
Recommendation: (a), one claim-correction PR for all four.

### C. Confirmation — #1119 delegation window default

#1144 applied the majority `exp` edge to delegation credentials without a ruling: refused at
exactly `exp+skew`, when `exp ≤ nbf`, and when `iat` is more than `skew` ahead. Strictly more
refusing; no claim depends on the edge. Confirm, or rule otherwise.

### D. Observations outside this campaign's claims

- TypeScript `coreWireCode` trusts any thrown object's `code` in the `mcp-re.` namespace, so a custom
  `poster` throwing one reads as a peer token (same exposure as the old message parser; pre-existing).
- A core refusal raised while signing still reaches the application as a wire code (pre-existing).

## Appendix — per-theorem re-review records (packets A–F)

---

## Re-review packet A — http_profile request/admission (Verus-backed) — main 72127a07

Read-only re-review. Reference point for "changed since review": a0b944c4 (every review current).

### Shared change set (triage)

Every http_profile unit's `source_inputs` pulls in the crate closure, so ten of the twelve
theorems show the same 41-42 changed files. Commits over that set, a0b944c4..72127a07:

| commit | what it changed | bears on group A claims? |
|---|---|---|
| 432f0081 MCPRE-191 | `VerifierPolicy::new` takes a `MaxClockSkew` instead of an `i64` (range check moves to the type); new `with_max_clock_skew`; tests updated | THM-0001/0014 read: skew still read through `VerifierPolicy::max_clock_skew` (proved symbol, unchanged); the claim is relative to `skew_of(policy)` and disclaims boundedness |
| 7bc25021 MCPRE-194 | admission assertion, admission-state record, delegation and PDP decision JWS handling now go through one `CompactJws` codec + one `ClaimWindow::check` | THM-0003..0006 read: only `verify_admission_assertion` (outside the proof cone, ASM-0012) and its issuer changed; semantics equal (below) |
| 75fae5e3 MCPRE-196 | `admission_policy.rs` doc names `EnforcedAdmission::enforcer_policy` (exists, `config_state/admission.rs:229`) | doc only |
| cab75969 MCPRE-184 | `PreparedDispatch::admit(answer)` replaces `into_admitted_outcome`; replay answer read in one place | THM-0009 read: `prepare_http_dispatch` (proved symbol) unchanged |
| 4312c49a MCPRE-182 | `retained_continuation.rs` doc: correlation lookup has one owner (proxy continuation plane) | THM-0010 read: doc only; constructor unchanged |
| 87f3424a MCPRE-212 | `RequestRoleEvidence::of_signed_request` is the one derivation of a signed request's handle; `verify/bound_request.rs` deleted, its tests moved | response-side and bodyless handle derivation; request-floor verification path (`verify/floor/*`) unchanged |
| 61605e13 MCPRE-211 | `SigningWindow` sole producer of delegated signed products (sign.rs, custody/*) | response signing; unrelated to request admission |
| 11c92802 MCPRE-200 | `clock_skew.rs`: refuse-not-clamp doc, `MaxClockSkew::ZERO` (= `Self(0)`, in range), one test | the one `proof_dependencies` change for the five Verus units; adds no behaviour to any proved function |

Formal surfaces: proved symbols, extracted symbols, Lean theorems, formal-model revision and
toolchain unchanged for every unit here; run 38513625401 passed Verus 6/6, Lean, generated model.

#### THM-0001 — Admitted request parameters imply a current freshness window
Verdict: CLEAN-NOTE
Changed since review: `http_profile.freshness_window` source_inputs (crate closure), proof_dependencies (`clock_skew.rs`), test_selection (+1 symbol).
What was read: `policy.rs`/`policy/bounds.rs` diff (432f0081), `clock_skew.rs` diff, unit tested_symbols at both commits.
Why it holds: `check_params` and `VerifierPolicy::max_clock_skew` are unchanged; the skew field is now only ever written from a `MaxClockSkew` (`new`, `with_max_clock_skew`), which strengthens rather than weakens the input; the claim is stated relative to `skew_of(policy)` and its scope disclaims boundedness.
Evidence: verus://http_profile/verify/check_params_admission_implies_fresh (PASS on 72127a07); tested_symbols: no symbol removed, `policy::tests::the_skew_a_policy_is_given_is_the_skew_it_applies` added.
Note: `policy::tests::out_of_bounds_configuration_fails_closed` lost its negative / over-bound skew assertions, because `VerifierPolicy::new` can no longer receive one; that refusal is now `MaxClockSkew::new`'s (`clock_skew.rs` `a_negative_or_unbounded_tolerance_is_not_constructible`), which is not in this unit's selection. No effect on THM-0001, whose scope excludes skew boundedness.

#### THM-0002 — RFC 3339 parsing is total and range-bounded
Verdict: CLEAN
Changed since review: `core.time_rfc3339` source_inputs: `mcp-re-core/src/time/clock_skew.rs` only.
What was read: full `clock_skew.rs` diff (11c92802).
Why it holds: the change is a doc paragraph, a `ZERO` constant and a test in a sibling module; `parse_rfc3339_utc`, `days_from_civil`, `verus_proofs.rs`, `verus_std_specs.rs` untouched.
Evidence: verus://core/time/parse_rfc3339_utc_total_and_bounded (PASS), test://core/time/grammar_and_truncation.

#### THM-0003 — Admission verdict integrity
Verdict: CLEAN
Changed since review: `http_profile.admission_currency` source_inputs (closure), proof_dependencies (`clock_skew.rs`).
What was read: `admission/mod.rs` diff in full; `admission/authenticated.rs`, `admission/verdict.rs`, `authoritative_admission/mod.rs` confirmed byte-unchanged; `check_admission` body unchanged (only a test import in that hunk).
Why it holds: the verdict-building code under the proof is untouched; the change is confined to issuing/verifying the assertion, which the scope places outside the proof cone (ASM-0012).
Evidence: verus://http_profile/admission/check_admission_currency (PASS), test://http_profile/admission/currency_and_degraded_battery, mutation://http_profile/admission/subject_currency.

#### THM-0004 — Admission anti-rollback
Verdict: CLEAN
Changed since review: as THM-0003.
What was read: as THM-0003, plus the scope's seal statement: `AuthoritativeAdmission` (authoritative_admission/mod.rs) unchanged, still `#[non_exhaustive]`, no struct literal outside its module (`git grep "AuthoritativeAdmission {"` empty).
Why it holds: subject, generation and status conjuncts are established by the unchanged `check_admission` postcondition over the unchanged `AuthoritativeAdmission`.
Evidence: as THM-0003.

#### THM-0005 — A degraded admission is a CANDIDATE, and requires deployment opt-in
Verdict: CLEAN
Changed since review: as THM-0003.
What was read: as THM-0003; `admission_policy.rs` diff (doc only); `degraded_age_exceeded` unchanged.
Why it holds: the two-variant verdict and the P-age conjunct are in unchanged proved code; the doc now names the proxy projection (`EnforcedAdmission::enforcer_policy`, present) instead of `serving_capabilities`.
Evidence: as THM-0003.

#### THM-0006 — Presenter binding
Verdict: CLEAN
Changed since review: as THM-0003.
What was read: as THM-0003; `authenticate_admission` (authenticated.rs) unchanged.
Why it holds: the presenter equality is established by unchanged proved code.
Evidence: as THM-0003.

Semantic equivalence of the codec move under THM-0003..0006's ASM-0012 boundary (read so the
premise still describes the code): `CompactJws::verify_root` checks `typ` and `alg == EdDSA`,
`header.kid == claims.issuer_kid`, resolves the issuer through the seam (absent → untrusted),
and verifies Ed25519 strictly over `header.payload`; `ProtectedHeader` is `deny_unknown_fields`.
`ClaimWindow::check` refuses `exp <= nbf`, `nbf - s > now`, `exp + s <= now`, `iat > now + s`
— the same four conditions the deleted inline code tested, same saturation. The old explicit
signature normalisation (decode/re-encode) is replaced by `verify_ed25519_with`'s own decode,
which refuses the same malformed segment. Refusal tokens unchanged.

#### THM-0007 — A typed artifact verifier admits only its own type
Verdict: CLEAN
Changed since review: `http_profile.artifact_typing` source_inputs (closure only), proof_dependencies (`clock_skew.rs`).
What was read: changed-file list — no `artifact*.rs`, `artifact/thumbprint.rs`, `block/artifact_binding/*` file moved.
Why it holds: none of the unit's own files changed; the closure changes are unrelated (triage table).
Evidence: verus://http_profile/artifact/typed_verifier_admits_only_its_own_type (PASS), test://http_profile/artifact/typed_binding_battery.

#### THM-0009 — A presented continuation cannot bypass verification
Verdict: CLEAN
Changed since review: `http_profile.continuation_unbypassability` source_inputs (incl. dispatch.rs, dispatch/outcome.rs, dispatch/retained_continuation.rs), proof_dependencies (`clock_skew.rs`).
What was read: full diffs of the three dispatch files (cab75969, 4312c49a).
Why it holds: `prepare_http_dispatch` (the proved symbol) is unchanged. The new `PreparedDispatch::admit` copies `continuation_verified` unchanged into `DispatchOutcome` and only on `Fresh`; `Replay` and store errors refuse distinctly. `DispatchOutcome` is still producible only from a `PreparedDispatch` (S34). Depends on THM-0010 (CLEAN).
Evidence: verus://http_profile/dispatch/continuation_present_implies_verified (PASS), test://http_profile/dispatch/continuation_binding_battery; new tests `a_replay_answer_is_refused_as_a_replay`, `a_store_that_did_not_answer_is_an_outage_and_never_a_replay`; the removed `an_operational_store_failure_fails_closed_and_never_admits` is superseded by the latter.

#### THM-0010 — Continuation handles match their retained evidence in slot
Verdict: CLEAN
Changed since review: `http_profile.continuation_binding` source_inputs (closure only), proof_dependencies (`clock_skew.rs`).
What was read: block.rs, evidence/digest.rs, evidence/role.rs, ids.rs unchanged; retained_continuation.rs diff (doc); constructor sites (`git grep RetainedContinuation::from_correlation`): the proxy answer leg (`answer_leg.rs:158`) and tests.
Why it holds: `HttpContinuation::verify` and `RequestEvidenceDigest::same_handle` unchanged; the scope's hand-off statement (answer leg via `from_correlation`, the only constructor) still true.
Evidence: verus://http_profile/block/continuation_handles_match_in_role (PASS), test://http_profile/block/continuation_role_battery.

#### THM-0014 — A successful request-floor verification establishes the cryptographic floor
Verdict: CLEAN
Changed since review: `request_floor_result` source_inputs (request_role.rs, policy.rs, verify/mod.rs) + test_sources (algorithm_confusion_test.rs); `freshness_window` as THM-0001.
What was read: diffs of all four; MCPRE-212 commit body.
Why it holds: `verify/floor/*` unchanged; verify/mod.rs only drops the deleted `bound_request` module (response-side handle derivation now in `RequestRoleEvidence::of_signed_request`); policy algorithm guard unchanged; the test edit only wraps `30` in `MaxClockSkew::new(30)`, same assertion. tested_symbols identical. Depends on THM-0001 (CLEAN-NOTE, proposition holds).
Evidence: test://http_profile/request_floor/what_a_successful_return_establishes, mutation://…same; algorithm_confusion_test battery.

#### THM-0015 — A successful full-profile request verification establishes audience and artifact binding
Verdict: CLEAN
Changed since review: `request_full_result` source_inputs (request_role.rs, policy.rs, verify/mod.rs); the other three supporting units unchanged.
What was read: as THM-0014; tested_symbols identical at both commits; `pdp_decision/binding` unchanged (the pdp_decision/verify.rs change is the JWS codec move, a decision's authority/validity, which the scope assigns to the authorization owner).
Why it holds: audience/target/artifact-binding code is unchanged; depends on THM-0014 (CLEAN), THM-0007 (CLEAN), THM-0008 (current).
Evidence: test://http_profile/request_full/audience_and_artifact_binding, mutation://…same; full_profile_test battery incl. the three carried-decision tests.

#### THM-0128 — The civil-date conversion is total on the domain its caller can supply
Verdict: CLEAN
Changed since review: `core.time_civil_from_days` source_inputs: `clock_skew.rs` only.
What was read: `clock_skew.rs` diff.
Why it holds: `civil_from_days` and its extraction untouched; extracted symbols and Lean theorem set unchanged; Lean lane PASS on 72127a07.
Evidence: lean theorem over the Charon/Aeneas model (PASS in run 38513625401).

---

## Re-review packet B: http_profile response / delegation / JOSE (main 72127a07)

Every review in this group was current at a0b944c4. These are the commits that moved semantic inputs of a
supporting unit in `a0b944c4..72127a07`. Each was read as a diff:

- **#1144 7bc25021 (MCPRE-194).** Adds one compact-JWS codec (`delegation/jose/{compact_jws,claim_window,protected_header,mod}.rs`)
  and one claim window. The admission assertion, PDP decision, authoritative admission record and delegation credential
  now all split, decode, check `typ`/EdDSA, check header-kid == issuer_kid, resolve the root and verify through
  `CompactJws::verify_root`. The four private `split_compact`/`decode_json`/header types are deleted. It also adds the
  new unit `http_profile.jose_statement`, which now supports THM-0019/0020/0039/0053/0129.
- **#1160 11c92802 (MCPRE-200).** The skew becomes a typed `MaxClockSkew` (`VerifierPolicy::new`,
  `DelegationExpectations::max_clock_skew`), and the delegation `bounded_skew` clamp is deleted.
  `clock_skew.rs` changes only by a doc paragraph, `ZERO` and a test.
- **#1163 87f3424a (MCPRE-212).** `verify/bound_request.rs::request_evidence_of` moves verbatim to
  `RequestRoleEvidence::of_signed_request` (`evidence/request_role.rs`), using the same single-header,
  `mcp-re`-member, `parse_signature_input` and `signature_base` steps via `parse_signature_input_for`. Its four
  tests move with it, and the `tested_symbols` are renamed accordingly.
- **#1162 61605e13 (MCPRE-211).** Delegated response emission takes a `DelegatedSigner` read from one `SigningWindow`
  (`custody/delegated_signer.rs`). The runtime `require_signer_is_delegated_key` refusal is replaced by
  `ActiveDelegatedKey` construction, and test fixtures use the testonly `SigningWindow::stated` /
  `ActiveDelegatedKey::stated` (`#![cfg(any(test, feature = "pre_052_fixtures"))]`).
- **Fixture plumbing only.** #1161 4dc1510a, #1113 5f7a4cac, #1154 0ba3db26 and #1109 abd8f49f touch the proxy and
  conformance test sources only to construct `ReplayAdmission` / `MaxClockSkew` / `SigningWindow`. A grep of the
  diffs for removed `#[test]`, `fn`, `assert*`, `expect_err` and `unwrap_err` lines finds no deleted test and no
  deleted assertion.

Untouched across the whole range: `verify/floor/**`, `verifier.rs`, `ids.rs`, `verus_std_specs.rs`,
`evidence/prover_model.rs` and `sigbase`. The request/response floor and the Verus cone are byte-identical.

**Triage of the 41-file `http_profile.freshness_window` `source_inputs` set (THM-0016/0017/0021/0022):**
- The unit's own floor files did not change.
- `policy.rs` changed by the typed skew only. `check_params` still reads `policy.max_clock_skew()`. The bound now
  holds by type rather than by a runtime check in `new`, and the new `with_max_clock_skew` builder also takes a
  `MaxClockSkew`.
- `policy/bounds.rs` changed in a test only.
- The rest is admission / custody / delegation / pdp / bodyless / dispatch / sign code reached through the crate
  module closure, and none of it is on the response-verification path.
- `test_selection` gains `policy::tests::the_skew_a_policy_is_given_is_the_skew_it_applies`.

---

#### THM-0016: a successful bound response-floor verification establishes trust-seam authorization of the signer
**Verdict:** CLEAN
- **Changed since review:**
  - `bound_response_seam_result`: `source_inputs` (`request_role.rs`, `policy.rs`, `verify/mod.rs`).
  - `freshness_window`: `source_inputs`, `proof_dependencies` (`clock_skew.rs`), `test_selection`.
- **Read:** the verify/ diffs, the `policy.rs` diff and `clock_skew.rs`.
- **Why it holds:** the floor path (`floor_bound_response`, slot resolution for Response, the accepted-signer
  equality) is unchanged. `verify/mod.rs` only drops `pub(crate) mod bound_request`.
- **Evidence:** the unit battery is unchanged, the freshness Verus proof `check_params_admission_implies_fresh` was
  re-proved on the final tree, and run 38513625401 is FRESH. Depends on THM-0021 (CLEAN).

#### THM-0017: a successful unbound response-floor verification establishes trust-seam authorization and no request binding
**Verdict:** CLEAN
- **Changed since review:** as THM-0016, plus `unbound_response_seam_result` `test_sources` (`delegation_e2e_test.rs`,
  fixture plumbing to `SigningWindow::stated`, no test or assertion removed).
- **Why it holds:** the unbound floor is unchanged, and the `;req`-is-malformed refusal sits in the untouched
  `verify/floor`. Depends on THM-0022 (CLEAN).

#### THM-0018: a successful full bound response verification establishes block agreement with the expected handle
**Verdict:** CLEAN
- **Changed since review:** `bound_response_full_result` `source_inputs` (`request_role.rs`, `policy.rs`, deleted
  `bound_request.rs`, `full/response.rs`, `verify/mod.rs`) and `test_selection` (the three handle tests renamed
  `verify::bound_request::tests::*` → `evidence::request_role::tests::*`).
- **Why it holds:** `full_bound_response` still derives the handle from the one `request` (now
  `RequestRoleEvidence::of_signed_request(request)`, the same algorithm) after the block parses. It compares that
  handle with `block.request_evidence` and `server_signer.keyid` with the floor's resolved keyid. There is still no
  second request operand, so the "ONE request input" paragraph of the claim is still accurate.
- **Evidence:** the `full_profile_test` handle and splice tests, plus `request_role::tests::{a_derived_handle_agrees_with_the_signers_handle,
  a_request_differing_in_a_covered_component_derives_a_different_handle, a_thin_covered_set_cannot_reproduce_a_signed_handle}`.

#### THM-0019: a successful delegated bound response verification establishes an accepted credential chain
**Verdict:** CLEAN-NOTE

**Changed since review:**
- `delegated_bound_result`: `source_inputs` (`full/delegated/bound.rs`, `expectations.rs`, `request_role.rs`, `policy.rs`)
  and `test_sources` (e2e plumbing).
- `delegated_credential_chain`: `source_inputs` (the jose codec, delegation `verify`/`parse`/`root_signed`/`issue`/`mod`)
  and `test_selection`, `test_sources`, `trusted_assumptions` (ASM-0069 text).
- New unit: `http_profile.jose_statement`.

**Why it holds:**
- `verify_delegation_credential` still runs, in order: `CompactJws::split` (three non-empty segments);
  `verify_root(DELEGATION_TYP)`, which checks the header `typ`, EdDSA, header kid == `issuer_kid`, and resolves the
  root through the caller's resolver (`IssuerUntrusted` → `DelegationIssuerUntrusted`); the Ed25519 signature over
  `h.p`; then `cnf.x != root`, `check_freshness`, `check_scope`, `check_epoch_and_revocation`, and `delegated_key`
  (`cnf` kid == `delegated_kid`).
- `bound.rs` still derives the handle from the same request and still requires the delegated kid on three sides
  (`DelegationKeyMismatch`).
- The claim's "accepted under the supplied expectations" survives. The expectations are still caller-supplied, and
  the skew is now a `MaxClockSkew`.

**Note for the owner (behaviour narrowed, claim unaffected).** The credential window is now the shared jose rule
`nbf < exp ∧ nbf-s <= now < exp+s ∧ iat <= now+s`. Before #1144 the delegation check was `nbf-s <= now <= exp+s`,
inclusive at `exp+s`, with no degenerate-window or future-`iat` refusal. So a credential is no longer accepted at
exactly `exp+skew`, nor with `exp <= nbf`, nor with an `iat` more than `skew` ahead.

This is strictly a narrowing. The claim does not state the edge rule, and the jose unit's description states the new
rule exactly. ASM-0069 is owner-approved at its current text. The old tests
`configured_skew_above_the_hard_cap_does_not_widen_the_credential_window` and `negative_configured_skew_is_treated_as_zero`
became `the_widest_constructible_skew_is_the_bound_and_applies_in_full` and `a_zero_skew_admits_exactly_the_credential_window`:
the out-of-range skews are now unconstructible, and the tests pin both edges.

**Evidence:**
- the jose battery: 18 `tested_symbols`, including `the_four_verifiers_share_one_window_rule`;
- M572 (window edge) and M573 (root signature skipped);
- `chain_reconstruction_test` and `delegation_e2e_test`.

#### THM-0020: a successful delegated unbound response verification establishes a chain and never a binding
**Verdict:** CLEAN-NOTE
- **Changed since review:** as THM-0019, with `delegated_unbound_result` (`expectations.rs`, `request_role.rs`,
  `policy.rs`, `verify/mod.rs`) and e2e plumbing.
- **Why it holds:** it uses the same credential chain path as THM-0019. The unbound path reads no request, and the
  `;req` refusal is in the unchanged floor.
- **Note:** the same credential-window narrowing as THM-0019.
- Depends on THM-0022 (CLEAN).

#### THM-0021: a successful bound-response verification establishes the shared cryptographic and request-binding facts
**Verdict:** CLEAN
- **Changed since review:** `bound_response_shared_facts` `source_inputs` (`request_role.rs`, `policy.rs`,
  `rejection/mod.rs`, deleted `bound_request.rs`, `delegated/bound.rs`, `verify/mod.rs`), `test_sources`, and the
  freshness_window set triaged above.
- **Why it holds:** the digest, params and `;req` signature check are all in the unchanged `verify/floor`.
  `rejection/mod.rs` changes only the emission side: the `*_with_owned_key` builders become crate-private
  `emit_delegated_rejection*` over a `DelegatedSigner`. Depends on THM-0001 (outside this group).

#### THM-0022: a successful unbound-response verification establishes the shared facts and no request binding at all
**Verdict:** CLEAN
- **Changed since review:** `unbound_response_shared_facts` `source_inputs` (`request_role.rs`, `policy.rs`,
  `rejection/mod.rs`, `verify/mod.rs`), `test_sources`, and the freshness_window set.
- **Why it holds:** as THM-0021. The verification side is unchanged.

#### THM-0039: an accepted PDP decision was authenticated under a key the trust seam resolved
**Verdict:** CLEAN-NOTE
- **Changed since review:** `pdp_decision_authentication` `source_inputs` (the jose codec, `pdp_decision/{claims,issue,verify}.rs`)
  and `mutation_probes` (M71 re-anchored). New unit: `jose_statement`.
- **Why it holds:** `verify_authorization_decision` performs every conjunct of the claim:
  - well-formed compact JWS;
  - `typ` = `PDP_DECISION_TYP` and alg EdDSA, with `deny_unknown_fields` on the header, so "no others" holds;
  - header kid == `issuer_kid`;
  - signature under the key the caller's AUTHORIZATION resolver returned (`IssuerUntrusted` keeps its own variant);
  - profile, then audience;
  - the window `[nbf-s, exp+s)` with `exp > nbf` (`Degenerate`/`Outside` → `Expired`);
  - `iat <= now+s` (`IssuedInTheFuture`, kept distinct);
  - `decision_age_exceeded` over i128 against `max_decision_age + skew`, unchanged.

  Old and new are equivalent apart from refusal naming: a non-base64url signature segment now reads
  `SignatureInvalid` rather than `Malformed`. `Deny` still returns Ok.
- **Note for the owner:** probe M71's conjunct text is "the signature verified under the key the trust seam
  resolved for the issuer kid". It now only kills the mapping `JwsDefect::IssuerUntrusted → PdpDecisionRefusal::IssuerUntrusted`.
  The resolution and the signature check moved into the shared codec, where M573 guards the signature and the jose
  test `an_unresolvable_issuer_is_untrusted_not_a_bad_signature` pins the unresolvable-kid refusal.

  The proposition is still established, because a root key cannot be produced except by the resolver, so skipping
  resolution is not expressible without fabricating a key. But M71's conjunct label now overstates what that one
  probe kills. This is an evidence-label point, not a claim discrepancy.

#### THM-0042: retained evidence is the evidence the statement was made about
**Verdict:** CLEAN
- **Changed since review:** `conformance.retained_corpus` `source_inputs` and `test_sources`
  (`scitt_retained_corpus_test.rs`).
- **Read:** the full diff. The skew became `MaxClockSkew::new(60)` and the hop signing moved to
  `sign_delegated_response_full(SigningWindow::stated(...))`.
- **Why it holds:** the `verify_retained_evidence` code is untouched, and so are the units
  `scitt_retained_correspondence` and `submitted_hop_identity`. No corpus assertion changed.

#### THM-0053: a presented admission assertion is authentic, in its window, and for this audience
**Verdict:** CLEAN
- **Changed since review:** `admission_assertion` `source_inputs` (`admission/mod.rs`, doc-only `admission_policy.rs`,
  the jose codec) and `mutation_probes` (M233 narrowed to the age cap; new M571 on the jose future-`iat` clause).
  New unit: `jose_statement`.
- **Why it holds:** `verify_admission_assertion` is now `verify_root(ADMISSION_TYP)`, then profile, audience,
  `window().check(now, policy.max_clock_skew)` and the exact age cap. Every conjunct holds:
  - trust-seam issuer resolution (`AdmissionIssuerUntrusted`);
  - typ/alg pinned;
  - profile and audience;
  - `iat` ahead refused (now inside the window check, killed by M571);
  - the window and the budget, each widened by the skew.

  The half-open `exp+s` edge is identical to the old code, so the claim's `[nbf, exp]` wording describes the same
  rule it did at the last review. Old and new are equivalent apart from refusal naming. The future-`iat` conjunct M233
  used to carry is now M571's, so its control is kept and moved, not lost.

#### THM-0065: an emitted bound response signature binds the request it answers
**Verdict:** CLEAN

**Changed since review:**
- `response_emission_binding`: `source_inputs` (`sign.rs`, `sign/request.rs`, `custody/{delegated_signer,window_emission}.rs`,
  `rejection/pre_052_direct_root.rs`) and `test_selection`, `test_sources` (`delegated_202_test.rs`).
- `mutation_probes`: M541 moved to `delegated_signer.rs`.

**Why it holds:**
- `emit_delegated_response_full` still derives `request_evidence` from the request being answered (the same
  derivation, now `RequestRoleEvidence::of_signed_request`). It still signs `;req` against that request through
  `sign_response_with_signer`.
- An unsigned request still yields no handle (`an_unsigned_request_cannot_be_answered_with_a_bound_response`).
- The removed runtime check `require_signer_is_delegated_key`, and its test `a_delegated_response_is_refused_when_the_signer_names_another_key`,
  concerned which key signs. The claim's scope puts that outside THM-0065 (it is THM-0062/0063). It is now held by
  `ActiveDelegatedKey` construction and M541 → `every_part_is_read_from_the_one_window`, under the NP-204 re-review of THM-0063.

**Evidence:** the `full_profile_test` five binding tests, `delegated_202_test` (three tests, plumbing only) and the
`sign::tests` handle tests. Depends on THM-0021 and THM-0022 (both CLEAN).

#### THM-0129: authoritative admission state is authenticated and bounded-current
**Verdict:** CLEAN

**Changed since review:**
- `admission_state_provenance`: `source_inputs` (`record/{mod,verified,currentness}.rs`, the jose codec) and
  `mutation_probes` (M133 re-anchored).
- New unit: `jose_statement`.
- `proxy.admission_state_source`: `test_sources` (17 integration test files, construction plumbing only:
  `ReplayAdmission`/`ReplayPosture`, `MaxClockSkew`; no test or assertion removed).

**Why it holds:**
- `verify_admission_state_record` is `verify_root(ADMISSION_STATE_TYP)`, so the signature covers `h.p` with `typ` in
  the header and the subject, generation, status, sequence, issuer and time claims in the payload. The claims struct
  is unchanged.
- `IssuerUntrusted` and `SignatureInvalid` are preserved, and the subject comparison and the currentness ceiling are
  unchanged.
- The window check is the identical rule, now `ClaimWindow::check`. The old inline check had the same four clauses.

**Evidence:**
- M133's new weakening skips `verify_root` (it parses the claims and never resolves or verifies), and its expect_red
  set is unchanged.
- M573 covers the codec signature.

Depends on THM-0132 (outside this group).

---

## Re-review packet C1 — proxy TLS identity, revocation, credential currency

Main 72127a07; reviews last current at a0b944c4. Evidence: run 38513625401, all supporting units FRESH.
Method: per theorem, the commits that moved each supporting unit's semantic inputs were
identified (`git log a0b944c4..72127a07 -- <files>`), the bearing diffs read, and every
`tested_symbols` member of every changed unit compared body-for-body between a0b944c4 and
72127a07 (a one-off comparison script, not kept): 122 unchanged, 4 flagged — 2 were false positives
(same fn name in other files; bodies identical), 2 are the `app::run` -> `app::run_request`
API adaptation in `app_startup_characterization_test.rs` (#1109), read below. No tested symbol
in this group is missing or weakened.

Shared change set, triaged once:
- `mcp-re-proxy/src/tls.rs` (a36c92ff #1157): `ServerLimits` defaults now name the
  `config_state::connection_bounds` constants (same 30s/256/30s values) and `ServerOptions`
  gains `connection_bounds`. Touches no identity, correspondence, resolver, peer-resolution or
  currency-classification code. Bears on none of THM-0026/0027/0031/0032/0054 claims.
- `mcp-re-proxy/tests/integration/*.rs` (#1109, #1110, #1111, #1113, #1154, #1116): fixture
  plumbing — `parse_args(...)` now returns `ValidatedDeployment` so tests call `.into_inner()`,
  and in-code configs go through `app::run_request`, which is `ValidatedDeployment::try_from`
  then `run` (`app.rs:101-106`). No assertion removed or weakened.
- `mcp-re-proxy/tests/integration_async/*`, `tests/common/mod.rs` (#1109, #1113, #1154, #1160,
  #1161): same plumbing plus typed `MaxClockSkew`; per-request-revocation tested symbols identical.

#### THM-0013 — No validated deployment enables online OCSP client-certificate revocation
Verdict: CLEAN-NOTE
Changed: unit `proxy.online_ocsp_reachability` source_inputs `config_state/validation/{mod,residue}.rs`
(a36c92ff #1157, 097b06ec #1165, 0ba3db26 #1154); test_sources (integration plumbing).
Read: residue.rs diff — 124 deleted lines are the connection-ceiling / drain-window /
slow-loris clauses moving to the `ConnectionBounds` owner; `online_ocsp_refusal`,
`ocsp_mode_violations`, `ocsp_responder_url_violations` untouched; `validation/mod.rs:220-222`
still extends violations with both OCSP clauses on the boundary. `ValidatedDeployment` is built
only in `TryFrom<DeploymentRequest>` (`validation/mod.rs:104-115`); `parse_args` and
`run_request` both go through it.
Why it holds: the refusal of `OnlineRevocationEvidenceRequest::Required` is still on the only
route to a `ValidatedDeployment`, feature-independent.
Evidence: `residue::tests::no_build_admits_the_online_ocsp_mode`,
`the_boundary_clause_carries_the_online_ocsp_refusal` (bodies unchanged);
`app_startup_characterization_test::a_programmatic_config_cannot_claim_an_ocsp_check_the_serving_path_never_makes`
(now `run_request`, which validates — same boundary); `online_evidence` tests unchanged; mutation lane M62 passed.
Note: #1157 deleted the doc comment "THM-0013 evidence, half one: no build honours
`--client-ocsp require` …" above `no_build_admits_the_online_ocsp_mode` together with the
neighbouring drain tests; the test is intact, only its labelling comment is gone ("half two"
still refers to it).

#### THM-0024 — Certificate identity interpretation reads the configured field and refuses rather than falling back
Verdict: CLEAN
Changed: `proxy.certificate_identity` test_sources only (integration plumbing above).
Read: no certificate-identity source file changed; authority_boundary and refusal_vocabulary
units unchanged; all tested symbols identical. Premise ASM-0030 REVIEWED; dep THM-0023.
Why it holds: interpreter, fields, policy, refusal and evidence sources are byte-identical.
Evidence: `test://proxy/certificate_identity/no_fallback_interpretation` members unchanged; mutation pass.

#### THM-0026 — Credential/key correspondence relates two independently interpreted keys …
Verdict: CLEAN
Changed: `proxy.credential_key_correspondence` source_inputs `tls.rs` (a36c92ff) only.
Read: tls.rs diff (connection-bounds defaults/field). Correspondence, key-evidence and
`delegated_tls/resolver.rs` unchanged. Premise ASM-0032 REVIEWED; dep THM-0025.
Evidence: `side_attributed_relation` members unchanged; mutation pass.

#### THM-0027 — A delegated resolver's existence proves its credential and signer corresponded
Verdict: CLEAN-NOTE
Changed: `proxy.delegated_resolver_materialization` tls.rs (a36c92ff) + integration test plumbing;
`proxy.delegated_resolver_materialization_sole_producer` structural_probes S06 (5f7a4cac #1113).
Read: `delegated_tls/resolver.rs` and `delegated_tls.rs` have no commits in range;
`DelegatedCertResolver` still has three private fields (`certified`, `budget`,
`_correspondence: CredentialKeyCorrespondenceFacts`), `materialize` sole producer. S06's
`construction` (the compiled attack) is unchanged; only `producer_paths.module-tree-visibility`
prose changed.
Why it holds: construction closure unchanged; structural lane passed S06.
Evidence: `construction_closure` members unchanged; `structural://proxy/delegated_tls/resolver_sole_producer` (S06) pass.
Note: #1113 rewrote S06's prose "all three fields are bare-private" to "both fields are
bare-private" — collateral of an edit aimed at S29 (`MaterializedReplay`). The resolver has
three fields, so S06's prose is now factually wrong. Same collateral edit hit S38
(`CurrentAuthenticatedRelationshipPeerFacts`, also three fields: `peer`, `evaluated_at`,
`applied`) — outside this group. Recommend restoring "all three" in S06 and S38 (probe prose,
not the claim).

#### THM-0031 — An authenticated relationship peer's identity is read from the leaf of the very credential …
Verdict: CLEAN
Changed: `proxy.channel_peer_resolution` source_inputs `tls.rs` (a36c92ff) only.
Read: tls.rs diff; `authenticated_relationship_peer.rs` unchanged. Premise ASM-0036 REVIEWED;
deps THM-0029, THM-0030.
Evidence: `test://proxy/tls/channel_peer_resolution` members unchanged; mutation pass.

#### THM-0032 — Per-request credential currency is decided from the credential the mechanism accepted …
Verdict: CLEAN
Changed: `proxy.currency_policy_classification` tls.rs (a36c92ff);
`proxy.per_request_revocation_serving` `async_serve/connection.rs` (a36c92ff #1157, 0ba3db26 #1154)
+ integration_async plumbing.
Read: connection.rs diff — drain grace, idle bound and TLS-handshake deadline now read from
`options.connection_bounds` (always in force, so the `None` arms are gone); handshake-permit
pool construction changed in the test helper. The acceptance passed to `handle_request`, the
per-request currency evaluation, `async_serve/request.rs` and `client_revocation.rs` are
unchanged. The four other supporting units are unchanged. Premises ASM-0038/0080/0086 REVIEWED.
Evidence: `per_request_revocation`, `currency_policy_classification` members unchanged; mutation pass.

#### THM-0054 — Every production listener denies unknown client revocation status
Verdict: CLEAN
Changed: `proxy.client_certificate_posture` tls.rs (a36c92ff), `tls_plane/client_revocation_posture.rs`
(a6f2091b #1111 — test fixture drops the removed `custody` plan field) + integration plumbing.
Read: `tls_listener_state/client_verifier.rs`, `assembly.rs`, `crl_reload_worker/mod.rs`
unchanged. Census of `WebPkiClientVerifier`/`ClientCertVerifier` in `mcp-re-proxy/src`: the one
production builder (`client_verifier.rs:55`), test-only builders, and the pre-existing
`#[cfg(feature = "fault_accept_any_client")]` fault verifier in tls.rs — no new site in range.
Dep THM-0048 (stale; other group).
Evidence: `deny_unknown_no_opt_out` members unchanged (`the_rules_would_catch_each_regression` body identical); mutation pass.

#### THM-0102 — A validated deployment's connection-age bound never exceeds the credential lifetime …
Verdict: CLEAN
Changed: `proxy.client_credential_window` / `_sole_producer` source_inputs
`config_state/client_credential_window.rs`, `credential_currency_bound.rs` (097b06ec #1165) + plumbing.
Read: `MAX_CLIENT_CERT_LIFETIME` moved from `config_state/transport.rs` into
`client_credential_window.rs`, same value (3600s); `credential_currency_bound.rs` only re-imports
`ClientRevocationPlan` from `crl_revocation`. `ClientCredentialWindow::new` checks unchanged
(non-zero, `<= MAX_CLIENT_CERT_LIFETIME`, `connection_age <= cert_lifetime`). Enforcement scope:
connection.rs still sleeps on `client_credential_window.connection_age()`; drain grace now from
`ConnectionBounds`.
Evidence: `connection_credential_window` members unchanged
(`the_public_constructor_validates_too` flag was a same-name false positive);
`a_config_that_skipped_the_parser_still_cannot_bypass_the_safety_guards` adapted to
`run_request` (validates), assertion unchanged; structural sole-producer probe pass.

#### THM-0131 — The client-revocation posture states what this replica is enforcing now
Verdict: CLEAN
Changed: `proxy.client_revocation_currency` posture.rs + `crl_reload_worker/supervision.rs`
(a6f2091b — test fixtures only); `proxy.retired_plane_cadence_retraction` `tls_plane/mod.rs`
(a6f2091b #1111, 75e64d04 #1164); `proxy.client_crl_next_update_gate` integration plumbing.
Read: tls_plane/mod.rs diff — `materialize` now takes an `EstablishedChannelCredential` (the
custody-mismatch refusal moved to the key-source owner,
`capability_materialization/key_source/channel_credential.rs:61`, with its two tests) and a
`CrlReference` (`tls_plane/crl_reference.rs`) whose sole producer refuses a faulted startup
clock when CRLs are enforced. The CRL gate is still `ClientCrlEvidence::from_checked` via
`load_and_check_crls`, shared with reload; `crl_evidence*`, `revocation_currency.rs`,
`client_crl_publication.rs` unchanged. Retraction code untouched. Change strengthens startup
(an epoch clock can no longer declare an expired CRL fresh); claim unaffected.
Premise ASM-0080 REVIEWED; dep THM-0054.
Evidence: `client_revocation_currency`, `client_crl_next_update_gate`,
`retired_plane_cadence_retraction` members unchanged; `crl_reference` tests new; mutation pass.

---

## Re-review packet C2: proxy trust plan, composition root, trust snapshot, epoch label

Tree: main 72127a07. Each review was current at a0b944c4. Evidence: run 38513625401 passed every lane on
72127a07, and all supporting units are FRESH.

Shared change set:
- `mcp-re-proxy/src/app.rs`: 13 commits, #1109 through #1164, with +122 lines and -375 lines.
- `mcp-re-proxy/src/trust_plan.rs`: changed by #1161.
- `mcp-re-proxy/src/trust_plane/mod.rs`: changed by #1109, test module only.
- `mcp-re-proxy/src/signing_plane/mod.rs`: changed by #1161 and #1164.
- The integration test sources were edited by #1109, #1111, #1113, #1116, #1154 and #1110.

Six of those integration test files have no deleted assertion and no deleted test fn.
`http_profile_dispatch_test.rs` is the exception, and it bears on no theorem in this group; see the end.

#### THM-0037: A trust plan's reload cadence is a projection of the revocation posture, never a second value
Verdict: CLEAN

**Changed since review:**
- Commit: 4dc1510a (#1161).
- Units and component: `proxy.trust_plan` and `proxy.trust_plan_co_provenance`, `source_inputs` (`trust_plan.rs`).

**What was read:**
- The full `trust_plan.rs` diff.
- `TrustPlan` fields and methods (`trust_plan.rs:65-127`).
- `startup_plan::response_authority_plans` (`startup_plan.rs:35`).

**Why the claim holds:**
- `TrustPlan` still has exactly four private fields: revocation, document, response_kid and epoch. It has no reload field, and `reload()` still returns `trust_reload_plan(&self.revocation)`.
- `from_validated` is still the only function returning `Self`. It was narrowed from `pub` to `pub(crate)`.
- It still takes `response_kid` and `epoch` as arguments and re-derives neither.
- The one production caller is now `response_authority_plans`, which reads the kid from `DelegatedSigningFacts` and the epoch from `TrustEpochPlan::from_validated` once. It hands both values to the trust plan and to the signing plan. That strengthens CF-09 and contradicts nothing in the claim.
- The test `the_shared_values_are_inputs_the_trust_plan_cannot_re_derive` now compares against `response_authority_plans(..).0.response_kid()` instead of the deleted `response_issuer_kid`. The assertion is unchanged.

**Evidence:** these all exist, and the final run's test/mutation lanes for `proxy.trust_plan` passed:
- `trust_plan::tests::{a_reload_bearing_state_cannot_be_projected_to_read_once, bounded_cache_keeps_both_refresh_postures, the_trust_plan_carries_the_retained_classification, the_shared_values_are_inputs_the_trust_plan_cannot_re_derive}`
- `structural://proxy/trust_plan/co_provenance`
- The mutation probe for `reload_is_a_projection`.

#### THM-0038: The composition root consumes trust as owner projections and re-reads no trust field from the request
Verdict: CLEAN

**Changed since review:**
- Commits: 13 to `app.rs` (#1109, #1111, #1113, #1114, #1116, #1146, #1147, #1149, #1161, #1154, #1167, #1157, #1164).
- Unit and components: `proxy.trust_composition_root`, `source_inputs` (`app.rs`) and `test_sources` (seven integration files).

**What was read:**
- The trust-bearing region of `run_validated` (`app.rs:205-262`), against a0b944c4 (lines 329-392 there).
- `composition_raw_read_test.rs`, which is unchanged since a0b944c4.
- Every `values.<field>` read in `app.rs`.

**Why the claim holds:**
- Trust still reaches materialization only as owner projections: `TrustPlane::materialize(&trust_plan, ..)` and `config.state().trust_document()`.
- The trust plan comes from the one producer `response_authority_plans(config)`, which replaces the three separate `response_issuer_kid`, `TrustEpochPlan::from_validated` and `TrustPlan::from_validated` calls.
- `app.rs` reads `values.` only for audience, bind, peer_trust_anchors, inner_http_urls, limits, route, target_uri and channel_credential.credential_chain. That is exactly the unchanged `ORDINARY` inventory, and no request-signer trust field is on it.
- The bidirectional inventory test is unchanged and passed on 72127a07, as did the control `the_rule_would_catch_a_new_raw_read`.
- Dependencies THM-0035 and THM-0037 are current, and THM-0037 is clean above.

**Evidence:**
- `composition_raw_read_test::{the_composition_root_reads_only_ordinary_validated_parameters, the_rule_would_catch_a_new_raw_read, every_ordinary_field_states_why_it_is_ordinary}`
- `app::tests::the_channel_binding_effects_are_a_function_of_the_recognised_state`
- The mutation probe for `composition_reads_only_projections`.

#### THM-0067: The composition root re-reads no owner's security semantics from the request
Verdict: CLEAN-NOTE

**Changed since review:** the same `app.rs` and test-source change set as THM-0038.

**What was read:**
- `app.rs` `values.` reads and `ServerOptions` construction (`app.rs:369-386`).
- The `ConnectionBounds` owner (`config_state/connection_bounds/mod.rs`, #1157).
- Every production `.limits.<member>` read in `mcp-re-proxy/src`.

**Why the claim holds:**
- The raw-read set equals the pinned `ORDINARY` inventory, which is checked in both directions by the unchanged test.
- Since review, several values moved from raw reads to owners: the skew policy (#1116), the in-flight basis (#1149), the connection bounds (#1157), the client credential window, and the startup clock reading (#1164). Each change removed or narrowed a raw read, and none added one.
- #1157 made `ConnectionBounds` the owner of `read_timeout`, `write_timeout`, `request_deadline`, `max_concurrent_connections` and `drain_grace`.
- The root still passes `values.limits` whole into `ServerOptions.limits`. No production code reads those five members from it any more; the only readers are the owner (`connection_bounds/mod.rs:119-134`) and `cli.rs` test assertions.
- Serving reads only `max_header_bytes`, `max_body_bytes` and `max_in_flight_requests` from `options.limits` (`async_serve/http_limits.rs:28-29`, `async_serve/inbound.rs:124`, `async_fleet/mod.rs:320`). The in-flight value is overwritten from the owner's ceiling.

**Note for the owner:**
- The `ORDINARY` reason for `limits` (`composition_raw_read_test.rs:66-70`) says "The one member that WAS a decision — max_connection_age — is owned by ClientCredentialWindow".
- Since #1157, five more members have an owner, `ConnectionBounds`.
- They still travel raw inside `ServerOptions.limits`, unread.
- The proposition holds, but the stated reason is incomplete. A future serving edit could read `options.limits.read_timeout` again, and this inventory would not notice, because it measures the root's `values.` reads, not a plane's reads of `ServerOptions`.

**Evidence:** as for THM-0038.

#### THM-0066: The serving PEP resolves actors through the deployment's materialized trust authority
Verdict: CLEAN

**Changed since review:**
- Units: `proxy.serving_trust_seam`, with `source_inputs` (`app.rs`) and `test_sources`; and `proxy.trust_plan`, with `source_inputs`.
- Commits: as for THM-0038, plus #1161.

**What was read:**
- `build_actor_resolver`. Its whole body is byte-identical to a0b944c4 (diffed).
- Its single call site (`app.rs:247-252`) against the a0b944c4 call site.
- The `revocation_serving_wiring_test` diff. It is a fixture change only: `parse_args` now returns the validated deployment.

**Why the claim holds:**
- The resolver is still built exactly once. `grep` finds one definition and one call.
- It is built from `building.trust()?.signers()` (the reloading directory snapshot) and `building.trust()?.resolver()` (the tier resolver), so Request-slot keyids still resolve through the tier per request.
- The Response slot still takes `config.state().server_identity()` and the root witness's `response_public_key()`. The witness was renamed from `key_source` to `roots` (#1111); it is the same `ResponseSigner` witness.
- `request_admission.rs`, the unit's other path, is unchanged.

**Evidence:**
- The ten `revocation_serving_wiring_test::*` tests named by the unit. These are the revoked, unavailable, rotated and slot-discipline cases.
- `serving_trust_seam_test::{the_serving_trust_seam_is_built_once_from_the_materialized_authority, the_seam_resolves_through_the_tier_rather_than_a_frozen_map, the_rules_would_catch_each_regression}`, all unchanged.
- The mutation probe for `serving_seam_wiring`.

#### THM-0099: The production actor resolver answers its Request-slot selector from the deployment's trust document
Verdict: CLEAN

**Changed since review:** `proxy.serving_trust_seam`, as for THM-0066.

**What was read:** as for THM-0066. The claim's Request and Response semantics are implemented entirely inside `build_actor_resolver`, which is byte-identical, over inputs whose provenance is unchanged.

**Why the claim holds:**
- The scope is "the PRODUCTION composition only: `build_actor_resolver` over the reloading signer directory and the revocation-tier resolver", and both the builder and its inputs at the call site are unchanged in meaning.
- The dependencies are clean in this packet: THM-0066 above, and THM-0097 and THM-0098 below.

**Evidence:** as for THM-0066.

#### THM-0097: A replica serves no request-signer binding outside its snapshot's authority window
Verdict: CLEAN

**Changed since review:**
- Commit: abd8f49f (#1109).
- Unit and component: `proxy.trust_resolution_window`, `source_inputs` (`trust_plane/mod.rs`).

**What was read:** the full diff. It is entirely inside `#[cfg(test)] mod handle_lifetime_tests` (`trust_plane/mod.rs:800-801`). `parse_args` now yields the validated deployment, so the separate `ValidatedDeployment::try_from` step was removed from the test fixture.

**Why the claim holds:**
- No production line of the trust plane changed.
- The test still asserts the no-cadence shape before materializing.
- The premise ASM-0079 is reviewed.

**Evidence:** the unit's 46 named tests:
- `trust_cache::tests` (deadline, flush and eviction cannot lengthen; Unavailable is not cached)
- `push_trust::tests`
- `live_trust::tests`
- `freshness_transition_tests`
- `handle_lifetime_tests`
- `reload_loop_tests`
- `supervision`

Plus the mutation probe for `local_currency`.

#### THM-0098: A replica's trust snapshot is the slot-wise interpretation of one accepted trust document
Verdict: CLEAN

**Changed since review:** the same test-only `trust_plane/mod.rs` change as THM-0097. `proxy.trust_document_interpretation` did not move.

**Why the claim holds:**
- The parser and the projections are untouched.
- The only moved input is a test fixture in a different unit's file.
- The premises ASM-0079 and ASM-0083 are reviewed.

**Evidence:** as for THM-0097, plus `proxy.trust_document_interpretation`'s battery, which is unchanged.

#### THM-0100: A replica's exposure to a key its document no longer enrols is confined to the serving interval it prints
Verdict: CLEAN

**Changed since review:** `proxy.trust_reload_cadence` and `proxy.trust_posture_declaration`, both with `source_inputs` (`trust_plane/mod.rs`, test-only as above). `trust_posture_declaration` also has `test_sources` (the integration files).

**What was read:**
- The `trust_plane/mod.rs` diff, which is test-only.
- `app_startup_characterization_test.rs`, which has no deleted assertion or test fn. That file holds `enabling_trust_reload_changes_the_tier_line_and_the_reload_line_together`.

**Why the claim holds:**
- The reload loop, the delivered-window arithmetic and the tier-line text are untouched.
- The dependency THM-0097 is clean, and the premise ASM-0079 is reviewed.

**Evidence:**
- `reload_loop_tests::*`
- `delivered_window::tests::*`
- `store_cadence_tests::*`
- The startup characterization test.
- The mutation probes for `reload_cadence` and `posture_declaration`.

#### THM-0133: With a shared trust-epoch counter configured, the delegated-signing plane mints only under the label its own read names, and never under a regressed one
Verdict: CLEAN

**Changed since review:**
- Commits: 4dc1510a (#1161) and 75e64d04 (#1164).
- Unit and component: `proxy.delegated_epoch_label`, `source_inputs` (`signing_plane/mod.rs`).

**What was read:**
- The full `signing_plane/mod.rs` diff.
- `SigningPlan::minting_under` (`startup_plan.rs:236-240`).

**Why the claim holds:**
- `minting.custody.trust_epoch = <label>` became `minting = plan.minting_under(<label>)`. That method clones the plan and sets exactly `custody.trust_epoch`, so the semantics are identical.
- The fail-closed path is unchanged: an unreadable epoch with a configured source still errors before anything is minted.
- `materialize` went from `pub` to `pub(crate)` and takes `&StartupReading` instead of `i64`. It passes `startup_reading.unix_seconds()`, the same value.
- The plan field reads became accessors.
- `epoch_watch.rs`, `epoch_watch/refusal.rs`, `trust_epoch/raise.rs` and `trust_epoch/advance.rs` did not move.
- The test fixture now uses `SigningPlan::from_parts`, which is test-gated, with the same values.
- The premises ASM-0068, ASM-0071 and ASM-0081 are reviewed.

**Evidence:**
- The unit's 26 named tests in `signing_plane::trust_epoch_watch_tests`, `signing_plane::epoch_watch::tests`, `trust_epoch::advance::tests` and `trust_epoch::raise::tests`.
- The mutation probe for `delegated_epoch_label`.

#### Out of scope, noted for the replay group
In `mcp-re-proxy/tests/integration/http_profile_dispatch_test.rs`, commit 5f7a4cac (#1113) deleted the test `fleet_strict_refuses_undeclared_tier`, which asserted `NoDeclaredReplayTier` and the wire code `mcp-re.replay_cache_unavailable`. The commit title says the replay tier and its declared posture now travel as one value. If so, an undeclared tier may now be unrepresentable rather than refused. The packet that reviews THM-0086 and THM-0092 should confirm this.

---

## Re-review packet D: proxy dispatch, refusal, audit

Re-reviewed against main 72127a07. The diff baseline is a0b944c4, when every one of these reviews was current. Evidence is final run 38513625401, which passed every lane; all supporting units are FRESH.

### Shared change sets, triaged once

**S1. `mcp-re-proxy/tests/integration_async/*` (16 files) and `tests/common/mod.rs`.** These are the `test_sources` of `pdp_decision_relation`, `dispatch_commitment`, `retention_commitment`, `audit_authority_coordinates`, `admission_currency_gate`, `audit_delivery` and `response_signing`.
- Commits: 5f7a4cac (#1113), abd8f49f (#1109), 4dc1510a (#1161), 0ba3db26 (#1154), 11c92802 (#1160).
- Every edit is constructor migration:
  - `ProxyDispatchConfig { tier: None, fleet_strict: false }` became `ReplayAdmission::new(tier, ReplayPosture::SingleProcess)`, which is semantically the same posture.
  - An integer `max_clock_skew: 60` became `MaxClockSkew::new(60)`.
  - `SigningPlan::from_validated(...)` became `response_authority_plans(&validated).1`.
  - `parse_args(..)` gained `.into_inner()`.
  - `ShardDepth::stated(n)` became `NonZeroUsize`.
- Test and assertion counts are identical in all 17 files, before and after (e.g. pdp_authorization_serving 25/104→25/104, mrt_continuation 36/159→36/159). No test or assertion was removed or weakened.

**S2. `mcp-re-proxy/tests/integration/*` (7 files).** These are the `test_sources` of `refusal_site_totality` and `refusal_audit_emission`.
- Commits: #1109, #1110, #1111, #1113, #1116, #1154.
- One test was deleted: `http_profile_dispatch_test::fleet_strict_refuses_undeclared_tier`. Its state is now unrepresentable, because #1113 made the fleet-strict posture `ReplayPosture::FleetStrict(ReplayDurabilityTier)` and deleted `ProxyDispatchError::NoDeclaredReplayTier`.
- `documented_cli_test` lost one assertion. `parse_args` now returns the validated deployment, so the separate `ValidatedDeployment::try_from` call is subsumed by the remaining one.
- No group-D claim names the deleted variant.

**S3. Gate controls.** These are `dispatch_commitment`'s `authorization_provenance_gate.py` and `serving_product_provenance_gate.py`, and `refusal_site_totality`'s `refusal_provenance_gate.py`. Commits are bff0cb91 (#1145) and 10211963 (#1117).
- Each gate's private test-region stripper, comment stripper and directory walk were replaced by the shared owner `_rust_source.production_view` / `code_only` / `crate_sources`.
- `serving_product_provenance_gate` now excludes modules that are test-only via `_module_tree`, which is rustc's view, with a selftest (`_selftest_test_only`). It previously used a `TEST_MOD_DECL` regex.
- The new stripper is equal or stricter: it counts braces over comment- and literal-blanked text. `crate_sources` excludes only `target`, `node_modules`, `.git`, `bazel-out`, `vendor` and the crate-level `tests`/`benches`/`examples` directories. None of those is a production authority directory.
- The rule sets are unchanged, and the gates and their selftests are green in the final run.

**S4. `mcp-re-proxy/src/refusal/cause.rs`** (5f7a4cac). Test-only: five fixtures moved from the deleted `NoDeclaredReplayTier` to `SubMinimumReplayTier(AsyncReplicatedBounded)`, with the same Core-verdict arm and the same wire token `mcp-re.replay_cache_unavailable`. Production `RefusalCause` is unchanged.

---

#### THM-0040 — An authorized request was permitted by a decision about that very request
Verdict: CLEAN
Changed since review: `proxy.pdp_decision_relation` test_sources only (S1).
What was read: the S1 diffs. The unit's source and its `authorization_coordinate_provenance` are unchanged.
Why it holds: no production change. The relation tests in `pdp_authorization_serving_test` (25 tests) are unchanged in content.
Evidence: `pdp_decision_relation` battery and mutation probes, FRESH in 38513625401. Depends on THM-0039, which is reviewed in another packet.

#### THM-0045 — The backend is reached only by consuming a fully assembled pre-dispatch commitment
Verdict: CLEAN
Changed since review: `dispatch_commitment` gate_controls (S3) and test_sources (S1); `retention_commitment` test_sources (S1).
What was read:
- S1 and S3.
- `request_stages.rs::ReadyForDispatch` still takes `PreparedInnerDispatch`, `SigningWindow` and `RetentionDisposition` by value.
- `AuthorizationPosture::release` is the sole producer of `AuthorizedRequestBody` (`authorization/dispatch.rs:46`).
- The only change in `authorization/` is `capability.rs`, which types the skew (#1116, `i64` became `MaxClockSkew`, read back with `.secs()`).
Why it holds: the representation and constructors named by the claim are unchanged. `SigningWindow` itself became stronger: by #1162 it is the only public producer of signed products.
Evidence: the authorization/serving-product provenance gates (green, selftests green) and the dispatch tests in S1.

#### THM-0046 — A refusal carries which authority reached it, over a closed set, unrendered
Verdict: CLEAN
Changed since review: `refusal_provenance` source_inputs = `cause.rs`, tests only (S4).
Why it holds: `RefusalCause`, its two arms, and the absence of a `PolicyError` route into Core are unchanged in production. The test fixtures use a still-existing Core dispatch verdict.
Evidence: `refusal::cause::tests::*`, including `a_dispatch_failure_is_a_core_verdict_and_keeps_its_own_token`.

#### THM-0051 — The pipeline holds, at dispatch, the verification product of this very exchange
Verdict: CLEAN
Changed since review: `dispatch_commitment` gate_controls (S3) and test_sources (S1).
Why it holds: the mechanism is the `serving_product_provenance_gate` source-text gate. Its reader was replaced by the shared owner, and its single-call / single-carrier rules are unchanged. The test-only exclusion now uses the module tree, with a selftest that a module reachable only under `#[cfg(test)]` is excluded while one reachable from a second production root stays in. `verifier_result_separation` is unchanged.
Evidence: the gate and its selftests, green in the run.

#### THM-0052 — A dispatched body was released by the decision a configured policy produced
Verdict: CLEAN
Changed since review: `dispatch_commitment` (S1, S3) and `pdp_decision_relation` (S1).
Why it holds: no production change to the authorization authority beyond the typed skew in `capability.rs`. `authorization_provenance_gate`'s posture-producer check (`check_posture_producers`) is unchanged in rule; only its comment stripper moved to `code_only(literals=True)`.
Evidence: `authorization_provenance_gate` (green), `a_deployment_running_no_decision_profile_is_unaffected` and the PDP serving battery.

#### THM-0069 — A security record states each authority's outcome in that authority's own coordinate
Verdict: CLEAN
Changed since review: `audit_authority_coordinates` test_sources (S1); `refusal_provenance` (S4); `admission_currency_gate` source_inputs, `admission_enforcer/{enforcement.rs, mod.rs, degraded_window.rs}`, by 75fae5e3 (#1147).
What was read: the `admission_enforcer` diff.
- It adds `From<config_state::AdmissionPosture> for AdmissionEnforcement`, mapping Optional→Optional and Required→Required, with a new test that pins both arms (`each_configured_posture_is_its_own_enforcement`, added to the unit's `tested_symbols`).
- Test policies use `..AdmissionPolicy::default()` in place of a literal `max_assertion_age: 300`.
Why it holds: the admission coordinate's vocabulary and its separation from Core and authorization are unchanged. The enforcer is now projected by the admission owner instead of being assembled by the root, and the mapping is pinned by a test.
Evidence: the coordinate tests in the audit unit, the new posture test, and the admission currency serving battery (21 tests, unchanged).

#### THM-0070 — The record stream is honest about what reached it
Verdict: CLEAN
Changed since review: `audit_delivery` source_inputs `audit_sink/{drain.rs, stream.rs}` by abd8f49f (#1109), plus test_selection and test_sources.
What was read: the full drain and stream diffs.
- `at_shutdown(report: bool)` became `at_shutdown()`. Whether a drain line is spoken is now read from `stream::opened_run()`, i.e. whether this process opened a stream, rather than from a caller flag.
- The drained and unknown lines now name `run=<incarnation>`.
- `Drained` and `OutcomeUnknown` stay distinct texts, and the `OutcomeUnknown` text still says "NOT a report that records were lost and NOT a clean shutdown".
Why it holds: the change removes a vacuous "drained" line for a process whose sink never opened (a refused `--audit-sink stderr` startup), and adds the run name. Neither weakens the claim that a drain is either acknowledged with no failed write or UNKNOWN, never misreported.
Evidence:
- `a_timed_out_audit_drain_never_reads_as_a_completed_one` (kept).
- New: `a_process_that_opened_no_stream_states_no_drain` and `the_drain_line_names_the_run_it_drained`, both added to `tested_symbols`.
- `an_unknown_drain_states_the_drop_count_the_writer_never_reported` (kept).

#### THM-0071 — Every reachable in-exchange refusal has a typed provenance that reaches the record
Verdict: CLEAN
Changed since review: `refusal_provenance` (S4) only. `audit_vocabulary_import` is unchanged.
Why it holds: a test-only change on one of two supporting units. The composed dependencies THM-0069, 0046, 0081, 0070 and 0085 are re-reviewed CLEAN in this packet.
Evidence: as for THM-0046, plus the dependencies' evidence.

#### THM-0074 — No unearned dispatch
Verdict: CLEAN
Changed since review: `dispatch_commitment` (S1, S3). `exchange_relation` is unchanged.
Why it holds: the claim's own supporting units changed only in gate readers and test construction syntax. It is a composition over 26 theorems, several re-reviewed in other packets (e.g. THM-0077, 0083, 0092, 0093, 0099–0101). This verdict is conditional on those packets.
Evidence: the gates in S3 and the S1 serving batteries.

#### THM-0075 — No unearned response attribution
Verdict: CLEAN
Changed since review: `proxy.response_signing` test_sources (S1). `http_profile.response_emission_binding` changed in source_inputs (`custody/delegated_signer.rs` new, `custody/window_emission.rs`, `sign.rs`, `sign/request.rs`, `rejection/pre_052_direct_root.rs`), test_selection, test_sources (`tests/delegated_202_test.rs`) and mutation_probes (new M541). Commits: 61605e13 (#1162), 87f3424a (#1163), 11c92802 (#1160).
What was read:
- #1162 replaced the five public `*_with_owned_key` emitters with crate-private `emit_*` functions taking a `DelegatedSigner`. That projection is produced only from a `SigningWindow` (`DelegatedSigner::of` is `pub(super)`).
- `server_signer`, `credential`, `key`, `kid` (= `delegated_kid`) and the `created`/`expires` validity are all read from the one window's `ActiveDelegatedKey`.
- `require_signer_is_delegated_key` was deleted, because `ActiveDelegatedKey::issued` refuses a mismatched identity. Its control `an_identity_naming_another_keyid_is_refused` is at `custody/active_key/mod.rs:546`, registered on the custody unit.
- The bound emitter still derives the request handle from the signed request. #1163 replaced `request_evidence_of` with `RequestRoleEvidence::of_signed_request`; I compared both and they are the same derivation: `parse_signature_input_for` = `single_header` + `member_value` + `parse_signature_input`, then `signature_base` and `from_signature_base`.
- The unbound emitter still takes only a diagnostic.
- `delegated_202_test` is 13 tests and 22 assertions before and after; it moved to the `pre_052_fixtures` flavor for `SigningWindow::stated`.
- `tested_symbols`: `sign::tests::a_delegated_response_is_refused_when_the_signer_names_another_key` was replaced by `custody::delegated_signer::tests::every_part_is_read_from_the_one_window`. The refusal it tested moved to construction, as above.
Why it holds: the signature is made by the materialized delegated capability, read from one window. Bound evidence is still bound to the exact request handle, and unbound evidence still carries no handle. The change makes a signer/key disagreement unconstructible rather than refused at emission.
Evidence:
- M541, which turns `every_part_is_read_from_the_one_window` red when the emitter reads its keyid from `server_signer().subject`; green-killed in the run's mutation lane.
- `delegated_202_test`, and the response_signing serving battery.
- Dependencies THM-0062, 0063 (current), 0065, 0022 and 0082 are reviewed in other packets.

#### THM-0078 — Refusal is terminal, and no refusal-side effect reads as success
Verdict: CLEAN
Changed since review: `refusal_provenance` (S4) only. `exchange_relation` and `pre_dispatch_refusal_precedence` are unchanged.
Why it holds: there is no production change in the supporting units. The continuation-retirement side effect (see THM-0081) still records the spend before signing the refusal.
Evidence: the supporting units' batteries; dependencies THM-0069, 0081, 0088 and 0046 are CLEAN here.

#### THM-0081 — Every production refusal is inside the exchange lifecycle
Verdict: CLEAN
Changed since review: `refusal_site_totality` source_inputs: `async_serve/mod.rs`, `http_profile_serve/{mod.rs, answering_commitment.rs}` and `http_profile_serve/continuation/{mod.rs, answer_leg.rs, open_leg.rs, refusal.rs (new), retirement.rs}`. Also gate_controls (S3) and test_sources (S2). Commits: 4312c49a (#1108), 5f7a4cac (#1113), 75fae5e3 (#1147), 6f9ea226 (#1149), 0ba3db26 (#1154), a36c92ff (#1157).
What was read:
- #1108 made `http_profile_serve::continuation` `pub`, so `examples/http_profile_proxy.rs` (the HTTP-profile proof front) runs the same sequence. The new `ContinuationRefusal` (Unavailable→`ReplayCacheUnavailable`/503, Conflict→`ContinuationConflict`/409, AlreadyAnswered→`ContinuationBindingFailed`/409) reproduces exactly the pairs the serving path minted before (`open_leg.rs`, `answering_commitment.rs` old arms). It is pinned by `each_refusal_keeps_its_wire_classification`.
- `Retirement::refusal()` and `may_have_spent()` reproduce the old match arms: AlreadyAnswered → 409 binding-failed; Indeterminate → 503 plus record Consumed. They are pinned by `each_outcome_states_its_refusal_and_whether_the_approval_may_be_spent`.
- In the serving path, `observe_retirement` still records `ContinuationState::Consumed` BEFORE `refuse_answerable` signs, and every continuation refusal still goes through `refuse_answerable` / the stage `Refusal` path, i.e. exchange-owned.
- The public plane returns classifications, not served responses. The proof front is an `examples/` target, outside the production site set the claim and the gate cover.
- `async_serve/mod.rs` swapped `limits.max_concurrent_connections` / `drain_grace` for the `ConnectionBounds` owner's projections; no reply site was added or removed. Its test lost the stated-depth-1 refusal branch, which #1154 moved to configuration (another group's claim).
- `http_profile_serve/mod.rs` folds `replay_async` + `dispatch_cfg` into one `ReplayAdmission` and injects the admission enforcer; no new reply site.
Why it holds: the site set is unchanged. Every continuation refusal is still minted by a stage and served under the exchange machine's disposition, and the four pre-exchange transport replies are untouched.
Evidence: `refusal_provenance_gate` (green, S3); the two new classification tests; the S2 characterization tests.

#### THM-0085 — Every exchange-owned refusal reaches the audit boundary, typed, before it is answered
Verdict: CLEAN
Changed since review: `refusal_audit_emission` source_inputs `http_profile_serve/mod.rs` (#1108, #1113, #1147) and test_sources (S2).
What was read: the full `mod.rs` diff (see THM-0081). The `receipt` module and its two emitters are unchanged. The signed-refusal constructor's visibility is unchanged. Making `continuation` public exposes no receipt or emitter.
Why it holds: the emission joint is untouched.
Evidence: the unit's battery (S2), and the dependencies THM-0046, 0069 and 0081, all CLEAN here.

#### THM-0088 — A retention artefact reads as a crossing only for an exchange that crossed
Verdict: CLEAN
Changed since review: `retention_commitment` test_sources (S1) only. The retained-evidence store source is unchanged.
Why it holds: there is no production change; the S1 edits are constructor migration with identical test and assertion counts.
Evidence: the retention_commitment battery, FRESH in the run.

### Discrepancies
None.

### Cross-packet notes (not group D)
- `async_serve` admission_bound test: the `stated(1)`-under-delegated-custody refusal branch was removed because #1154 made it a configuration refusal. It belongs to THM-0077 / connection-bounds.
- THM-0074 and THM-0075 are compositions; their CLEAN verdicts assume the dependency theorems re-reviewed elsewhere stay CLEAN.

---

## Re-review packet E1 — proxy serving posture, lifecycle, replay, continuation, drain

Baseline: every review current at a0b944c4; tree reviewed at main 72127a07. Evidence: run
38513625401 (all lanes PASS, every supporting unit FRESH). No claim text changed in the range
(specification reviews are REVIEWED for all twelve); the staleness is semantic only.

Summary: 9 CLEAN, 3 CLEAN-NOTE (THM-0049, THM-0077, THM-0092), 0 DISCREPANCY.

#### THM-0012 — The lifecycle record cannot claim a shutdown that did not happen
Verdict: CLEAN
Changed since review: NEW_UNIT `proxy.materialized_lifecycle_sole_producer` (#1146 6f2000c3).
`proxy.runtime_lifecycle` and `proxy.runtime_lifecycle_sole_mutator` unchanged (runtime_state.rs
untouched).
What was read: `materializing_runtime/materialized_lifecycle.rs` (`started`, `failed`,
`MaterializedLifecycle::reached`, all `pub(super)`; private field), `materialized_runtime.rs`
`serving_events` and `serve`; structural probes S54–S56.
Why it holds: the relation and sole mutator are unchanged, so path-uniqueness stands. The scope's
named obligation on the materialized-runtime owner ("events applied only on a proven Ok") is still
discharged: `serving_events(&served)` returns `ServingStarted/ShutdownRequested/FleetDrained` only
for `Ok`, `&[]` otherwise, and `serve` applies only those. FailedToStart is still unreachable from
Materialized (`failed` is applied only at Materializing). The new unit strengthens the record: a
`MaterializedRuntime` can only be built around a lifecycle that passed validation, planning and
materialization (S55/S56 refuse the two forgeries; S54 refuses serving on a foreign lifecycle).
Evidence: runtime_state transition-relation battery (8 tests) + mutation; S54/S55/S56;
`a_serve_that_never_bound_justifies_no_lifecycle_event`.

#### THM-0048 — Every listener obtains its whole security posture through one listener state
Verdict: CLEAN
Changed since review: `proxy.listener_state_assembly` source_inputs `tls.rs`, `tls_plane/mod.rs`
(#1111 a6f2091b, #1157 a36c92ff, #1164 75e64d04).
What was read: both diffs in full.
Why it holds: no change touches `TlsListenerSecurityState`, the epoch, the session store, the
signing budget or the verifier assembly (no +/- line mentions any of them). tls.rs: ServerLimits
defaults now read named constants (same values) and ServerOptions gains `connection_bounds`.
tls_plane: `materialize` takes an `EstablishedChannelCredential` (custody check moved to the
key-source owner, see THM-0077) and a `CrlReference`; listener-state build is unchanged.
Evidence: unchanged tested_symbols (12, tls_listener_state/delegated_tls/tls_plane) + mutation.

#### THM-0049 — Every illegal cross-owner configuration combination is refused at layer A
Verdict: CLEAN-NOTE
Changed since review: `proxy.cross_machine_legality` source_inputs (#1154 0ba3db26): new relation
X10 in `cross_machine/delegated_tls_depth.rs`, wired into `validate`.
What was read: full diff. X2a/X6/X9 code untouched; X10 is added (a fourth refusal: delegated
channel custody × operator-stated `--workers-per-shard 1`).
Why it holds: the claim's three relations are still refused unconditionally, reading owner states.
X10 only adds a refusal (strengthening); the unit description records "X10 ... is
`proxy.delegated_tls_depth_refusal`'s claim; its module is measured here because this file
declares it."
Note for owner: the scope sentence "Three are live — X2a, X6, X9 — and those are what a validated
deployment is held to" is now an UNDERSTATEMENT: the pass decides four relations. Not an
overclaim; no proposition is false in the safe direction. Owner may wish to word-correct it in a
later claim correction; not required for soundness.
Evidence: cross_machine relation battery (7 tests, unchanged) + mutation.

#### THM-0077 — No deployment serves a posture nobody selected
Verdict: CLEAN-NOTE (X10 evidence attribution; see #1154 + #1149 bullet)
Changed since review: 18 of 22 supporting units; NEW_UNIT `proxy.connection_bounds` (#1157).
Commits: #1109 abd8f49f, #1111 a6f2091b, #1113 5f7a4cac, #1114 1a207717, #1116 432f0081, #1146
6f2000c3, #1147 75fae5e3, #1149 6f9ea226, #1154 0ba3db26, #1157 a36c92ff, #1161 4dc1510a, #1164
75e64d04, #1165 097b06ec, #1167 1c318c48. Probes M312, M314, M337, M338, M358 re-anchored.
What was read and why each is not a silent weakening:
- #1111: the requested-vs-established TLS custody refusal moved from `TlsPlane::materialize` to
  `EstablishedChannelCredential::establish` (sole producer; test-only `from_parts_for_tests` is
  `#[cfg(test)]`), comparing against `admitted.channel_credential_custody().exposure()` — the
  classified owner state. Same refusal text, still refused before serving.
- #1157 (new unit): a disabled timeout/zero ceiling/zero or >1-day drain is now REFUSED by the
  flag the operator typed; the async path previously treated `None` as "no timeout". Serving reads
  `config.state().connection_bounds()` (app.rs:373–379), so the serving component cannot disagree
  with the owner. `idle_bound` == request_deadline, equivalent to the old `request_deadline.or(read)`
  now that the deadline is required. Strengthening.
- #1164: `CrlReference::of` refuses a faulted clock where CRLs are enforced; `for_paths` refuses a
  reference checked without CRLs being spent on a plan that loads them. Strengthening.
- #1154 + #1149 (coordinator lead, delegated depth-1): before, the stated-1 × delegated refusal was
  a STARTUP refusal in `CorePool::for_core` (`DelegatedTlsDepthRefusal`, keyed on
  `ShardDepth::stated`). #1154 moved it to layer A as relation X10; #1149 then removed
  `ShardDepth` provenance, so `for_core` now raises ANY depth 1 under delegated custody to the
  safe pooled depth (`delegated_custody_on_one_worker_gets_the_safe_depth`), and the async_serve
  test's depth-1 refusal branch was dropped because `for_core` is now infallible. The stated-1
  case is therefore guarded only at configuration. REACH: `ValidatedDeployment` has one
  production producer, `TryFrom<DeploymentRequest>` (validation/mod.rs:104–116), which runs
  `validate_configuration` → `cross_machine::validate(.., channel_credential_custody,
  shard_topology, ..)` → `delegated_tls_depth::x10` (validation/mod.rs:165–170); every other
  `ValidatedDeployment` mention is a test helper name. The runtime and fleet take only a
  `ValidatedDeployment` (`MaterializingRuntime::begin`; S54–S56). So every validated path reaches
  X10, and a stated 1 under delegated custody cannot reach `for_core`. CONTROLS: X10's three
  tests (`a_delegated_channel_key_on_a_stated_single_worker_is_refused`,
  `neither_half_of_the_refused_pair_refuses_on_its_own`,
  `the_boundary_refuses_the_pair_however_the_request_was_built` — the last drives
  `unsafe_config_violations`, i.e. the whole boundary) and the mutation probe at
  mutation-probes.toml:10875 belong to `proxy.delegated_tls_depth_refusal`, which is NOT in
  THM-0077's support; THM-0077 reaches X10's file only through `proxy.cross_machine_legality`'s
  `paths` (its tested_symbols do not name X10). That attribution is UNCHANGED from a0b944c4 (the
  refusal unit existed then and was not in THM-0077's support either), so it is a note, not a
  regression: owner may wish to add `proxy.delegated_tls_depth_refusal` to THM-0077's support.
  No silent widening is reachable: the remaining `for_core` widening applies only to the host's
  `auto` answer, which the operator declined to choose.
- #1113: tier and declared posture travel as one
  value (see THM-0086/0092). #1114: control runtime started by the arm that needs it; the three
  internal-error branches are gone because need and handle are one step.
- #1147, #1149, #1161, #1165, #1167, #1116, #1109: single-producer/projection refactors. Checked the
  admission mapping (identical to the old `(bool,i64)` projection; `AdmissionPolicy::default`
  max_assertion_age is 300, the deleted literal), M314 (saturating aggregate, re-anchored), M337
  (same clamp, now in resolved_topology.rs), M312/M338 (re-anchored, red by hand per #1161), M358
  (anchor at the validated entry point). #1165 states byte-for-byte moved refusals.
Evidence: all 22 units FRESH in run 38513625401, mutation lane green (all re-anchored probes
killed); new unit battery 11 tests + `mutation://proxy/connection_bounds/no_bound_is_off`.

#### THM-0083 — What a request is, is decided once, before anything reads it for meaning
Verdict: CLEAN
Changed since review: `proxy.outstanding_id_provenance` source_inputs `http_profile_serve/mod.rs`
(#1108, #1113, #1147); test_sources = the shared `//mcp-re-proxy:integration_test` sources.
What was read: mod.rs diff: continuation module made `pub` (proof front reuse), replay fields
collapsed into `ReplayAdmission`, admission enforcer attach. No envelope/`OutstandingId` code
touched; `request_admission.rs`, `pre_admission/` unchanged; `outstanding_id_provenance_test.rs`
not in the changed set.
Why it holds: the single decision and its carriage are untouched; the source-scan control
`no_production_serving_code_reads_the_outstanding_id_a_second_time` passed on 72127a07.
Evidence: three outstanding_id_provenance tests + mutation; http_profile.request_envelope unchanged.

#### THM-0086 — The established replay tier is the selected one, and never a weaker substitute
Verdict: CLEAN
Changed since review: `proxy.replay_materialization` source_inputs `backends.rs`,
`materialized.rs`, tested symbols (#1113 5f7a4cac, #1114 1a207717).
What was read: both diffs. `materialize` reads `tier = plan.tier()` and `accept(established,
tier.clone())` builds `ReplayAdmission::new(tier, ReplayPosture::FleetStrict(declared))`; the
volatile-tier refusal in `accept` is unchanged; the backends now return only the tier, and the
posture is stated once from the plan. Redis arm takes the control runtime via
`ControlRuntimeProvision::handle()`.
Why it holds: the pairing "tier the plan selected, with the posture that plan declared" is now a
single value; a volatile tier still cannot be handed over; a backend the build lacks is still
refused by name. #1113's own commit noted the statement remains true of the new shape.
Evidence: 7 tested symbols incl. new `the_handed_over_value_admits_under_the_tier_it_was_declared_at`
(goes red if `accept` drops the declared tier) + S29 (literal route) + mutation.

#### THM-0092 — A request whose replay state was not established does not dispatch
Verdict: CLEAN-NOTE
Changed since review: `proxy.replay_admission_gate` (#1110 cab75969, #1113 5f7a4cac) source,
tested symbols, probes M139/M140/M86; `http_profile.fleet_strict_store_class` source (#1110).
What was read: dispatch.rs/outcome.rs diffs; `PreparedDispatch::admit` (outcome.rs:131): `Ok(Fresh)`
→ outcome, `Ok(Replay)` → ReplayDetected, `Err` → ReplayCacheUnavailable (outage, never replay);
`admit_replay_tier` (replay_posture.rs:130) unchanged in meaning; probe diffs M139/M140/M86.
Why it holds: sub-minimum declared tier and single-process store class are still refused before
the store is touched; the atomic admission is the last step; an unanswered store is an outage.
THE UNDECLARED-TIER CONJUNCT ("refuses ... when the deployment declares no replay tier"):
#1113 deleted `ProxyDispatchError::NoDeclaredReplayTier` and its two controls
(`the_serving_path_refuses_an_undeclared_tier_before_the_store_is_touched`,
`fleet_strict_refuses_undeclared_tier`) and M139 dropped "undeclared" from its conjunct. This is
NOT a silent un-refusal. It is now unrepresentable and refused upstream:
- type level: `ReplayPosture` is `SingleProcess | FleetStrict(ReplayDurabilityTier)` — the tier is a
  mandatory payload, no `Option` (http_profile_dispatch.rs:56–63). Fleet-strict with no tier
  cannot be written.
- production construction: the only production `ReplayAdmission::new` is
  `replay_plane/materialized.rs:99`, always `FleetStrict(declared)` with `declared = plan.tier()`;
  `SingleProcess` is built only in tests and the example proof front
  (`examples/http_profile_proxy.rs:153`), never by `run`.
- layer A: a deployment declaring no tier names no replay state and is refused
  (`proxy.replay_configuration_state`: `no_declared_tier_yields_no_state`,
  `a_shared_store_with_no_declared_tier_names_no_state`).
No structural probe targets the missing-payload form specifically; the enum payload is the
witness (a probe would be a type error by construction).
Note for owner (evidence attribution, not soundness): THM-0092's supporting units no longer carry
a CONTROL for the undeclared conjunct; it is discharged by the `ReplayPosture` type plus a unit
outside THM-0092's support (`proxy.replay_configuration_state`, reached via THM-0077). The claim's
word "refuses" for that conjunct now reads "cannot be stated at the gate; refused at layer A".
Owner may choose to (a) accept as is, (b) add `proxy.replay_configuration_state` to THM-0092's
support, or (c) word-correct the conjunct. No proposition is false.
Evidence: 13 tested symbols (serving-path refusals, mirrors, integration twins), M139/M140/M86
re-anchored and killed; `http_profile.fleet_strict_store_class` 5 tests + M323.

#### THM-0093 — An answer leg that needs a continuation does not proceed unbound
Verdict: CLEAN
Changed since review: `proxy.continuation_leg_binding` source (answering_commitment.rs,
continuation/*), tested symbols, M87 (#1108 4312c49a, #1113).
What was read: commit body and diffs; `continuation/refusal.rs` (Unavailable→503
ReplayCacheUnavailable as a deployment fact; Conflict and AlreadyAnswered→409 as the caller's);
`read_answer` (`Ok(None)` miss vs `Err` outage; no-capability → `capability_absent()` refusal);
`Retirement` four variants NotInvolved/Retired/AlreadyAnswered/Indeterminate (retirement.rs:78).
Why it holds: the plane became public so the proof front uses the same sequence; the serving
assembly keeps thin adapters; the four-valued retirement and outage-vs-miss attribution are now
carried by the plane's own types. #1108 fixed the proof front's divergent copy (outage misread as
forgery), which did not affect the serving path the claim is about.
Evidence: continuation_leg_binding battery incl. new `read_answer`/retirement/refusal-classification
tests; M87/M88 re-anchored, weakening unchanged in meaning.

#### THM-0096 — The runtime installs exactly the continuation capability its plan names
Verdict: CLEAN
Changed since review: four units, source/tested symbols/S19 (#1114 1a207717; app.rs commits for
`proxy.continuation_installation`).
What was read: `continuation_control.rs` (deleted `needs_control_runtime`), `serving_capabilities/
continuation.rs` (store arm now `control.handle()?`; OFF starts no runtime, asserted).
Why it holds: OFF still yields no store and an explicit OFF posture; a named store still
materializes exactly that store or refuses. The deleted test
`a_selected_capability_that_cannot_be_established_refuses_startup` is replaced by the
unreachable-store control on an idle provision, which asserts refusal and that the store asked for
the control runtime. The declaration conjunct is claimed at the strength stated in the scope,
unchanged.
Evidence: units FRESH; S19 structural (prose updated only); tested symbols updated by #1114.

#### THM-0101 — An emitted exchange transition corresponds to the work that justifies it ...
Verdict: CLEAN
Changed since review: `proxy.exchange_transition_ownership` source (continuation/*,
answering_commitment.rs, mod.rs) (#1108, #1113, #1147).
What was read: all direct `.advance(` sites in `http_profile_serve/`: `ContinuationRetired`
(answering_commitment.rs:162), `BackendDispatched` (mod.rs:495, :538), `ContinuationNotRequired`
(reply_assembly/mod.rs:66) — exactly the three assembly-owned events. The #1108 adapters attach the
exchange event inside the owner; `observe_retirement` reads projections.
Why it holds: the assembly-owned set is still exactly the three; stage-owned events still travel in
`Established<T>`; the two-direction control passed on 72127a07.
Evidence: exchange_transition_ownership source-measured battery; exchange_publication unchanged.

#### THM-0104 — Shutdown stops admission and bounds the wait on admitted work ...
Verdict: CLEAN
Changed since review: `proxy.serving_drain` source (connection.rs, core_admission.rs, mod.rs,
open_connection.rs) and `tests/async_drain_test.rs` (#1149, #1154, #1157).
What was read: full diffs. Drain grace, idle bound, handshake deadline and connection ceiling are
now read from `options.connection_bounds` (always in force) instead of `Option` limits; the
`None`-means-unbounded arms are deleted. Test changes are constructor-only (`ShardDepth::stated(n)`
→ `NonZeroUsize`, `ServerLimits` → `ConnectionBounds::from_limits`); no assertion removed or
weakened. The RAII guard, accept-loop exit and drain wait are untouched.
Why it holds: mechanism unchanged; bounds can no longer be absent. "A grace that cannot be turned
into an instant" is now unreachable from configuration (drain >1 day refused) but the stated
conditional remains true.
Evidence: `//mcp-re-proxy:async_drain_test` (async_serve feature lane) FRESH in run 38513625401.

#### THM-0132 — A replica serves on last-known admission state for at most P ...
Verdict: CLEAN
Changed since review: `proxy.admission_currency_gate` source (degraded_window.rs, enforcement.rs,
mod.rs), tested symbols, test sources (#1147 75fae5e3).
What was read: enforcer diff (test literals `max_assertion_age: 300` → `..AdmissionPolicy::default()`,
whose value is 300; new `From<AdmissionPosture> for AdmissionEnforcement` + test);
`config_state/admission.rs::enforcer_policy` vs the old `serving_capabilities.rs` mapping at a0b944c4
(lines 319–323, 370–377): identical `(allow_degraded_mode, degraded_propagation_bound)` projection,
P = `bound_secs` exactly, skew is the freshness owner's `MaxClockSkew` (not added to P).
Why it holds: the degraded window code (`degraded_window.rs`) logic is untouched; P is still exactly
the configured bound on the monotonic window.
Evidence: 9 degraded_window tests + enforcement/refusal tests + integration; mutation
`degraded_window_clock`.

---

## Re-review packet E2 — proxy signing credentials, peer identity, KMS, retention/attestation

Tree: main 72127a07. Reviews were current at a0b944c4; every change below is in
a0b944c4..72127a07. Evidence: run 38513625401, every lane green, all supporting units FRESH.
Verdicts: 7 CLEAN, 2 CLEAN-NOTE (THM-0073, THM-0082), 0 DISCREPANCY.

Shared, mechanical test churn (counted once here, cited below as "API-shape test edits"):
the proxy `integration` / `integration_async` crates and `tests/common/mod.rs` moved with
API reshapes and nothing else: `cli::parse_args(..)` now returns a proof wrapper
(`.into_inner()`, abd8f49f #1109); `app::run(config, ..)` became `app::run_request(config, ..)`
which is `ValidatedDeployment::try_from` then `run` (`app.rs:101-106`), so every
"refused however it was built" test still goes through the same validation boundary;
`ProxyDispatchConfig { fleet_strict: false, tier: None }` became
`ReplayAdmission::new(tier, ReplayPosture::SingleProcess)` (5f7a4cac #1113);
`max_clock_skew: 60` became `MaxClockSkew::new(60).expect(..)` (11c92802 #1160);
`SigningPlan::from_validated(..)` became `response_authority_plans(&validated).1` (4dc1510a
#1161). I read the full diffs of `app_startup_characterization_test.rs`,
`signing_credential_provenance_test.rs`, `delegated_serving_test.rs`,
`delegated_production_wiring_test.rs`, `root_key_lifecycle_test.rs`,
`transparency_e2e_test.rs` and `common/mod.rs`: no test deleted, no assertion removed or
weakened, no case dropped from a table.

#### THM-0062 — A response-signing credential exists only while a valid delegated key does
Verdict: CLEAN
Changed: `proxy.delegated_signing_credential` source_inputs `delegated_wiring.rs`,
`signing_plane/mod.rs` (4dc1510a #1161, 75e64d04 #1164, abd8f49f #1109); test_sources
(API-shape test edits).
Read: both diffs in full. `plan.custody` field reads became `plan.custody()` /
`plan.epoch()` accessors; the epoch override became `plan.minting_under(epoch)`
(`startup_plan.rs:236-240`: clone, set `custody.trust_epoch`, nothing else — identical to the
old field write); `SigningPlane::materialize` narrowed `pub` -> `pub(crate)` and takes
`&StartupReading` whose `unix_seconds()` is the same `now_unix()` reading (`clock.rs:67-91`).
No change to `delegated_server_signer/*`, `rotation.rs`, `mint_successor.rs`,
`trust_epoch_advance.rs`, `delegated_response_signer.rs` — the snapshot, expiry, retirement,
poison-recovery and backoff logic the claim is about.
Holds: the credential lifecycle code is untouched; the edits are plan plumbing.
Evidence: the unit's 60 tested symbols incl. `no_key_before_first_rotate_fails_closed`,
`snapshot_fails_closed_past_expiry`, `fail_closed_issuance_retires_the_snapshot`,
`issuance_failure_serves_the_valid_key_then_fails_closed_at_expiry`,
`backoff_never_sleeps_past_a_still_valid_key`,
`a_poisoned_snapshot_lock_is_recovered_and_retirement_still_dominates`,
`a_mint_landing_after_the_owner_is_gone_cannot_restore_signing`; integration
`missing_delegated_key_fails_closed`, `root_issuance_failure_serves_until_delegated_key_expiry_then_fails_closed`.
Premise ASM-0068 REVIEWED.

#### THM-0073 — Serving materialization refuses a deployment whose two signing roles are one key
Verdict: CLEAN-NOTE
Changed: `proxy.signing_role_separation` source_inputs (all four key_source files),
test_selection, mutation_probes M432 — a6f2091b (#1111, MCPRE-185, closes #1099);
`proxy.signing_credential_provenance` source_inputs `app.rs`, `signing_plane/mod.rs`, test
sources, M254/M432.
Read: #1111 in full. `MaterializedSigningRoles::establish` and `compare_roles` are unchanged in
substance (the comparison over `response_role_identity` / `channel_role_identity`
`raw_point()`, the three-valued `RoleSeparation`, refusal on `Collapsed`); the witness now also
holds the requested channel custody. `key_source()` (the borrowed `&dyn KeySource`) is DELETED;
the witness exposes `channel_credential()` -> `EstablishedChannelCredential::establish`
(`key_source/channel_credential.rs`), which reads chain, client CA and handshake key eagerly
with `?` and refuses a custody mismatch; the response role is reached only via the witness's
`ResponseSigner` impl. `app.rs:195-201` takes `roots.channel_credential()?` immediately and
`app.rs:244` `roots.response_public_key()?`; no `.key_source()` remains anywhere in
`mcp-re-proxy/src`.
Holds: the statement ("obtains its key source only as the product of a comparison over the two
materialized public keys, and that comparison refuses before any server starts") is unchanged
in truth, and the NotCompared argument is now stronger: a listener is built only from an
established channel credential, and establishing it reads the chain.
Note for the owner (scope prose, not the proposition): the scope says
`proxy.signing_credential_provenance` "pins both reads ... and `M432` is the probe that swallows
it". After #1111 the root's eager channel read is `channel_credential()` (pinned by
`the_composition_root_reads_both_signing_roles_eagerly_and_fallibly`, `EAGER_ROLE_READS =
[".channel_credential()", ".response_public_key()"]`), and M432 now swallows the chain read
inside the owner (`channel_credential.rs`, `tls_server_cert_chain().unwrap_or_default()`),
killed by `an_unreadable_channel_chain_refuses_establishment` in
`proxy.signing_role_separation`. Each sentence remains true of a read of the chain; the scope
no longer says that the clause rests on the owner as well as on the root's read, which is what
#1111's commit message records. No claim edit proposed.
Evidence: `a_deployment_whose_two_roles_are_one_key_cannot_be_materialized`,
`a_role_that_produced_no_key_is_not_reported_as_a_separated_one` (now also asserts
`channel_credential()` errs without a chain), `two_distinct_roles_materialize`,
`an_unreadable_channel_chain_refuses_establishment`,
`an_unreadable_exported_key_refuses_establishment`,
`a_delegated_signer_is_used_without_reading_an_exported_key`; M432 (expect_red above); the
provenance unit's six tests. Depends on THM-0025, THM-0027 (THM-0027 is itself in this
campaign's stale set, another group).

#### THM-0080 — Serving derives peer identity only from the credential the mechanism accepted
Verdict: CLEAN
Changed: `proxy.serving_identity_provenance` source_inputs `async_serve/{connection,
core_admission,http_limits,inbound,mod,open_connection}.rs`, `tls.rs` (a36c92ff #1157,
0ba3db26 #1154, 6f9ea226 #1149); gate_controls `scripts/serving_identity_provenance_gate.py`
(bff0cb91 #1145); test_sources (API-shape test edits).
Read: code-line diffs of the serving files: all are `ServerLimits` -> `ConnectionBounds`
(timeouts become always-present bounds), `ShardDepth` -> `NonZeroUsize`, drain grace. Grepped
the diff for resolver/identity/peer/certificate/currency/x509: comment lines only. The gate
diff replaces its private `production_text` test-region stripper with the shared
`_rust_source.production_view`, and `rglob("*.rs")` with `crate_sources` (same walk minus
build outputs, crate `tests/`/`benches/`/`examples/`, `build.rs`); `RESOLVERS`, `COMPOSITION`,
`FORBIDDEN_PARAM`, the signature regex and the once-per-path count are unchanged. I ran the
gate (rc 0) and its `--selftest` (rc 0) on 72127a07.
Holds: neither serving path's identity route moved; the measurement measures the same thing.
Evidence: `serving_identity_provenance_test` (unchanged file):
`each_serving_path_asks_its_authority_exactly_once`,
`neither_serving_path_reconstructs_identity_from_representation`,
`the_resolver_admits_no_second_credential`, `the_rules_would_catch_each_regression`; gate.

#### THM-0082 — The serving path signs under the credential source materialization produced
Verdict: CLEAN-NOTE
Changed: `proxy.signing_credential_provenance` source_inputs `app.rs` (12 commits; bearing:
a6f2091b #1111, 75e64d04 #1164), `signing_plane/mod.rs`; test_sources; mutation_probes M254,
M432.
Read: as THM-0073, plus `signing_credential_provenance_test.rs` diff in full and `app.rs`
195-250, 395-410. `build_key_source(` occurs once in `app.rs`; none of the
`RIVAL_CONSTRUCTORS` (`FileKeySource::`, `Pkcs11KeySource::`, `AwsKmsKeySource::`,
`GcpKmsKeySource::`) occurs; `SigningPlane::materialize(&signing_plan, roots,
&startup_reading)` still moves the same witness in (`SigningPlane::materialize` is now
`pub(crate)`, narrower). The test's `WITNESS_EXIT` became `.channel_credential()` and still
asserts exactly one occurrence; `the_role_reads_follow_the_witness_exit` now anchors on
`build_key_source(`; its regression self-test was updated to the new spellings, same four lazy
shapes. M254's anchor follows the `&startup_reading` argument; its weakening (`let rival =
roots;`) is unchanged.
Holds: the root opens one source through the materializer, constructs none, and installs the
signing plane from that same witness — all still true, and the source now never leaves the
witness at all.
Note for the owner: the statement says the root "reads it through the role-separation
witness's one borrowed projection". That projection (`key_source()`, a `&dyn KeySource`) was
deleted by #1111; the root now takes the witness's one channel projection
(`channel_credential()`, an owned established credential) and reads the response key through
the witness's own `ResponseSigner`. The proposition is unchanged and if anything stronger; the
phrase "one borrowed projection" describes the pre-#1111 shape. No claim edit proposed.
Evidence: the six `signing_credential_provenance_test` tests; M254; depends on THM-0062,
THM-0064, THM-0073, THM-0116.

#### THM-0087 — Through MCP-RE, a continuation entry is reachable only by the actor the verifier resolved
Verdict: CLEAN
Changed: `proxy.continuation_key_provenance` source_inputs `continuation/answer_leg.rs`,
`open_leg.rs`, mutation_probes M88 — 4312c49a (#1108, MCPRE-182).
Read: both diffs in full, `continuation/mod.rs:100-140`, `continuation_store/key.rs:48-55`,
M88, and the proof front `examples/http_profile_proxy.rs` before/after. `prepare` /
`record_open_leg` became public `read_answer(verified: &VerifiedMcpRequest, body, aud)` /
`record_open(verified, ..)` returning a `ContinuationRefusal`; the serving assembly calls them
through thin wrappers that pass `ex.verified` and `envelope.body()` and record the same
exchange events. The key is still `ContinuationKey::for_request(audience_id, verified,
state)`, which reads `verified.resolved_actor().actor_id()` — the verifier's product, never the
body. Peek remains non-consuming; an outage remains a 503 `ReplayCacheUnavailable` (new test
`an_answer_leg_reaching_an_unreachable_tier_is_refused_as_unavailable` asserts it is never
`ContinuationBindingFailed`). The proof front previously built its own key and read `peek`
errors as a miss; it now goes through the owner — the claim's "through MCP-RE" surface got
narrower, not wider. M88's anchor/weakening moved to the new call shape and still forges the
actor from `params.actorIdentity`.
Evidence: `the_operand_is_the_carried_products_actor_and_not_one_the_body_asserts`,
`the_leg_is_recorded_under_the_carried_products_actor`, M88; the store unit's
`one_actors_entry_is_not_reachable_by_another`, `peek_does_not_consume_and_consume_is_one_shot`
(store files unchanged). Premises ASM-0047/0048/0060 REVIEWED; depends on THM-0051.

#### THM-0089 — A KMS or STS endpoint reaches the authority its text names
Verdict: CLEAN
Changed: `proxy.kms_endpoint_authority` test_sources only (API-shape test edits).
Read: the `app_startup_characterization_test.rs` diff in full; in
`a_programmatic_config_cannot_point_a_root_key_endpoint_at_a_plaintext_host` only
`parse_args(..).into_inner()` and `run` -> `run_request` changed; every (flag, reason,
mutation) case and the negative control are intact. `kms_endpoint_policy/*` unchanged.
Evidence: the unit's 19 tested symbols (`kms_endpoint_policy::tests::*`,
`endpoint::tests::*`, the integration test above). Premise ASM-0082 REVIEWED.

#### THM-0112 — A retained hop is exactly what re-verifies it, and nothing a sender could widen it to
Verdict: CLEAN
Changed: `proxy.retained_record_content` test_sources only (API-shape test edits).
Read: `transparency_e2e_test.rs` diff in full (server builders and `signing_plan` helper only);
`transparency/retained_record.rs`, `covered_set.rs`, `durability.rs` unchanged.
Evidence: `covered_set::tests::*` (four widening attacks), `retained_record::tests::*`,
`durability::tests::only_the_signed_headers_are_retained`,
`transparency_e2e_test::a_served_notification_is_retained_like_any_other_accepted_exchange`.

#### THM-0113 — An attestation is checked against the bytes it was issued over, and says which binding it established
Verdict: CLEAN
Changed: `proxy.evidence_attestation` test_sources only (API-shape test edits).
Read: as THM-0112; `transparency/attestation.rs` unchanged; the three tested e2e functions'
bodies unchanged (only shared builders moved).
Evidence: `a_served_call_becomes_an_offline_verifiable_receipt`,
`the_statement_is_verifiable_against_the_bytes_the_store_kept`,
`a_chain_with_no_verified_hop_is_still_attested`. Premise ASM-0037 REVIEWED; depends on
THM-0088.

#### THM-0116 — A non-exporting signer's advertised key is established at construction, and a signature it cannot verify is never emitted
Verdict: CLEAN
Changed: `proxy.aws_kms_adapter` source_inputs `aws_kms_keysource.rs` — 75e64d04 (#1164).
Read: the diff: `amz_date_at` calls `crate::clock::reading_is_faulted(now)` instead of
`startup_plan::host_clock_is_faulted(now)`; both are `now_unix < EPOCH_CLOCK_FAULT_THRESHOLD_SECS`
with the constant `946_684_800` in both trees. Construction-time key-spec/SPKI checks and the
verify-before-return path are untouched; GCP and PKCS#11 adapters unchanged.
Evidence: `non_ed25519_key_spec_fails_closed`, `get_public_key_parses_ed25519_spki`,
`prehash_signature_is_rejected_before_return`, `aws_backend_signs_and_verifies_end_to_end`,
`an_authority_that_re_points_the_request_is_refused`. Premises ASM-0027/0052/0053/0054/0076
REVIEWED; depends on THM-0108, THM-0089.

---

## Re-review packet F — client, SDKs, conformance (main 72127a07, base a0b944c4)

Method: per theorem, the supporting units' semantic deltas from `rereview/manifest.json`; every
changed file's diff `a0b944c4..72127a07` read (not stat); claim (statement, scope) read in full;
unit `[[unit]]` entries and probes read for new units and for moved tests. Evidence: run
38513625401, all supporting units FRESH. No theorem text changed; every specification review
is REVIEWED. Dependency theorems in other groups (THM-0016/0019/0020/0022/0046/0057/0121) are
judged in their own packets; nothing in this group's claims re-derives them.

Commits touching this group: 11c92802 (#1160 MaxClockSkew one producer), 9734fe2b (#1152
ValidatedClientConfig), 3db41cbd (#1158 typed signing-device failure), abc3e183 (#1151 SDK
binding core), 61605e13 (#1162), 4dc1510a (#1161), 5f7a4cac (#1113), abd8f49f (#1109),
cab75969 (#1110), 432f0081 (#1116).

---

#### THM-0058 — A client accepts a response only under a signer its trust configuration authorizes
**Verdict:** CLEAN
**Changed since review:** `client.response_signer_authorization` source_inputs:
`mcp-re-client-core/src/response.rs` (11c92802, 61605e13, 3db41cbd).
**What was read:** the whole diff. Every hunk is inside `mod delegated_tests` (line 357 on):
`DelegationPolicy::new` takes `MaxClockSkew::new(60)`; test wire codes respelled to frozen
tokens (`mcp-re.request_signature_invalid` → `mcp-re.invalid_signature`,
`mcp-re.upstream_unavailable` → `mcp-re.inner_dispatch_indeterminate`; #1158 made the SDK
wire-code gate scan these crates); one stale-credential test rebuilt on `SigningWindow::stated`.
**Why it holds:** no production line of the signer-authorization path changed. The renamed
test `the_widest_constructible_skew_cannot_widen_the_credential_window_past_its_bound` is
stronger than its predecessor: it asserts a week is not constructible and that the widest
legal skew (300 s) still refuses a credential 3300 s past `exp` with
`DelegationCredentialExpired`. Revoked-kid/jti and no-credential refusals untouched.
**Evidence:** `client.response_signer_authorization` battery (FRESH); control-dispositions
entry for the renamed test updated (`control-dispositions.toml:7023`).

#### THM-0059 — An unbound receipt is never a success and never another request's answer
**Verdict:** CLEAN
**Changed since review:** `client.response_binding_disposition` source_inputs: `response.rs`
(same three commits).
**Why it holds:** test-module-only changes as above; the bound/unbound/preflight disposition
code is unchanged. The preflight-splice tests (`spliced` receipt for the attacker's request,
`generic` no-request receipt) keep their assertions; only their wire-code literal changed.
**Evidence:** `client.response_binding_disposition` battery (FRESH).

#### THM-0061 — A receipt that says nothing is not a receipt that says nothing ran
**Verdict:** CLEAN
**Changed since review:** `client.receipt_contract_carriage` (`response.rs`),
`client.proxy_reply_disposition` (`mcp-re-client-proxy/src/proxy.rs`, 11c92802, 3db41cbd).
**What was read:** both diffs; `proxy.rs` hunks are all inside `mod tests` (line 543 on).
**Why it holds:** `an_unstated_contract_produces_no_invented_disposition` and the
possibly-executed plain-error test keep every assertion (`execution_status` absent when
unstated; `possibly_executed` / `unsafe_without_reconciliation` / `consumed` carried) with
frozen tokens. No production change to the contract parse or the plain-error rendering.
**Evidence:** both units' batteries (FRESH).

#### THM-0076 — A client accepts only an answer to its own request, under a signer it trusts
**Verdict:** CLEAN
**Changed since review:** `client.response_binding_disposition`,
`client.response_signer_authorization` — `response.rs` test module only (above).
**Why it holds:** composition of THM-0058/0059/0084 over unchanged production code; the
shipped `ClientProxy` path is unchanged (THM-0084).
**Evidence:** as THM-0058/0059.

#### THM-0084 — The shipped client proxy verifies against the request it sent
**Verdict:** CLEAN
**Changed since review:** `client.proxy_request_correspondence` source_inputs: `proxy.rs`.
**Why it holds:** `proxy.rs` changes are test-module-only (wire-code literals,
`MaxClockSkew` construction). `handle` still builds one `SignedRequest`, forwards it and
derives the expectation from it; no second request reconstruction was introduced.
**Evidence:** `client.proxy_request_correspondence` battery (FRESH).

#### THM-0091 — The sidecar signs only for a request its ingress policy admitted
**Verdict:** CLEAN
**Changed since review:** `client.local_leg_declaration` (`config/validation.rs`),
`client.bind_scope` + `_sole_producer` (`config/bind_scope.rs`, `serve/mod.rs`; new test
symbol), `client.accepted_authority` + `_sole_producer` (`serve/accepted_authority.rs`),
`client.local_request_surface` (`serve/mod.rs`, `tests/local_leg_e2e_test.rs`) — all #1152
(9734fe2b), plus #1160 and fixture commits for the e2e test.
**What was read:** all five diffs; `BindScope` constructors.
**Why it holds:** the change makes the claim's "possession of the scope IS that permission"
more literal. `check_local` now returns the `BindScope` `BindScope::decide` granted;
`ValidatedClientConfig` carries it; `serve::bind(scope: BindScope)` no longer takes
`LocalConfig` and no longer re-decides — it opens the socket for the scope's address and
re-scopes the OS-bound address via the new `pub(crate) BindScope::bound_to`, which is
`Self::decide(bound, self.exposed)`: a loopback scope admits only a loopback bound address,
an off-host scope carries only the operator's declaration. `decide` remains the only
constructor; the representation stays private. The accepted authority is still derived from
the scope (`accepted_authority.rs` change is a test using `bind(scope(..))`). Caller-shape
refusals and framing are untouched. The e2e test changes are fixture API updates
(`BindScope::decide`, `ReplayAdmission`, `response_authority_plans`); no test removed.
New test `a_bound_address_is_admitted_off_host_only_under_an_off_host_scope` pins `bound_to`.
**Evidence:** bind_scope / accepted_authority batteries and their sole-producer structural
probes (FRESH); `bind_refuses_a_non_loopback_address_unless_it_is_declared` retained.

#### THM-0094 — The shipped Python SDK accepts only an answer to its own request
**Verdict:** CLEAN-NOTE
**Changed since review:** ten `sdk_python.*` units (`transport.py`, `correlation.py`;
#1160, #1158), `sdk_python.native_binding` (all five `sdk/python/src/*.rs`, test selection,
probes M569/M570 → binding core, M591 new, governing boundary `boundary.pyo3_marshalling`),
and NEW_UNIT `sdk_binding_core.adapter` (#1151).
**What was read:** `transport.py`/`correlation.py` diffs; `sdk/python/src/refusal.rs`;
`sdk/binding-core/src/error.rs` (`wire_code`); the native_binding and adapter `[[unit]]`
entries and their tested symbols before/after; probes M569/M570/M591.
**Why it holds:**
- *Verdict over transmitted bytes, anchor and policy from caller values, field-for-field
  projection:* moved from the PyO3 crate into `mcp-re-binding-core`, used by both bindings.
  The four controls that carried the native-binding sentence at the review
  (`an_empty_issuer_field_is_refused_by_name`, `a_retired_root_resolves_through_its_deadline_and_not_after`,
  `an_absent_execution_member_stays_absent_in_the_projection`,
  `a_rejection_is_not_reported_as_a_success`) now live in `sdk_binding_core.adapter`'s
  battery, and M569 (empty issuer) / M570 (silence not read as not-executed) now target
  `pinned_issuer.rs` / `verdict.rs` in the core. The adapter is in this theorem's
  `supported_by`, so the closure covers them.
- *Local failures never as a peer wire code:* the `"mcp-re: <token>"` rendering and the
  regex parser `_peer_wire_code` are deleted. A core refusal is now `_core.WireRefusal`
  (`.wire_code` = frozen token, set only from `BindingError::Wire`); a signing-device failure
  is `SigningDeviceFailure` with no wire code, a `ValueError` subclass that `_one`/`_notify`
  deliver under the `mcp-re-sdk:` prefix; any other `ValueError` is local. Strictly tighter
  than the reviewed state, where the token was recovered by parsing prose.
- *Skew bound / consumed grace:* `MAX_CLOCK_SKEW_BOUND` and `_CONSUMED_GRACE` now read
  `_core.max_clock_skew_bound()` (300) instead of a literal 300 — same value, one source.
- Correlation, nonce floor, notification, envelope, continuation units: `transport.py`
  changes in their files are the ones above; no behaviour of theirs changed.
**Note for the owner:** the SCOPE paragraph "THE NATIVE BINDING IS INSIDE IT.
`sdk_python.native_binding` owns what the PyO3 binding does with the values it is handed and
with the core's verdict" now names one owner where there are two: the anchor, policy, device
failure and projection are `sdk_binding_core.adapter`'s (the native_binding unit's own
description now says so). The statement is still true and both units are in the closure;
only the scope's attribution is out of date. Not a claim error; offered for wording.
Also observed, PRE-EXISTING and not in this delta: a core refusal raised while SIGNING
(`HttpProfileError` → `BindingError::Wire`) reaches the application as a wire code although
no peer sent it. That was the reviewed behaviour at a0b944c4 (then via `_peer_wire_code`) and
#1158 did not change it; mentioned only so the "signing failure" sentence is read with it.
**Evidence:** sdk_python.* units, `sdk_python.native_binding`, `sdk_binding_core.adapter`
(20 tested symbols, M569/M570) — all FRESH.

#### THM-0095 — The shipped TypeScript SDK accepts only an answer to its own request
**Verdict:** CLEAN-NOTE
**Changed since review:** eleven `sdk_typescript.*` units (`transport.ts`, `correlation.ts`),
`sdk_typescript.native_binding` (five `src/*.rs`, M567/M568 probes, `boundary.napi_marshalling`),
NEW_UNIT `sdk_binding_core.adapter`.
**Why it holds:** as THM-0094. `peerWireCode` (message regex) replaced by `coreWireCode`,
which reads the thrown error's typed `code` and accepts it only in the `mcp-re.` namespace;
the binding throws `SigningDeviceFailure` / `InvalidArg` codes outside that namespace, so a
device or argument failure travels under `mcp-re-sdk:`. `MAX_CLOCK_SKEW_BOUND` and
`CONSUMED_GRACE` read `maxClockSkewBound()` (300). "Refusing any time or skew that is not a
whole number of seconds" stays measured by `a_time_that_is_not_whole_seconds_is_refused`
(native_binding) and the core's `a_skew_past_the_bound_is_refused_and_the_bound_is_accepted`.
**Note for the owner:** same scope-attribution wording as THM-0094
(`sdk_typescript.native_binding` "owns" what is now shared with the adapter). Also: unlike
Python's type check, `coreWireCode` trusts any thrown object's `code` in the `mcp-re.`
namespace, so a caller-supplied `poster` that threw an error with such a `code` would be
reported as a peer token. The reviewed `peerWireCode` had the same exposure through
`message`; this is unchanged in kind, not introduced.
**Evidence:** sdk_typescript.* units, native_binding, adapter — FRESH.

#### THM-0111 — Two vocabularies decide what an mcp-re.* verdict token says
**Verdict:** CLEAN
**Changed since review:** `conformance.verdict_vocabulary_scope` (guard test,
`verification/generated/rust-targets.json`), `conformance.scanned_tree_declaration`
(`mcp-re-conformance/BUILD.bazel`), `conformance.carrier_minting_absence` (guard test,
`mcp-re-proxy/src/http_profile_dispatch.rs`, `.../core_projection.rs`; 5f7a4cac, cab75969,
abc3e183, 61605e13).
**Why it holds:** the new crate `sdk/binding-core` is added to `CRATE_SOURCE_TREES` and to
the guard's `data`/`env`, so the workspace-wide scan covers it (the "a new member is scanned
or the lane fails" property is exactly what forced this). The replay-tier dispatch gate's
projection lost the `NoDeclaredReplayTier` arm because #1113 made an undeclared tier
unrepresentable; the `From<&ProxyDispatchError> for McpReError` projection is still
exhaustive with no wildcard, and `SubMinimumReplayTier` still maps to
`ReplayCacheUnavailable`. The BUILD change at line 346 (`scitt_retained_corpus_test` →
`_pre052`) is unrelated to the guard.
**Evidence:** `audit_vocabulary_guard_test` (FRESH) incl. `the_scanned_crate_set_is_the_workspace`.

#### THM-0120 — A client that cannot establish current anchors publishes none
**Verdict:** CLEAN
**Changed since review:** `client.anchor_refresh` test_sources only:
`tests/local_leg_e2e_test.rs`.
**Why it holds:** fixture API updates only (above); refresh dispositions untouched.

#### THM-0122 — A security record says what a Core verdict says
**Verdict:** CLEAN
**Changed since review:** `conformance.audit_vocabulary_drift` — the guard test file, whose
only change is the binding-core scan entry and a doc sentence (abc3e183).
**Why it holds:** `core.audit_vocabulary` is unchanged; the drift control's token parsing and
success/key-lifecycle allowlists are untouched.

#### THM-0123 — An admitted local request cannot leak its slot, ...
**Verdict:** CLEAN
**Changed since review:** `client.local_serving_pipeline` test_sources: e2e test only.
**Why it holds:** fixture updates; the in-flight ceiling, routing, deadlines and
pause rendering code is unchanged.

#### THM-0124 — A declared binding commits to what the verifier will digest, or the deployment does not start
**Verdict:** CLEAN
**Changed since review:** `client.deployment_config` (`config/mod.rs`, `validated.rs` new,
`validation.rs`; test selection gains the parity test target), NEW_UNIT
`client.validated_config_sole_producer` (#1152, #1160).
**What was read:** all three diffs; `validated.rs`; both unit entries; probes S57/S58;
`clock_skew_parity_test.rs`.
**Why it holds:** the document checks are unchanged in content and now run in the ONE
constructor `ValidatedClientConfig::new` (private representation; S57 refuses assembling it
around an unchecked document, S58 refuses handing `build` a raw `ClientConfig`).
"The configured clock-skew bound equals the profile's, and a value outside it is refused":
the client's private `MAX_CLOCK_SKEW_SECS = 300` and the equality test
`a_config_skew_bound_matches_the_profile_bound` are deleted because there is no second bound
left to compare — `check_trust_and_delegation` builds `MaxClockSkew::new(skew)`, the profile's
own type, and refuses `None`. `an_out_of_range_clock_skew_is_refused` now also asserts the
bound itself is the running skew and that bound+1 is refused naming the bound;
`clock_skew_parity_test` asserts sidecar and SDK refuse 301 s and accept 300 alike. The
claim is now true by construction rather than by a pinned equality.
**Evidence:** `client.deployment_config` (19 tested symbols), structural S57/S58 — FRESH.

#### THM-0126 — A verified reply is not a completed call
**Verdict:** CLEAN
**Changed since review:** `client.verified_outcome` (`verified_outcome.rs`, 11c92802): one
line inside `mod tests` (`MaxClockSkew::new(60)`).

#### THM-0127 — The deployable's serving path always runs an anchor refresher
**Verdict:** CLEAN
**Changed since review:** `client.serving_lifetime` (`startup.rs`, 9734fe2b).
**Why it holds:** `serve_until_shutdown` takes the cadence (`reload: Duration`) instead of the
whole `ClientConfig`; `main.rs:129` passes `config.reload_interval()` from the
`ValidatedClientConfig`, whose checks bound `trust.reload_secs`. The refresher is still
started before the listener is served and held for the serve; the control
(`serve_until_shutdown must start the anchor refresher`, startup.rs:398-432, incl. the
source-order assertion) is unchanged apart from passing the duration.

---
Summary: 13 CLEAN, 2 CLEAN-NOTE (THM-0094, THM-0095: scope attribution names
`*.native_binding` as sole owner of what the binding core now owns), 0 DISCREPANCY.
No formal-proof surface in this group (all V0).
