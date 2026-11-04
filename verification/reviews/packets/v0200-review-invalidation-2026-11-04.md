<!-- SPDX-License-Identifier: Apache-2.0 -->

# v0.20.0 review-invalidation census and re-review packets: 76 stale theorem reviews (2026-11-04)

Layer 1 (measurement). Integration baseline main `bae159e07`; the tree these digests describe
adds two evidence corrections (below) at `9920603ed`. Baseline: the v0.19.0 closure record
`verification/closures/0f902773dfa647d82c1a18b96a5bdc3b4e5b0ce2.json` (135/135). At this tree
`tools/verification/review` reports **59 of 135 REVIEW_CURRENT**. Tracking: #1297.

**Nothing here is an approval.** No specification record, ruling or ledger line is written by
this packet. Every verdict below is an agent reading prepared for the owner, who ratifies,
rejects or amends. THM-0070's claim correction and the THM-0101 discrepancy are owner decisions
about claim text.

## Method

The census is derived, not hand-listed. For each theorem it recomputes, with the functions
`tools/verification/review` uses (`fingerprint_theorem`, `fingerprint_unit`, `theorem_premises`,
`theorem_review_digests`), the claim fingerprint and the semantic `review_digest`, and compares
them component by component with the record's `components` and `review_components`:

- claim surface: `theorem_claim`, `theorem_dependencies`, `theorem_review_requirement`;
- premises: each assumption digest in the closure;
- per supporting unit: each `SEMANTIC_UNIT_COMPONENTS` digest.

Changed FILES come from each moved unit's current input set (`source_inputs`, `test_sources`,
`proof_dependencies`, …) intersected with `git diff <base>..9920603ed`, and are attributed to the
first-parent merges that touched them. `<base>` is `0f902773` (the v0.19.0 closure, where all
135 were current) for a record written before it, and the record's own commit otherwise
(THM-0074 and THM-0101 at `f28ec97c3`, THM-0136 at `ab5f4f4ff`).

Each causing PR's diff, restricted to those files, was then read once against every stale
theorem it touches (one packet per PR, below). Verdicts:

- **CLEAN**: the proposition holds and the evidence still bears.
- **CLEAN-NOTE**: it holds, and there is something the owner should see.
- **DISCREPANCY**: the claim or its evidence closure is no longer accurate.

## Result

**75 of 76 hold; 1 DISCREPANCY (THM-0101); 1 claim correction pending (THM-0070).**
No premise digest and no review requirement moved for any of the 76. No formal-proof input
(`proved_symbols`, `lean_theorems`) moved.

| category | count |
|---|---|

| A. claim text changed | 1 |
| B. dependency propagation only | 1 |
| C. supporting production source changed | 60 |
| D. evidence selection only | 0 |
| E. supporting-unit set changed | 1 |
| F. test sources only | 13 |

| required disposition | count |
|---|---|
| re-record at the current digests | 63 |
| owner confirms the note(s), then re-record | 10 |
| OWNER: approve or reject the scope correction, then re-record | 1 |
| re-record together with THM-0070 (propagation only) | 1 |
| OWNER DECISION: claim text or control, before any re-record | 1 |

| provenance of the stale record | count |
|---|---|
| agent re-review, ratified by owner ledger line `owner-signature:epic-1201-assurance-closure-2026-10-21` | 42 |
| delegated agent decision 2026-10-22 (Verus change); not a personal owner signature | 13 |
| owner batch ruling 2026-10-14 (MCPRE-218) | 11 |
| delegated agent decision 2026-10-22 (toolchain modernization); not a personal owner signature | 5 |
| agent record under owner ruling 2026-10-27; no ledger line | 2 |
| owner-authorized step 7 re-review (Ruling 40) | 2 |
| agent record under owner ruling 2026-10-29; no ledger line | 1 |

### Owner decisions

1. **THM-0070**: approve or reject the scope correction of #1283. The claim fingerprint moved
   `dd38b842…` → `7660e7ca…`; the correction record is
   `verification/claim-corrections/THM-0070-stderr-offer-order-scope-2026-11-03.json`.
   THM-0071 is pure propagation and is re-recorded with it.
2. **THM-0101 (DISCREPANCY, #1277)**: the claim says the serving path states exactly three
   assembly-owned events. Since #1277 `disposition` (`mcp-re-proxy/src/http_profile_serve/mod.rs`)
   also states `ExchangeEvent::Refused` through `ExchangeProgress::refuse()`
   (`mcp-re-proxy/src/exchange_state/publication.rs`). The control
   `the_serving_path_states_only_the_assembly_s_own_transitions`
   (`mcp-re-proxy/tests/integration/exchange_transition_ownership_test.rs`) scans for `.advance(`
   only, so it stays green. Either the claim names the refusal route with its own control, or the
   scan covers `refuse()` and the claim's set grows; both change claim text. Separately the
   `proxy.publish_permit_sole_producer` description still says the permit exposes the exchange
   "only by shared reference"; #1277 added `withdraw(self) -> &mut`.
3. **THM-0136 (#1256)**: two source-scan order tests were replaced by type order plus structural
   probes S80/S81 and re-adjudicated mutation probes. Confirm the substitution; the re-adjudicated
   probes are unmeasured until the scheduled run.
4. **The other CLEAN-NOTE items** are listed per theorem below and explained in their PR packets.

### Evidence corrections made with this packet

Both move only theorems already stale here, so the owner reads them in the same pass:

- **THM-0077**: `proxy.legality_boundary_totality` gains
  `mcp-re-proxy/src/config_state/validation/refusable_machines.rs` and `total_machines.rs`. The
  first-pass classifier that produces every legality machine's refusals was in no unit's paths
  (unit-closure register, UC-1, since `7e184961`), so #1253 rewrote it without moving any review
  fingerprint. Read both files whole, not as a diff.
- **THM-0090**: `an_agents_https_is_authenticated_by_the_proxys_own_connector`
  (`mcp-re-proxy/src/outbound_fetch/binding.rs`) sends a request through
  `VettedDestination::agent` to a private-CA server and requires the connector's `UnknownIssuer`
  as an I/O error. With the connector unchained it fails (`TlsRequired`); under a ureq TLS feature
  it would fail on ureq's own error variant. Before this, the connector's refusal was tested on a
  socket only, so ASM-0092's "the connector that speaks TLS is this one" had no request-level
  control.

## Per-theorem census

Fingerprints are the first 16 hex digits. "claim fp" is unchanged unless an arrow is shown.

| theorem | cat | claim fp | review digest (record → now) | moved (unit: components) | causing PRs | verdicts | disposition |
|---|---|---|---|---|---|---|---|
| THM-0001 | C | 1ac678800a4ac149 | fc5416c136158b86 → a580b404beef654d | `http_profile.freshness_window`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0003 | C | 0dfcfbd73ce6e43d | a59c339692bffc31 → 9d00e7b9359814ef | `http_profile.admission_currency`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0004 | C | 159cb32ef80b0770 | 96e35713f3829a35 → cc6ae4cbf04a3cbd | `http_profile.admission_currency`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0005 | C | aa09c2838cc39291 | c7800222926759c5 → 152f2e73b4bd491d | `http_profile.admission_currency`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0006 | C | 858b9d7be9c726e5 | 7eb2865318cb2c67 → cb3bf56482d7064f | `http_profile.admission_currency`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0007 | C | ab73c764a7ac3b50 | f487f215ac4e66d9 → 8fd1f133f6a85bb3 | `http_profile.artifact_typing`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0009 | C | f891aa87da728c7f | 09ddad2c61326c18 → d60e193993299f5c | `http_profile.continuation_unbypassability`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0010 | C | 69b6f32424f55fba | 82edd8074322a207 → 06135689fb3c7776 | `http_profile.continuation_binding`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0013 | C | 222ff157f0f34c25 | 4606cf77c95d755c → 5e37627e718e461a | `proxy.online_ocsp_reachability`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0014 | C | f88e7b44fb0fe96e | 415916117f10a447 → 3657c7c258f07be3 | `http_profile.freshness_window`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0016 | C | 72e76db6da1548a5 | a2664516b11cdaf6 → 6dcdd8a281299e45 | `http_profile.freshness_window`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0017 | C | 077bfbfcb16f265b | adfa5874868e97e4 → d8e6302142461da4 | `http_profile.freshness_window`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0021 | C | 4af426ca8dcb0f33 | 3bd8e07cecce2a7f → ed6ec4c8e8429253 | `http_profile.freshness_window`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0022 | C | 26250e9cf23da4a0 | e1c09e4cd5a5bc14 → 3eff31864fb32ac0 | `http_profile.freshness_window`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0024 | F | 49de376b15e2eccb | 801197cd611fe545 → 202fa3d86bdb9a7b | `proxy.certificate_identity`: test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0026 | C | fc7c6804aca29d3e | dd12f58d691efd50 → 966c1012d1ec8d0c | `proxy.credential_key_correspondence`: source_inputs | #1253 #1270 | CLEAN ×2 | re-record at the current digests |
| THM-0027 | C | faec59e583744094 | 930860c9ee2f470e → 57f4881a8fa5a1a8 | `proxy.delegated_resolver_materialization`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0031 | C | 3a18e01fff6ca10c | 5420489356b80efe → 735c26793f2a459d | `proxy.channel_peer_resolution`: source_inputs | #1253 #1270 | CLEAN ×2 | re-record at the current digests |
| THM-0032 | C | 91e09c858b798230 | 10c2da1985c84ac9 → a4d80e0960c44358 | `proxy.client_revocation_index_verdict`: source_inputs; `proxy.currency_policy_classification`: source_inputs; `proxy.per_request_revocation_serving`: source_inputs+test_sources | #1253 #1255 #1256 #1265 #1270 #1281 | CLEAN ×6 | re-record at the current digests |
| THM-0037 | C | bdb81b3228374d48 | 2fa578b333101d3b → 2dad2bfbf60ed0a7 | `proxy.trust_plan`: source_inputs+test_selection; `proxy.trust_plan_co_provenance`: source_inputs+structural_probes | #1268 | CLEAN ×1 | re-record at the current digests |
| THM-0038 | C | 2f38be9ca9fedba5 | ddac7d8d5bbb8c24 → e276cc8f7dda32ba | `proxy.trust_composition_root`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | #1255 CLEAN-NOTE | owner confirms the note(s), then re-record |
| THM-0040 | F | 4c5d90700148aa8e | 5f148a5707176656 → f198a7b9eeb0bb45 | `proxy.pdp_decision_relation`: test_sources | #1253 #1255 #1256 #1265 #1270 #1281 | CLEAN ×6 | re-record at the current digests |
| THM-0043 | C | 34353106aaab2d04 | 222a2c6551fd50b4 → d4658aed2ebc2df9 | `proxy.exchange_relation`: source_inputs+test_selection | #1253 #1277 | CLEAN ×2 | re-record at the current digests |
| THM-0044 | C | a2c4aa5807f9e176 | 754a1a2f9209e3c4 → caf5d28699a22a20 | `proxy.exchange_retry_consequence`: source_inputs | #1253 #1277 | CLEAN ×2 | re-record at the current digests |
| THM-0045 | C | a3677e05cf813f66 | 23ff18b2e2dcf09b → e493c068f20e4591 | `proxy.dispatch_commitment`: source_inputs+test_sources; `proxy.retention_commitment`: mutation_probes+source_inputs+test_selection+test_sources | #1253 #1255 #1256 #1257 #1265 #1270 #1277 #1281 | #1253 CLEAN-NOTE; #1281 CLEAN-NOTE | owner confirms the note(s), then re-record |
| THM-0048 | C | 36d8b72301e9dacf | ed7535fc1c8a5c0c → c19b37b2a3056ed6 | `proxy.listener_state_assembly`: source_inputs | #1253 #1259 #1270 | CLEAN ×3 | re-record at the current digests |
| THM-0051 | C | cc371a5dbf05380e | 80726ebebf37d581 → 0f82db61810a0135 | `proxy.dispatch_commitment`: source_inputs+test_sources | #1253 #1255 #1256 #1257 #1265 #1270 #1277 #1281 | CLEAN ×8 | re-record at the current digests |
| THM-0052 | C | 597274da4b9339e7 | 94fd53453259dd99 → 9c2840a331cfd9b5 | `proxy.dispatch_commitment`: source_inputs+test_sources; `proxy.pdp_decision_relation`: test_sources | #1253 #1255 #1256 #1257 #1265 #1270 #1277 #1281 | CLEAN ×8 | re-record at the current digests |
| THM-0053 | C | 4b5654d1fceac971 | a50b9eb681efe166 → a83ba63e620248b4 | `http_profile.admission_assertion`: source_inputs | #1269 | CLEAN ×1 | re-record at the current digests |
| THM-0054 | C | ca274e81669473a9 | 3bd18eb91fa7d627 → af4b0fb56968fd9e | `proxy.client_certificate_posture`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0062 | C | e87e43867b5c6882 | 294d6a3642a46662 → 2cb5ebd35118ea3f | `proxy.delegated_signing_credential`: source_inputs+test_sources | #1253 #1255 #1256 #1265 #1270 #1281 | CLEAN ×6 | re-record at the current digests |
| THM-0063 | C | 8871ed21a3b398b6 | f9406908ad82a662 → ef4fd7fc26b57089 | `proxy.delegated_signing_credential`: source_inputs+test_sources; `proxy.response_signing`: test_sources | #1253 #1255 #1256 #1265 #1270 #1281 | CLEAN ×6 | re-record at the current digests |
| THM-0066 | C | 2426e6c26764233a | 2e7f78278949993d → fdb4cec0a50328b4 | `proxy.serving_trust_seam`: source_inputs+test_sources; `proxy.trust_plan`: source_inputs+test_selection | #1253 #1255 #1259 #1262 #1268 #1270 | CLEAN ×6 | re-record at the current digests |
| THM-0067 | C | db84c710a7de60e2 | 52c12f4824493a39 → a40f454323afbbd2 | `proxy.trust_composition_root`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | #1255 CLEAN-NOTE | owner confirms the note(s), then re-record |
| THM-0069 | F | 0ce3b80720627213 | 4913199e575fbe87 → a820706f7704cd94 | `proxy.admission_currency_gate`: test_sources; `proxy.audit_authority_coordinates`: test_sources | #1253 #1255 #1256 #1265 #1270 #1281 | CLEAN ×6 | re-record at the current digests |
| THM-0070 | A | dd38b842fb857af4 → 7660e7caa07f9253 | 496cc0f0d574b137 → 16273d870aabda79 | claim: theorem_claim; `proxy.audit_delivery`: source_inputs+test_selection+test_sources | #1253 #1255 #1256 #1265 #1270 #1281 #1283 | CLEAN ×7 | OWNER: approve or reject the scope correction, then re-record |
| THM-0071 | B | 2b59216016047aec → cc325187ec814c99 | 87b63d9f06bdf4ed → a0e700cbc8ee1764 | claim: theorem_dependencies | — | — | re-record together with THM-0070 (propagation only) |
| THM-0073 | C | 14a931f5c1cfa81f | 7cea3207097fbcc9 → 232c0389d3671aa7 | `proxy.signing_credential_provenance`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0074 | C | d5f490dbe8437827 | be22e2f92765e240 → ece842a08f3ee091 | `proxy.dispatch_commitment`: source_inputs+test_sources; `proxy.exchange_relation`: source_inputs+test_selection | #1265 #1270 #1277 #1281 | CLEAN ×4 | re-record at the current digests |
| THM-0075 | F | 1403c470b204923e | 2401bd584f7b7962 → 3ccb608d6ad01ddd | `proxy.response_signing`: test_sources | #1253 #1255 #1256 #1265 #1270 #1281 | CLEAN ×6 | re-record at the current digests |
| THM-0077 | C | 9412e9593b1981a0 | 27c148db9d09ce9e → d2b75b8555d8e6dd | `proxy.audit_posture`: test_sources; `proxy.connection_bounds`: source_inputs; `proxy.delegated_signing_configuration_state`: test_sources; `proxy.fleet_topology_provenance`: source_inputs; `proxy.in_flight_limit_basis`: source_inputs; `proxy.legality_boundary_totality`: mutation_probes+source_inputs+test_selection+test_sources; `proxy.serving_capability_posture`: source_inputs; `proxy.startup_plan_legality`: mutation_probes+source_inputs; `proxy.startup_plan_pool_ceiling`: source_inputs+test_selection; `proxy.startup_plan_provenance`: mutation_probes+source_inputs+test_selection; `proxy.transport_binding_and_crl_state`: test_sources; `proxy.trust_composition_root`: source_inputs+test_sources; `proxy.unestablishable_capability_refusal`: source_inputs+test_sources | #1253 #1255 #1256 #1259 #1262 #1265 #1268 #1269 #1270 #1281 #1286 | #1253 CLEAN-NOTE; #1286 CLEAN-NOTE | owner confirms the note(s), then re-record |
| THM-0078 | C | cff60d4953093224 | dc3dd379ba0317c7 → dea562a10c73a9e2 | `proxy.exchange_relation`: source_inputs+test_selection | #1253 #1277 | #1277 CLEAN-NOTE | owner confirms the note(s), then re-record |
| THM-0080 | C | e5fd5b87e8c336c5 | 6ef3ec1408ea395d → 3094e83733b4600b | `proxy.serving_identity_provenance`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0081 | C | bf723ba252cf5ed8 | da8d00456260a4fa → dac174804b2caadf | `proxy.refusal_site_totality`: source_inputs+test_selection+test_sources | #1253 #1255 #1256 #1257 #1259 #1262 #1270 #1277 #1281 | CLEAN ×9 | re-record at the current digests |
| THM-0082 | C | 3f5a3cf9b340ccc1 | 0125c0a21a79f283 → 9c346e2453d35a87 | `proxy.signing_credential_provenance`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0083 | C | f51f19ff25e327d0 | 10d9d3d489eabc49 → f69d112ee1a5b222 | `proxy.outstanding_id_provenance`: source_inputs+test_sources | #1253 #1255 #1256 #1257 #1259 #1262 #1270 #1277 | CLEAN ×8 | re-record at the current digests |
| THM-0085 | C | f39497f8ded64f01 | 85717f2ed259befa → 08edeea4bb86f795 | `proxy.refusal_audit_emission`: source_inputs+test_sources | #1253 #1255 #1256 #1257 #1259 #1262 #1270 #1277 | #1253 CLEAN-NOTE | owner confirms the note(s), then re-record |
| THM-0088 | C | 4cd3913879e3417c | 3ec5f3649c60f139 → b1a1c239d9d99c2e | `proxy.retention_commitment`: mutation_probes+source_inputs+test_selection+test_sources | #1253 #1255 #1256 #1257 #1265 #1270 #1277 #1281 | #1253 CLEAN-NOTE | owner confirms the note(s), then re-record |
| THM-0089 | C | e72c8e86f82919aa | 2e8960e252cef4c0 → b2259884b56fe593 | `proxy.kms_endpoint_authority`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | #1262 CLEAN-NOTE | owner confirms the note(s), then re-record |
| THM-0090 | C | ce22a7ec651a2fbd | 6369b9318af63e58 → 6d65e6eb1b983ce1 | `proxy.outbound_destination`: source_inputs | #1262 style: rustfmt the new binding test and the shared serve hel verification: an agent's https is the proxy's connector; the | #1262 CLEAN-NOTE | owner confirms the note(s), then re-record |
| THM-0091 | F | 20f89a291e53e454 | 8bf96811ce936adc → e49828864ff4b2fc | `client.local_request_surface`: test_sources | #1255 | CLEAN ×1 | re-record at the current digests |
| THM-0092 | F | 49569e318ea23f11 | 5460791b69e7f531 → af0fde9e3a9717cc | `proxy.replay_admission_gate`: test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0093 | C | 1f65ea3aeacc3fc8 | 8aaacb1bcda3ead0 → e026d47ac0837c2c | `proxy.continuation_leg_binding`: source_inputs | #1277 | CLEAN ×1 | re-record at the current digests |
| THM-0096 | C | 97fb6e966903e09f | 073a5d379fe81cd0 → 34f4fda4092d548c | `proxy.continuation_installation`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0097 | C | fbb59368a89a8266 | 224c117ea11549dd → 62b2bf26d4322b08 | `proxy.trust_resolution_window`: source_inputs | #1268 | CLEAN ×1 | re-record at the current digests |
| THM-0098 | C | f4c1f2628fa3a8fe | f9b558c652281421 → 36c0225c04fd145d | `proxy.trust_resolution_window`: source_inputs | #1268 | CLEAN ×1 | re-record at the current digests |
| THM-0099 | C | 91c7d9e6c56d998a | 75c7eef094351d03 → d44407b1b739dbfc | `proxy.serving_trust_seam`: source_inputs+test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0100 | C | 5027b6a894e9091e | 69c6c13793f7bf12 → 0a85b9be6367270c | `proxy.trust_posture_declaration`: source_inputs+test_sources; `proxy.trust_reload_cadence`: source_inputs | #1253 #1255 #1259 #1262 #1268 #1270 | CLEAN ×6 | re-record at the current digests |
| THM-0101 | E | 9f9745bcb0bf2af7 | d721b975180df1bb → 6624412127180c88 | `proxy.exchange_publication`: source_inputs+test_selection; `proxy.exchange_transition_ownership`: source_inputs+test_sources; `proxy.publish_permit_sole_producer`: (added or removed) | #1259 #1262 #1265 #1270 #1277 #1281 | #1277 DISCREPANCY | OWNER DECISION: claim text or control, before any re-record |
| THM-0102 | F | 34c89b238de94e4c | dda82bd8079c7a97 → 8a488eacab675e1e | `proxy.client_credential_window`: test_sources | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0104 | C | a5cf8723f0329c9b | 03acccb1d6183610 → 17f3bd8e8d54b3dc | `proxy.serving_drain`: source_inputs+test_sources | #1253 #1270 | CLEAN ×2 | re-record at the current digests |
| THM-0109 | F | 6b80104b3451c66b | 358677587bcc3da5 → e7f5a52f2aee49b4 | `client.transport_server_identity`: test_sources | #1253 | CLEAN ×1 | re-record at the current digests |
| THM-0111 | C | f3f5713603a624cc | 9c551b77f43d569f → a5ac68c60d28f185 | `conformance.verdict_vocabulary_scope`: source_inputs | #1253 #1257 #1259 #1265 #1268 #1269 #1270 #1274 #1286 | CLEAN ×9 | re-record at the current digests |
| THM-0112 | C | 29c9bb8d600e2fa4 | 89f36297a102773c → 0ed4ca5f2b751f9a | `proxy.retained_record_at_the_store`: source_inputs; `proxy.retained_record_content`: source_inputs+test_sources | #1253 #1255 #1256 #1265 #1270 #1281 | CLEAN ×6 | re-record at the current digests |
| THM-0113 | F | 95c28f72283a689e | 0e163d20c56026ca → 4a32337ad83e549b | `proxy.evidence_attestation`: test_sources | #1253 #1255 #1256 #1265 #1270 #1281 | CLEAN ×6 | re-record at the current digests |
| THM-0115 | C | 8a261e0cf571539e | 6e72856060178143 → da308aa4db15ee60 | `proxy.remote_signer_call_aws`: source_inputs; `proxy.remote_signer_call_gcp`: source_inputs | #1262 | CLEAN ×1 | re-record at the current digests |
| THM-0116 | C | 9a2a8e3cca72d6ca | 65a6dd15f69a7344 → ed081600a37f2ffa | `proxy.aws_kms_adapter`: source_inputs; `proxy.gcp_kms_adapter`: source_inputs; `proxy.pkcs11_adapter`: source_inputs+test_sources | #1253 #1262 | CLEAN ×2 | re-record at the current digests |
| THM-0117 | C | 53bdf89381bc4656 | 1e63ee35b383fd9a → d35e3489456d28db | `proxy.aws_sts_credentials`: mutation_probes+source_inputs+test_selection; `proxy.aws_web_identity_credential_exchange`: source_inputs; `proxy.gcp_kms_adapter`: source_inputs; `proxy.gcp_metadata_token_lifetime`: source_inputs | #1262 #1274 | CLEAN ×2 | re-record at the current digests |
| THM-0120 | F | 90fa085e9c2688c8 | 70a42d59d290e171 → a1c3730e371c422f | `client.anchor_refresh`: test_sources | #1255 | CLEAN ×1 | re-record at the current digests |
| THM-0123 | F | 6eea9ad5cec8f7cd | c0bf587643cfcd65 → c597d1409990a53c | `client.local_serving_pipeline`: test_sources | #1255 | CLEAN ×1 | re-record at the current digests |
| THM-0127 | C | 5f6e9adcb2f9d049 | e2515ee7690fac47 → dc6d23ee2020ce26 | `client.serving_lifetime`: source_inputs | #1237 | CLEAN ×1 | re-record at the current digests |
| THM-0129 | F | 8531b9c45bd24aae | e8df3156bf8d70a9 → 123c861e3d929c85 | `proxy.admission_state_source`: test_sources | #1253 #1255 #1256 #1265 #1270 #1281 | CLEAN ×6 | re-record at the current digests |
| THM-0131 | C | 9db314ae680c138e | d9d8b2e468b0dea6 → b2f6b898fdea24b1 | `proxy.client_crl_next_update_gate`: test_sources; `proxy.client_crl_reload_republish`: source_inputs; `proxy.client_revocation_currency`: source_inputs; `proxy.retired_plane_cadence_retraction`: source_inputs | #1253 #1255 #1259 #1262 #1270 | CLEAN ×5 | re-record at the current digests |
| THM-0132 | F | cedf63cdb0ad2b7f | 946ed21dbf8cf815 → 2d9b57915c333a00 | `proxy.admission_currency_gate`: test_sources | #1253 #1255 #1256 #1265 #1270 #1281 | CLEAN ×6 | re-record at the current digests |
| THM-0135 | C | df790c7b287331ca | 432d90fc757de1d2 → b3c9a6dd452b40bb | `proxy.audit_commitment_sole_producer`: source_inputs; `proxy.audit_commitment_witness`: source_inputs; `proxy.audit_intent_gate`: mutation_probes+source_inputs+test_selection+test_sources; `proxy.audit_intent_gate_sole_producer`: source_inputs+structural_probes; `proxy.audit_posture`: test_sources | #1253 #1255 #1256 #1257 #1259 #1262 #1265 #1270 #1277 #1281 | CLEAN ×10 | re-record at the current digests |
| THM-0136 | C | b58fc9fc3c312214 | b089c43c9178e998 → b9b5046fa6f10227 | `proxy.audit_intent_gate_sole_producer`: source_inputs; `proxy.audit_outcome_gate`: mutation_probes+source_inputs+test_sources; `proxy.audit_posture`: test_sources; `proxy.success_exit_order`: source_inputs | #1262 #1270 #1277 #1281 | #1256 CLEAN-NOTE | owner confirms the note(s), then re-record |

### Record provenance per theorem

- delegated agent decision 2026-10-22 (Verus change); not a personal owner signature (record `20872b822`): THM-0001 THM-0003 THM-0004 THM-0005 THM-0006 THM-0007 THM-0009 THM-0010 THM-0014 THM-0016 THM-0017 THM-0021 THM-0022
- agent re-review, ratified by owner ledger line `owner-signature:epic-1201-assurance-closure-2026-10-21` (record `ec1152bbb`): THM-0013 THM-0024 THM-0026 THM-0027 THM-0038 THM-0040 THM-0043 THM-0044 THM-0045 THM-0048 THM-0051 THM-0052 THM-0054 THM-0062 THM-0063 THM-0066 THM-0067 THM-0069 THM-0073 THM-0075 THM-0077 THM-0078 THM-0082 THM-0083 THM-0085 THM-0088 THM-0089 THM-0090 THM-0092 THM-0093 THM-0096 THM-0099 THM-0100 THM-0102 THM-0109 THM-0111 THM-0112 THM-0113 THM-0129 THM-0131 THM-0132 THM-0135
- owner batch ruling 2026-10-14 (MCPRE-218) (record `551ba14be`): THM-0031 THM-0037 THM-0053 THM-0071 THM-0091 THM-0097 THM-0098 THM-0116 THM-0120 THM-0123 THM-0127
- delegated agent decision 2026-10-22 (toolchain modernization); not a personal owner signature (record `d202361ca`): THM-0032 THM-0070 THM-0080 THM-0081 THM-0104
- agent record under owner ruling 2026-10-27; no ledger line (record `f28ec97c3`): THM-0074 THM-0101
- owner-authorized step 7 re-review (Ruling 40) (record `86cd7e91e`): THM-0115 THM-0117
- agent record under owner ruling 2026-10-29; no ledger line (record `ab5f4f4ff`): THM-0136

## Packets by causing PR

### #1253 Architecture review: merge readiness, RequestTarget owner, exchange-bound publish permit; pinned Python 3.14.7 (merge e236f1d46, squash)

What changed (security-relevant mechanism only):
- **`RequestTarget` owner** (`config_state/request_target.rs`, new). `--target-uri` is now a value whose only constructor refuses each of the following: empty, scheme-less, non-http(s) scheme, empty host, non-numeric or out-of-range port, userinfo (redacted in the refusal), fragment, and whitespace/control/non-ASCII characters. Previously `residue.rs::target_uri_violation` refused only empty and scheme-less. The legal set is strictly narrower.
- **`ServerOptions.target: RequestTarget`** replaces `target_uri: String` (`tls.rs:220`). `ServerOptions::new` now requires a target. The old `new` left it empty, which turned the arrival-path check off for any embedder (#1243). `target_uri_mismatch` (`async_serve/mod.rs:255`) lost its `configured.is_empty() → None` arm and `origin_form_of`.
- **Origin-form derivation corrected.** A target whose query precedes any path now projects `/?q`; the old code projected `/` or a path taken from inside the query (`https://h?next=/mcp` gave `/mcp`). This fails closed for a deployment relying on the old projection.
- **Composition root** (`app.rs:243,373`). The audience tuple and the serving options take the target from `config.state().request_target()`, not `values.target_uri`. `target_uri` leaves the raw-read ORDINARY list (`composition_raw_read_test.rs:69`), which makes that gate stricter.
- **`PublishPermit`** (`exchange_state/publication.rs`, new). `may_publish` takes the success by value and returns a permit only `exchange_state` can mint. The permit holds `&mut` of the exchange that cleared it, and `PublishPermit::publish` is the only path to a success terminal; `ExchangeProgress::publish` is deleted. `publish_success` and `answer_notification` now take the permit, so "decide, then publish" is a type fact.
- **`DispatchedExchange::split` → (`DispatchedOutcome`, `PostDispatch`).** PostDispatch carries window, retention and intent. `into_publication` releases retention and intent together only to the success exit. A pure regrouping: the same values reach the same consumers.
- **`retain_accepted`'s failure path** now calls `refuse_accepted` instead of an inline `response_rejection`. I checked `receipt/mod.rs:143`: same coordinate, cause, status, evidence, actor, disposition and key snapshot.
- **`classify_refusable`** (`validation/refusable_machines.rs`) is rewritten through a local macro. The struct literals still require every field, so no machine can be dropped silently. This file is no unit's input; see the note below the table.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0013 | none: `residue.rs` loses the target clause; online-OCSP refusal untouched | CLEAN | |
| THM-0024 | none: shared integration test files, mechanical `ServerOptions::new(.., target)` | CLEAN | |
| THM-0026 | none: `tls.rs` field and constructor arity only | CLEAN | |
| THM-0027 | none: as THM-0026 | CLEAN | |
| THM-0031 | none: as THM-0026 | CLEAN | |
| THM-0032 | none: currency policy unchanged; tests pass a target | CLEAN | |
| THM-0038 | composition root reads the target from its owner | CLEAN | Stricter: `target_uri` is no longer an ORDINARY raw read |
| THM-0040 | none: async test harness pass a target | CLEAN | |
| THM-0043 | success-tail advancer moved to `publication.rs` | CLEAN | `publication.rs` is outside `proxy.exchange_relation`'s paths. It drives only `advance` (in `exchange_state.rs`), so the relation and its latch are unchanged |
| THM-0044 | refused publication drops the success by value | CLEAN | `a_refused_publication_reports_the_exchange_as_possibly_executed` kept |
| THM-0045 | `DispatchedExchange` returns `PostDispatch` | CLEAN-NOTE | Consumption of `ReadyForDispatch` is unchanged. Co-supporter `proxy.retention_commitment` lost probe M92 and the source-order test `accepted::…the_publication_decision_precedes_retention…`. Their conjunct is now enforced by the permit type, witnessed by S76–S79 under `proxy.exchange_publication` (THM-0101), which does not support THM-0045 |
| THM-0048 | none: `ServerOptions` shape | CLEAN | |
| THM-0051 | none: `request_stages.rs` regrouping | CLEAN | |
| THM-0052 | none: as THM-0051 | CLEAN | |
| THM-0054 | none: revocation path untouched | CLEAN | |
| THM-0062 | none: test harness | CLEAN | |
| THM-0063 | none: test harness | CLEAN | |
| THM-0066 | audience target now from owner, same bytes (`uri.to_owned()`) | CLEAN | |
| THM-0067 | as THM-0038 | CLEAN | |
| THM-0069 | none: test harness | CLEAN | |
| THM-0070 | none: test harness | CLEAN | Its claim change is #1283's, not this PR's |
| THM-0073 | as THM-0066 | CLEAN | |
| THM-0075 | none: test harness | CLEAN | |
| THM-0077 | new legality machine `request_target`, spliced where the residue clause was | CLEAN-NOTE | The legal set narrowed: a deployment whose `--target-uri` has userinfo, a fragment, a non-http(s) scheme, a bad port or non-ASCII characters now refuses at startup. That is an operator-visible change, in the refusal direction; M311 re-anchored on the owner. See the out-of-closure note |
| THM-0078 | as THM-0043 | CLEAN | |
| THM-0080 | `async_serve/**`: target type; peer-identity derivation untouched | CLEAN | |
| THM-0081 | `retain_accepted` failure routes through `refuse_accepted` | CLEAN | Same refusal, so it stays inside the lifecycle |
| THM-0082 | as THM-0066 | CLEAN | |
| THM-0083 | `http_profile_serve/mod.rs`: `split()` only | CLEAN | |
| THM-0085 | emitter route count pinned 5 → 4 | CLEAN-NOTE | Lower pin because the accepted-reply route now reaches the funnel via `refuse_accepted`. I checked the emission is argument-identical (`receipt/mod.rs:143`); no route was lost |
| THM-0088 | `proxy.retention_commitment` mutation set: M92 retired | CLEAN-NOTE | The two-stage store mechanism is untouched. M92's conjunct (success decided before retention) is not in THM-0088's statement, and it is now a type fact owned by THM-0101 |
| THM-0089 | none: shared integration tests | CLEAN | |
| THM-0092 | none: shared integration tests | CLEAN | |
| THM-0096 | as THM-0066 | CLEAN | |
| THM-0099 | as THM-0066 | CLEAN | |
| THM-0100 | none: shared integration tests | CLEAN | |
| THM-0102 | none: shared integration tests | CLEAN | |
| THM-0104 | `async_serve/**` target type; drain untouched | CLEAN | `async_drain_test.rs` change is mechanical |
| THM-0109 | none: `mcp-re-transport/tests/mtls_client_test.rs` spawn helper | CLEAN | |
| THM-0111 | none: `rust-targets.json` lists two new files, neither holds a verdict token | CLEAN | |
| THM-0112 | none: test harness | CLEAN | |
| THM-0113 | none: test harness | CLEAN | |
| THM-0116 | none: `pkcs11_keysource_e2e_test.rs` spawn helper | CLEAN | |
| THM-0129 | none: test harness | CLEAN | |
| THM-0131 | none: shared integration tests | CLEAN | |
| THM-0132 | none: test harness | CLEAN | |
| THM-0135 | intent travels in `PostDispatch`, released only to the success exit | CLEAN | Refusal paths drop it as before |

**Out-of-closure note (pre-existing gap, exposed by this PR).** `mcp-re-proxy/src/config_state/validation/refusable_machines.rs` is the pass-1 classifier that produces every legality machine's state and refusals. It is listed in no unit's `paths` in `verification/policy/verification.toml`; it has existed since 0d7ac5889 (2026-08-29). #1253 rewrote it without moving any review digest. The struct literals make a dropped machine a compile error, so the rewrite is safe. The gap is that THM-0077's evidence closure omits a file that decides it. Disposition: add it to `proxy.legality_boundary_totality`'s paths. That is a mechanical registry correction, but it moves that unit's fingerprint.

**Arrival-path check.** The origin-form correction changes a serving refusal. Its deciding code (`async_serve/mod.rs::target_uri_mismatch`, `request_target.rs::origin_form`) is covered by THM-0080's glob and THM-0077's unit, but no stale theorem's statement names the check. THM-0015, which names `@target-uri`, is not stale.

Tests removed or weakened:
- `async_serve::target_uri_tests::an_empty_configured_target_is_not_checked_here`: removed, because the state is no longer constructible.
- `residue::tests::a_target_uri_that_would_disable_the_reconstruction_check_is_refused`: moved and widened into `request_target::tests` (same cases plus 16 new refusals).
- `accepted::tests::the_publication_decision_precedes_retention_and_the_response_signed_record` and `notification::tests::the_terminal_is_decided_before_the_202_is_minted` (`include_str!` order probes): removed, with mutation probes M92/M93 retired. Replaced by the permit type, the compile-fail probes S76–S79 and `exchange_state::publication::tests` (3).
- `EMITTER_ROUTES` 5 → 4: re-routing, not a weakening.
- No assertion weakened otherwise.

### #1270 refactor(proxy): serving receives ServedLimits, not the request's limits bag (#1250) (merge 9b8a22664)

What changed:
- `ServerLimits` moved from `tls.rs` to `deployment_request/server_limits.rs`, with the same fields and the same `Default` values. It is now the REQUEST only.
- New `ServedLimits { max_header_bytes, max_body_bytes, max_in_flight_requests }`. It is the only limits value `ServerOptions.limits` carries (`tls.rs`). `ServerLimits::served(basis, shards)` produces it, and `app.rs:365` calls `values.limits.served(in_flight_limit, topology.shards())`.
- The per-core in-flight ceiling is unchanged in mechanism. `async_fleet/mod.rs:320-324` still writes the basis's per-core ceiling into each shard's options. `ServedLimits::default()` still carries `DEFAULT_PER_CORE_IN_FLIGHT` (256); the test `the_default_served_limits_are_the_unstated_requests` asserts this.
- The blocking mTLS harness (`blocking_mtls_harness/connection.rs`, `deadline_stream.rs`, `http1.rs`) now reads its read and write timeouts and its request deadline from the owner's `ConnectionBounds`, which are resolved and always `Some`, instead of from raw `Option`s. `read_http_request` takes the two size caps as arguments, and the body-cap and header-cap checks are textually unchanged. This is tighter, not looser: a harness connection can no longer run with a timeout disabled.
- `connection_bounds`, `in_flight_limit` and `client_revocation` changed only in import paths and doc comments.
- Tests:
  - `config_snapshot_hot_reload_test.rs` and `per_request_revocation_test.rs` dropped the line `limits: ServerLimits::default()`, which now equals the `ServerOptions::new` default.
  - In `composition_raw_read_test.rs`, the `ORDINARY` table's justification text for `limits` was rewritten. The table entry itself is kept, so the raw-read gate still covers it.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0013 | none: raw-read table prose only | CLEAN | |
| THM-0024 | none: raw-read table prose only | CLEAN | |
| THM-0026 | none: `tls.rs` ServerLimits relocation | CLEAN | |
| THM-0027 | none: `tls.rs` relocation; table prose | CLEAN | |
| THM-0031 | none: `tls.rs` relocation | CLEAN | |
| THM-0032 | per-request currency: `connection.rs` test import, `client_revocation.rs` doc link | CLEAN | max_connection_age is still read from ClientCredentialWindow |
| THM-0038 | composition root takes owner projections: `app.rs` now calls `served()` | CLEAN | strengthens: serving no longer receives the resolved-elsewhere bounds |
| THM-0040 | none: removed redundant default in tests | CLEAN | |
| THM-0045 | none: same test edit | CLEAN | |
| THM-0048 | listener posture: `tls.rs` relocation | CLEAN | |
| THM-0051 | none: same test edit | CLEAN | |
| THM-0052 | none: same test edit | CLEAN | |
| THM-0054 | none: `tls.rs` relocation; table prose | CLEAN | |
| THM-0062 | none: same test edit | CLEAN | |
| THM-0063 | none: same test edit | CLEAN | |
| THM-0066 | `app.rs` limits projection | CLEAN | |
| THM-0067 | composition root re-reads no owner semantics | CLEAN | the change removes a raw-bag pass-through |
| THM-0069 | none: same test edit | CLEAN | |
| THM-0070 | none: same test edit | CLEAN | stale for its own reasons (claim change, #1283) |
| THM-0073 | `app.rs` limits projection | CLEAN | |
| THM-0074 | none: same test edit | CLEAN | |
| THM-0075 | none: same test edit | CLEAN | |
| THM-0077 | serves only a selected posture: limits defaults and resolution | CLEAN | defaults are byte-identical; the per-core ceiling comes from the selected basis |
| THM-0080 | peer identity from credential: blocking harness now reads owner-resolved timeouts | CLEAN | identity derivation is untouched |
| THM-0081 | refusals inside the lifecycle: `async_serve/mod.rs` doc comment only | CLEAN | |
| THM-0082 | `app.rs` limits projection | CLEAN | |
| THM-0083 | none: table prose | CLEAN | |
| THM-0085 | none: table prose | CLEAN | |
| THM-0088 | none: same test edit | CLEAN | |
| THM-0089 | none: table prose | CLEAN | |
| THM-0092 | none: table prose | CLEAN | |
| THM-0096 | `app.rs` limits projection | CLEAN | |
| THM-0099 | `app.rs` limits projection | CLEAN | |
| THM-0100 | none: table prose | CLEAN | |
| THM-0101 | none: table prose and test edit | CLEAN | |
| THM-0102 | connection-age bound: table prose | CLEAN | max_connection_age is still owned by ClientCredentialWindow |
| THM-0104 | shutdown bounds: `async_serve/connection.rs`, `mod.rs` import and doc only | CLEAN | drain_grace is still read from ConnectionBounds |
| THM-0111 | none: `verification/generated/rust-targets.json` regenerated | CLEAN | stale only because the generated target table is a digested input |
| THM-0112 | none: same test edit | CLEAN | |
| THM-0113 | none: same test edit | CLEAN | |
| THM-0129 | none: same test edit | CLEAN | |
| THM-0131 | none: table prose | CLEAN | |
| THM-0132 | none: same test edit | CLEAN | |
| THM-0135 | none: table prose and test edit | CLEAN | |
| THM-0136 | none: table prose and test edit | CLEAN | |

Tests removed or weakened: none.
- In `http_limits.rs`, `deadline_stream.rs` and `http1.rs`, the tests were re-expressed against the new arguments with the same assertions.
- New test: `server_limits.rs` (2 tests).

### #1269 refactor(proxy): the admission enforcer and record verifier take one skew decision (#1250) (merge 8487b95d1)

What changed:
- `mcp-re-http-profile/src/admission_policy.rs`: one DOC-COMMENT word, `enforcer_policy` changed to `budgets`. This file is in the http-profile crate, and every formal unit digests that whole crate, so the comment staled 14 theorems.
- `EnforcedAdmission` moved to `config_state/admission/enforced_admission.rs`.
- New `AdmissionBudgets { enforcer, record_verifier }`: its fields are private to that module, and `EnforcedAdmission::budgets(max_clock_skew)` is its only producer. Both budgets come from ONE skew value.
- `enforcer_policy` is byte-identical to the old method (same FailClosed→(false,0) and BoundedDegraded→(true,P) projection), now private.
- `record_verifier` is `{max_record_age: gate.currentness.max_age_secs(), max_clock_skew: skew}`, which is identical to the struct literal previously built inline in `serving_capabilities.rs`.
- `serving_capabilities.rs::admission_currency` builds the verifier and the enforcer from `budgets`. The authority resolver, kid, key, profile tag and store URL are unchanged.
- Tests went from 14 to 15. The two projection tests moved to `enforced_admission::tests`, and `both_budgets_carry_the_one_skew_they_were_taken_under` was added. The tested_symbols in `verification.toml` follow the move.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0001 | none: doc comment in admission_policy.rs | CLEAN | |
| THM-0003 | none: doc comment | CLEAN | |
| THM-0004 | none: doc comment | CLEAN | |
| THM-0005 | none: doc comment | CLEAN | the degraded opt-in projection is unchanged |
| THM-0006 | none: doc comment | CLEAN | |
| THM-0007 | none: doc comment | CLEAN | |
| THM-0009 | none: doc comment | CLEAN | |
| THM-0010 | none: doc comment | CLEAN | |
| THM-0014 | none: doc comment | CLEAN | |
| THM-0016 | none: doc comment | CLEAN | |
| THM-0017 | none: doc comment | CLEAN | |
| THM-0021 | none: doc comment | CLEAN | |
| THM-0022 | none: doc comment | CLEAN | |
| THM-0053 | none: doc comment | CLEAN | |
| THM-0077 | admission posture served is the selected one: `serving_capabilities.rs` | CLEAN | same values; the skew pairing is now type-owned |
| THM-0111 | none: rust-targets.json regenerated | CLEAN | |

Tests removed or weakened: none (moved 2, added 1).

CLEAN-NOTE (method): 14 V1 theorems re-staled on a one-word doc-comment edit. The formal units' `source_inputs` digest the whole http-profile crate, which over-approximates in the safe direction. The owner can confirm all 14 by reading one line.

### #1268 refactor(proxy): the response authority is sealed; both plans take it whole (#1251) (merge e3802ebe2)

What changed:
- New `startup_plan/response_authority.rs`: `ResponseAuthority { kid, epoch }`. Its fields are private, and its private `from_validated` reads the kid from `delegated_signing().issuer_kid()` and the epoch from `TrustEpochPlan::from_validated`, exactly the two reads the old `response_authority_plans` made.
- `response_authority_plans` is now in that module. It is the only producer and hands one authority to both plans (`authority.clone()` to the trust plan, the original to the signing plan).
- `TrustPlan::from_validated(config, authority)` and `SigningPlan::from_validated(config, authority)` take the authority whole. A caller can no longer pass a kid and an epoch separately. `response_kid()` and `epoch()` return the authority's values.
- Tests: the CF-09 controls were moved into the owner module, not removed:
  - `the_issuer_kid_in_the_credential_is_the_one_that_was_planned` moved from `startup_plan/mod.rs`;
  - `the_shared_values_are_inputs_the_trust_plan_cannot_re_derive` became `the_trust_plan_carries_the_authority_it_is_handed`;
  - new: `the_authority_reads_what_layer_a_decided`.
- The `trust_plan.rs` and `trust_plane/mod.rs` tests now build plans through the producer. One assertion changed from the literal `"root-1"` to the configuration's issuer kid, which is the same proposition stated against the real producer.
- Structural probe S84 (E0451) witnesses the seal.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0037 | trust-plan reload cadence projection: `trust_plan.rs` | CLEAN | cadence fields untouched |
| THM-0066 | PEP actor resolution through materialized trust: `trust_plan.rs`, `response_authority.rs` | CLEAN | |
| THM-0077 | posture is the selected one: `startup_plan/mod.rs`, `response_authority.rs` | CLEAN | same two reads, now sealed |
| THM-0097 | request-signer binding within snapshot authority: `trust_plane/mod.rs` test fixture | CLEAN | the response kid is still excluded from signer enrolment |
| THM-0098 | snapshot is the slot-wise interpretation: `trust_plane/mod.rs` test fixture | CLEAN | |
| THM-0100 | key exposure confined: `trust_plane/mod.rs` test fixture | CLEAN | |
| THM-0111 | none: rust-targets.json | CLEAN | |

Tests removed or weakened: none (2 moved and renamed, 1 added; one literal assertion re-anchored to the producer's value).

### #1286 fix(proxy): pin each serving shard inside the CPUs the process may run on (#1196) (merge 6566fc296)

What changed:
- New `async_fleet/cpu_placement.rs`. `CpuPlacement::of_this_process()` reads the `sched_getaffinity` mask ONCE before the shards spawn, and shard `i` is pinned to the `i`-th allowed CPU, wrapping. Before this change it pinned to `i % online_cpus` and could land outside the operator's mask.
- An unreadable mask, or any non-Linux platform, pins nothing. Each CPU number is checked to be below `CPU_SETSIZE` before `CPU_SET`.
- Pinning stays best-effort, and failures are ignored. No serving, admission or limits path changes.
- `async_fleet/mod.rs` loses the old `pin_current_thread_to_core` and `online_cpu_count`.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0077 | none: CPU affinity is a performance hint, not a posture | CLEAN-NOTE | adds two `unsafe` blocks (`sched_getaffinity`, `sched_setaffinity`). Each has its SAFETY comment and a bounded index check (`cpu < CPU_SETSIZE`). The owner may want to see that new unsafe surface. |
| THM-0111 | none: rust-targets.json | CLEAN | |

Tests removed or weakened: none (new placement tests added in `cpu_placement.rs`).

### #1237 feat(dist): installable releases: archives, GHCR image, Homebrew tap, compose reference (merge d11d601de)

What changed:
- `mcp-re-client/src/startup.rs::parse_invocation` gains `--version` / `-V`. It prints `mcp-re-client <CARGO_PKG_VERSION>` and returns `Err(ExitCode::SUCCESS)` before any listener, route or refresher exists, the same shape as the existing `--help` arm.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0127 | serving path always runs an anchor refresher | CLEAN | the new arm exits before serving; no serving path is reachable without the refresher |

Tests removed or weakened: none.

### #1255 composition: the raw-read gate measures every config() reader; into_inner is gone (merge a29601904)

What changed:
- `ValidatedDeployment::into_inner` (public, test-only callers) deleted (`config_state/validation/mod.rs:75`). Production now has no way to unwrap a validated deployment back to a mutable request; tests clone through `config()`.
- 13 test call sites (`delegated_wiring.rs` tests, 9 proxy integration tests, `mcp-re-client/tests/local_leg_e2e_test.rs`): `.into_inner()` → `.config().clone()`. Mechanical; each test still mutates its own copy and re-validates, so every "programmatic config cannot X" control still drives the boundary it drove.
- `composition_raw_read_test.rs`: the scan now covers every production `src/` file that calls `config()` (was `app.rs` + `app/`), follows the binding's actual name, catches reads off the call itself (`c.config().limits`), joins rustfmt-split reads, strips comments. Five new self-controls. The `ORDINARY` inventory is unchanged (only the `limits` rationale text grew to name the handshake-signing capacity).
- No production decision logic changed.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0038 | raw-read inventory of the composition root (the theorem's own measurement) | CLEAN-NOTE | Measurement widened and strengthened. One under-detection edge in the new comment stripper: `joined()` cuts a line at any `//` preceded by whitespace, including inside a string literal (`"a //b"`), so a raw read later on that same line would be missed (`composition_raw_read_test.rs`, `joined`). No such line exists today; the inventory is unchanged. |
| THM-0067 | same raw-read gate | CLEAN-NOTE | Same note as THM-0038. |
| THM-0077 | parse-then-mutate controls in `app_startup_characterization_test.rs`, `delegated_wiring.rs` tests, raw-read gate | CLEAN | Every posture-bypass control still mutates a parsed config and asserts the validation boundary refuses it. |
| THM-0135 | intent-before-dispatch fixtures (test construction only) | CLEAN | |
| THM-0013 THM-0024 THM-0027 THM-0032 THM-0040 THM-0045 THM-0051 THM-0052 THM-0054 THM-0062 THM-0063 THM-0066 THM-0069 THM-0070 THM-0073 THM-0075 THM-0080 THM-0081 THM-0082 THM-0083 THM-0085 THM-0088 THM-0089 THM-0092 THM-0096 THM-0099 THM-0100 THM-0102 THM-0112 THM-0113 THM-0129 THM-0131 THM-0132 | fixture construction in shared integration test sources (`.into_inner()` → `.config().clone()`); stale because those files are in their units' `test_sources` | CLEAN | No assertion touched. |
| THM-0091 THM-0120 THM-0123 | `mcp-re-client/tests/local_leg_e2e_test.rs` fixture construction | CLEAN | |

Tests: removed/weakened: none. (Five raw-read self-controls added.)

### #1262 build(deps): bump ureq from 2.12.1 to 3.5.0 (merge 391d26a41)

What changed:
- `outbound_fetch/binding.rs:43` `VettedDestination::agent`: ureq 3 config — `max_redirects(0)`, `http_status_as_error(false)`, `proxy(None)` (ureq 3 would otherwise read proxy env), `timeout_global(timeout)`; connector = `DefaultConnector.chain(RootedConnector::public())`; resolver = `VettingResolver` for certificate-derived, `DefaultResolver` for operator-configured (unchanged split).
- New `Failure` / `Fetch` / `FetchWith` / `RequestBound` (`binding.rs`): 4xx/5xx become `Failure::Status` with the response kept for a capped read; 3xx is a body (no redirect is followed) — same partition ureq 2 gave.
- `public_roots.rs`: `RootedConnector` is now a ureq 3 `Connector` stage. It wraps an `https` transport that is not already TLS; **an already-TLS transport passes through unchanged** (`if !details.needs_tls() || transport.is_tls()`). Handshake, root set, server-name handling unchanged.
- `resolver.rs`: `VettingResolver` implements ureq 3 `Resolver`: resolves and vets every address (mixed answers still refused), then copies into `ResolvedSocketAddrs` up to its capacity.
- KMS/STS/GCP/OCSP transports: `.set`→`.header`, `.timeout(NETWORK_TIMEOUT)`→`.bounded_by(NETWORK_TIMEOUT)`, `send_*`→`fetch_with`, `Error::Status`→`Failure::Status`. All body caps (`read_capped`, `take(256 KiB)`, `take(64 KiB)`, `MAX_ERROR_BODY_BYTES`) unchanged.
- `kms_endpoint_policy/mod.rs`: refusal rule unchanged (userinfo, encodings, separators). Client-agreement test now parses with `http::Uri`; adds 8 explicit userinfo → `evil.example.com` cases; for numeric hosts (`127.1`, `2130706433`) the "client reads it differently" check accepts a new disjunct, `connects_elsewhere` (std resolver canonicalises), because `http::Uri` no longer normalises them.
- `remote_signer_bound_test.rs`: rule now counts `.bounded_by(NETWORK_TIMEOUT)` and additionally forbids raw `.timeout_global(`/`.timeout_per_call(`/`.timeout(` in transports. M170/M171 anchors follow.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0090 | where a credential-bearing request can connect and who authenticates the server | CLEAN-NOTE | Holds as built: no redirects, no env proxy, vetted resolver, rustls over webpki-roots. Two things for the owner: (1) the TLS stage now **passes through any transport already TLS**, so if a ureq TLS feature ever entered the build graph (feature unification), ureq's own TLS would run first and `RootedConnector` would be bypassed silently; ureq 2's `tls_connector(..)` replaced instead. ASM-0092 now carries that. (2) The `public_roots` tests drive `handshake()` directly; no test drives `agent()` to an https server under a private CA, so the chain wiring itself (that https actually goes through `RootedConnector`) is unmeasured. Suggest a control on both: an agent-level private-CA refusal test and a gate that `ureq` resolves with no TLS feature. |
| THM-0089 | KMS/STS endpoint reaches the authority its text names | CLEAN-NOTE | Rule and refusals unchanged; userinfo coverage strengthened. The numeric-host agreement check now rests on the std resolver's canonicalisation (`connects_elsewhere`) instead of the URL parser's; the refusal assertion beside it is unchanged, so the property holds. |
| THM-0115 | quota window armed by a typed wire fact (`wire_limits.rs` `read_error_body`) | CLEAN | Same 8 KiB capped read; response type only. |
| THM-0116 | non-exporting signer's key established at construction (AWS/GCP KMS transports) | CLEAN | Transport API only; status/transport partition and caps unchanged. |
| THM-0117 | credential never used past its stated lifetime (`aws_sts.rs`, GCP token fetch) | CLEAN | Lifetime parsing/clamping untouched; only the request plumbing moved. |
| THM-0013 THM-0024 THM-0027 THM-0038 THM-0054 THM-0066 THM-0067 THM-0073 THM-0077 THM-0080 THM-0081 THM-0082 THM-0083 THM-0085 THM-0092 THM-0096 THM-0099 THM-0100 THM-0101 THM-0102 THM-0131 THM-0135 THM-0136 | only `remote_signer_bound_test.rs`, a shared integration-test source of their units | CLEAN | Stale by test-binary co-location, not by meaning. The file's rule got stricter. |

Tests: removed/weakened: none in substance. M170's weakening (drop `.bounded_by`) now leaves a request bounded by the agent's own `timeout_global`, so the mutant is "second-bound-less", not "unbounded"; the source rule still turns it red. The numeric-host client-agreement check gained an alternative disjunct (above).

### #1259 refactor(proxy): the channel-establishment plan is sealed; from_validated is its only producer (merge 6c045ef7d)

What changed:
- `ChannelEstablishmentPlan` moved to `startup_plan/channel_establishment_plan.rs`; its three fields (revocation plan, credential window, handshake capacity) are now private; `from_validated` is the sole producer, body identical to before.
- Consumers read projections: `crl_paths()`, `crl_reload_cadence_secs()`, `currency_bound()`, `credential_window()`, `handshake_capacity()`. `fleet_crl_bound` calls `plan.currency_bound()`, the same `credential_currency_bound(posture, window)` it called before, now over the plan's own pair.
- Test fixtures go through `channel_plan(..)` (cfg(test)), which validates a legal config; illegal combinations fail the fixture instead of reaching the code.
- New V0 structural unit `proxy.channel_establishment_plan_sole_producer` with probes S82 (struct literal) and S83 (field write).
- `startup_plan.rs` → `startup_plan/mod.rs`; probes/paths follow. One test assertion changed from `!client_revocation.is_enforced()` to `crl_paths().is_empty()`; equivalent (`is_enforced` is `!paths.is_empty()`, `crl_revocation.rs:49`).

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0054 | every listener denies unknown revocation status: CRL paths reach `TlsPlane` | CLEAN | Same paths, now via projection. |
| THM-0131 | revocation posture lines state what is enforced | CLEAN | Same window values printed; fixtures now validated. |
| THM-0077 | no deployment serves an unselected posture | CLEAN | Strengthened: a plan cannot be assembled outside validation. |
| THM-0048 | one listener state carries the whole posture | CLEAN | |
| THM-0102 | connection-age bound ≤ credential lifetime | CLEAN | Fixture can no longer name an age > lifetime. |
| THM-0013 THM-0024 THM-0027 THM-0038 THM-0066 THM-0067 THM-0073 THM-0080 THM-0081 THM-0082 THM-0083 THM-0085 THM-0089 THM-0092 THM-0096 THM-0099 THM-0100 THM-0101 THM-0111 THM-0135 | `composition_raw_read_test.rs` (scan now names `startup_plan/mod.rs` and the new file) or `rust-targets.json` | CLEAN | Path rename in a shared test source / generated target table. |

Tests: removed/weakened: none (one assertion restated equivalently; two plan tests and two structural probes added).

### #1274 refactor(proxy): the STS wire codec is its own module (EX-016) (merge 5e62cf846)

What changed:
- `read_capped`, `form_encode`, `parse_assume_role_response`, `element_text`, `decode_xml_entities`, `MAX_SESSION_LIFETIME` moved byte-for-byte into `aws_sts/sts_protocol.rs`; the three callers are `pub(super)`.
- `parse_assume_role_response` now takes `now` explicitly (the old `_at` variant became the only one); production passes `SystemTime::now()` (`aws_sts.rs`). The 12-hour clamp and the UNIX_EPOCH-for-unreadable rule are unchanged.
- 12 tests moved with the code (30 → 18 + 12); M265 and `tested_symbols` re-pathed.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0117 | STS credential lifetime: clamp to 12 h, unreadable ⇒ expired | CLEAN | Code identical, tests all carried over. |
| THM-0111 | verdict-token producers (`rust-targets.json` only) | CLEAN | Generated target table. |

Tests: removed/weakened: none.

### #1281: the signing window must survive the outcome commitment's wait (merge 6155d91ae)

What changed:
- `IntentCommitment::wait` became `waits`, which returns `bound + bound` (saturating): G1 before dispatch plus G2 after signing (`audit_commitment/intent.rs:63`).
  - G2 commits under the same `self.bound`, through `OwedOutcome`.
- `AuditPosture::pre_dispatch_wait` became `commitment_waits` (`posture.rs`). It is zero under best-effort.
- `dispatch_commitment.rs` asks `signing_window::covers(window, completion.after(commitment_waits()))`.
  - This tightens the check: more windows are refused, and still before reserve or intent, where refusing is free.
- Retention completion is still not inside the window check (ADR-070 §14 item 11, O5). The comment says so.
- `completion_bound.rs`: doc text only.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0045 | dispatch consumes the assembled `ReadyForDispatch` | CLEAN-NOTE | The window admission is stricter. No theorem in this set states "the window survives the commitment waits" as a claim, so the strengthened property is unclaimed. O5 (retention completion unbounded) is unchanged. |
| THM-0051, THM-0052, THM-0074 | dispatch-carrier provenance / policy release / no unearned dispatch | CLEAN | Only the bound fed to an existing refusal changed. Order and carrier are untouched. |
| THM-0135 | G1 before dispatch | CLEAN | `waits` is a read of the bound and does not change G1 placement. |
| THM-0136 | G2 before success | CLEAN | The window now also accounts for G2's wait. The claim's order is unaffected. |
| THM-0081, THM-0101 | refusal site / transition ownership | CLEAN | The refusal call site is unchanged. |
| THM-0032, 0040, 0062, 0063, 0069, 0070, 0075, 0077, 0088, 0112, 0113, 0129, 0132 | shared test `intent_before_dispatch_test.rs` only | CLEAN | Test rewording plus a stronger case (see Tests). |

Tests removed or weakened: none.
- `the_window_must_survive_the_commitment_waits` now refuses bounds of 30 s and 15 s, where it previously refused only 30 s. It serves at 5 s, where the old test served at 10 s.
- The posture unit tests assert 2×bound.

### #1265: evidence retention keeps the stage protocol; other authorities move to their owners (merge 8ad919901)

What changed:
- `transparency/durability.rs` (−444 net) was split three ways:
  - `marker_stage.rs`: the closed `MarkerStage {Reserved, Committed}`, which owns the names `reserved` and `pending` and their read-back. It replaces the `RESERVED_EXTENSION` / `PENDING_EXTENSION` consts and `marker_digest`.
  - `retention_queue.rs`: queue admission, and a dead writer distinguished from a full queue.
  - `writer_thread.rs`: the writer thread and its bounded reclamation.
- `pending_reservations` and `stale_reservations` moved from `EvidenceRetention` to the read-only `RetainedArchive` (`retained_archive.rs:113,126`). The reconciliation read now needs no write authority.
- `EvidenceRetention::retain`, which has no execution boundary, is now `#[cfg(test)]`. This narrows the surface. `EvidenceRetention::archive()` was removed.
- `RetainedHopRecord::of` is now `#[cfg(test)]`.
- Mutation probe for dead writer vs backpressure: re-anchored to `retention_queue.rs`. It gained one expect_red (`a_retired_writer_is_a_retired_store_and_not_backpressure`) and lost none.
- `verification.toml` adds the three new paths to the unit and seven new tested_symbols.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0088 | `.reserved` / `.pending` two-stage names; only `commit_to_dispatch` advances | CLEAN | The two names are now one closed enum with a single owner, and `the_two_stages_never_read_each_others_markers` pins that they are disjoint. Write and enumerate both go through `MarkerStage`. |
| THM-0045 | retention_commitment unit | CLEAN | `DispatchCommitted` and `ReservedBeforeDispatch` lost only their const definitions. |
| THM-0112 | retained hop content | CLEAN | `of` is test-only; production builds through `over`. |
| THM-0111 | generated `rust-targets.json` | CLEAN | The new modules are registered; no verdict-token literal was added. |
| THM-0032, 0040, 0051, 0052, 0062, 0063, 0069, 0070, 0074, 0075, 0077, 0101, 0113, 0129, 0132, 0135 | shared integration tests only | CLEAN | The tests now read through `RetainedArchive::open_read_only` instead of the retention handle. Every assertion is identical. |

Tests removed or weakened: none.
- `durability::tests::an_enumerated_marker_is_a_well_formed_token` moved to `retained_archive::tests`, with the same `.pending` and `not-a-digest.pending` cases. It is registered in `control-dispositions.toml:12500`.

### #1256: the dispatched exchange's exits and the success exit's order are types (#1245) (merge 40a314219)

What changed:
- `reply_assembly/dispatched.rs`:
  - `Answering::of` is the only producer of `DispatchedNotification` and `DispatchedCall`, whose fields are private.
  - `assemble_reply` now takes `DispatchedCall` only, so a notification cannot reach the assembler by type. Before this, that was an early `return` checked by a source scan.
- `success_exit.rs`:
  - The steps are `commit_outcome` → `Committed` → `complete_retention` → `Retained` → `serve_published`. The products are private, so G2 → retention → offer/publish/serve is an ordering enforced by types.
  - `retain_accepted` was deleted from `accepted.rs` and its body moved into `complete_retention`. The indeterminate case is the same 500 `EvidenceRetentionIndeterminate`.
- `request_stages.rs`: adds a `#[cfg(test)]` `test_support::dispatched_exchange` only.
- Mutation probes M616 and the G2-before-retention probe were re-adjudicated: the old weakenings no longer compile.
  - M616 now weakens `is_accounted_for() || true`.
  - The second probe now weakens a G2 refusal served without retention.
  - The removed source-scan test was dropped from expect_red.
- Structural probes S80 and S81 were added. They were registered on units with no structural evidence until #1264 created `proxy.dispatched_exit_split` and `proxy.success_exit_order`.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0136 | outcome committed and retention completed before success is visible | CLEAN-NOTE | The order evidence moved: it was a source-order test plus a swap mutation, and is now type order plus S81 plus re-adjudicated mutations. Same proposition, different falsifier. The re-adjudicated probes have not been measured; they wait for the 11-08 run. |
| THM-0081 | refusal minted from a stage's `Refusal` | CLEAN | Refusal arms are unchanged (`refuse_retained` / `refuse_accepted`). |
| THM-0083 | outstanding id established once | CLEAN | `outstanding` is still `admitted.envelope.outstanding()`, and it is the only input to `Answering::of`. |
| THM-0085 | two emitters | CLEAN | No new emitter. |
| THM-0045, 0088 | retention completion before serve | CLEAN | Completion still precedes offer, publish and serve. |
| THM-0051, 0052, 0135 | `request_stages.rs` | CLEAN | Test-only addition. |
| THM-0032, 0040, 0062, 0063, 0069, 0070, 0075, 0077, 0112, 0113, 0129, 0132 | `transparency_e2e_test.rs` | CLEAN | Doc-comment change only. |

Tests removed or weakened: two source-scan order tests were deleted.
- `dispatched::tests::a_notification_is_answered_before_any_reply_is_assembled` was replaced by `a_notification_yields_nothing_the_reply_assembler_takes` and `a_call_yields_the_call_with_the_id_it_answers`, plus S80.
- `success_exit::tests::the_outcome_is_committed_before_retention_and_both_before_success_is_served` was replaced by type order plus S81. Its own comment says "the order has no test".
- The integration controls on both mutation probes remain.
- The owner should confirm this substitution.

### #1277: refusals enter their terminal state (#1209) (merge 5d225f562)

What changed:
- Closes #1209: before this, `RefusedBeforeDispatch` and `FailedAfterDispatch` were never entered in production.
- `HttpProfileProxy::disposition` now takes `&mut ExchangeProgress` and calls `p.refuse()`, which is `advance(Refused)`, before reading `retry_semantics()` (`http_profile_serve/mod.rs:405`).
  - Every refusal exit derives its disposition through this one function: `mod.rs:382`, `dispatch_commitment.rs:64`, `answering_commitment.rs:91`, `pre_admission/mod.rs:81`, and `notification.rs:56`.
- `ExchangeProgress::advance` now floors at `transition(state, event)` when `event.establishes()` is `None`. `Refused` is the only such event (`exchange_state.rs:346`).
- `PublishPermit::exchange()` is now `#[cfg(test)]`.
- New `PublishPermit::withdraw(self) -> &mut ExchangeProgress` consumes the permit, so the refusal enters its own terminal unpublished.
- Tests: `advance_refused_enters_the_terminal_the_relation_picks` checks:
  - the terminal reached;
  - no anomaly and an unchanged verdict on the first refusal;
  - on a second refusal, a latch and `NotRetrySafe`.
- Also added: `a_refusal_disposition_enters_the_exchange_terminal` and `a_withdrawn_permit_leaves_its_exchange_to_the_refusal`.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0043 | relation decided; terminals absorbing | CLEAN | A refusal from a terminal state fails `transition`, latches, and does not move (tested). |
| THM-0044 | retry consequence never under-reports | CLEAN | The verdict is unchanged by the first refusal. A second refusal reports `NotRetrySafe`, which over-reports. No production exit calls `disposition` twice for one exchange (checked all six call sites). |
| THM-0078 | refusal is terminal, under the retry contract the machine derives | CLEAN-NOTE | The terminals are now live, so the claim's "refusal is terminal" is backed by machine state at runtime. Until #1209 it rested on `backend_may_have_executed()` read at the site. |
| THM-0101 | every event reaches the machine by exactly two routes; the assembly-owned set is exactly three | **DISCREPANCY** | See the note after this table. |
| THM-0081 | refusal under the machine's derived disposition | CLEAN | It is still derived in one function, which now also enters the terminal. |
| THM-0045, 0051, 0052, 0074, 0135 | `dispatch_commitment.rs` | CLEAN | The parameter is now `&mut`; behaviour is otherwise unchanged. |
| THM-0083, 0085 | `mod.rs` | CLEAN | Neither id provenance nor the emitters changed. |
| THM-0088, 0136 | success exit refusals | CLEAN | `permit.exchange()` became `permit.withdraw()`; retention is still completed with the refusal. |
| THM-0093 | `answering_commitment.rs` | CLEAN | `&` became `&mut` only. |

THM-0101 discrepancy:
- `ExchangeEvent::Refused` is now stated by the serving path. `disposition` at `mcp-re-proxy/src/http_profile_serve/mod.rs:405` calls `ExchangeProgress::refuse()` (`exchange_state/publication.rs:20`).
- That route is neither stage-owned nor one of the three assembly-owned events (`BackendDispatched`, `ContinuationRetired`, `ContinuationNotRequired`).
- The measured control `the_serving_path_states_only_the_assembly_s_own_transitions` (`tests/integration/exchange_transition_ownership_test.rs:205`) scans the serving source for `.advance(` and cannot see `.refuse()`. The control stays green while the enumeration in the claim is incomplete.
- The record was written at f28ec97c3, before this change landed.
- Either the claim names `Refused` as a fourth, refusal-owned route with its own control, or the scan must cover `refuse()`. Both are owner decisions about claim text.
- Also stale: the `proxy.publish_permit_sole_producer` unit description (`verification/policy/verification.toml:4277`) still says the permit "exposes it only by shared reference". Since #1277 it also exposes `withdraw(self) -> &mut`. The structural probe's `producer_paths` was updated, but the unit prose was not.

Tests removed or weakened: none; three were added.

### #1257: a committed intent carries its owed outcome; D7 is one function (#1247) (merge 099787cbf)

What changed:
- `IntentCommitment::commit` returns `OwedOutcome { provider, bound, coordinate, Redeemed<Intent> }` (`audit_commitment/outcome.rs`). Its only producer is G1, through the `pub(super)` `new`.
- G2 is `IntentDisposition::outcome` → `OwedOutcome::commit`. It commits to the same provider and coordinate G1 used.
  - The old `AuditPosture::outcome` was deleted. It re-read the posture and `acc.exchange_coordinate()`, and had a `Committed`+`BestEffort` → 500 arm.
- An absent coordinate is now refused only at G1, before dispatch (`intent.rs:78`). G2 can no longer see one.
- D7 is now one function, `dispatch_obligations::take`, which runs reserve → intent → commit with `?` (`dispatch_obligations.rs`). The order is identical.
  - Any refusal returns to the single `refuse_accepted` (`dispatch_commitment.rs:166`). Dropped obligations rescind themselves, as before.
- Mutation probes:
  - M610 was re-anchored and gained one unit-test expect_red.
  - New M626 (reserve before intent).
  - The G2 posture probe was re-anchored to `outcome.rs`.
  - No expect_red was removed.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0135 | G1 after reserve, before commit and dispatch; absent coordinate refused | CLEAN | Order is preserved and is now mutation-probed in both directions (M610, M626). |
| THM-0136 (via THM-0135 units) | G2 against the provider G1 used; requiredness carried, never re-read | CLEAN | This makes the statement's "against the provider G1 used" and "never a re-read of the posture" literally true by type. |
| THM-0045, 0051, 0052 | `ReadyForDispatch` assembly | CLEAN | The same three obligations in the same order. |
| THM-0081 | refusal routing | CLEAN | It still goes through one refusal function. |
| THM-0083, 0085, 0088 | `mod.rs` / `success_exit.rs` | CLEAN | Module declaration plus the G2 call-site change. |
| THM-0111 | `rust-targets.json` | CLEAN | Generated. |

Tests removed or weakened:
- `outcome::tests::an_absent_coordinate_is_500_and_asks_nothing` was removed, because G2 can no longer receive `None`.
- The G1 counterpart `intent::tests::an_absent_coordinate_is_500_and_asks_nothing` (`intent.rs:247`) remains, and it is M611's expect_red.
- Added: `the_owed_outcome_is_committed_for_the_exchange_its_intent_named` and the `dispatch_obligations` tests.

### #1283: characterise the stderr stream's order; THM-0070's order property is the collector's (#1211) (merge 6a535b614)

What changed:
- `audit_sink/stderr.rs`:
  - Extracted `record_on(envelope, queue, dropped, queued)` from `record`, with the same `offer` and `admission_ceiling`.
  - Added the test `the_stream_is_in_offer_order_and_keeps_each_events_own_seq`.
- THM-0070's scope gains a paragraph (see the claim diff below).
- Claim-correction records for THM-0070 and THM-0071, plus the packet `verification/reviews/packets/thm-0070-stderr-offer-order-scope-2026-11-03.md`.

| theorem | security meaning touched | verdict | note |
|---|---|---|---|
| THM-0070 | record stream honest; collector preserves emission order | CLEAN (source); **claim pending owner** | The source change is a behaviour-preserving extraction. The claim change is below. |

Tests removed or weakened: none; one added.

### THM-0070: claim text change (STALE_CLAIM, record d202361ca)

- Claim fingerprint: `sha256:dd38b842…` → `sha256:7660e7ca…`.
- Review digest: `sha256:496cc0f0…` → `sha256:16273d87…`.
- Field changed: `scope`. Statement, security consequence, severity, depends_on and review requirement are byte-identical (correction record `verification/claim-corrections/THM-0070-stderr-offer-order-scope-2026-11-03.json`).
- Old scope (end): "…It establishes nothing about whether a record SHOULD have been written for a given outcome, which is the totality proposition below."
- Added paragraph: "The emission-order property is the collector's. The stderr sink writes lines in the order they are offered, and a record's `seq` is allocated when its event is produced, before the offer, so lines from concurrent producers can reach the stream out of `seq` order. Position is still carried by every line: a consumer orders a run by `seq`, and a gap is a gap whatever the arrival order."
- Reading: this is a precision narrowing. It names what was never established for stderr, and it has a witness test. The security consequence (gaps are visible via `(run, seq)`) still holds on stderr.
- The correction record is an ADR-068 Phase-1 precision correction, and by its own text "is not an approval". **Owner specification approval is pending.**
- Supporting-unit semantics also moved: `proxy.audit_delivery` source (`stderr.rs`, #1283), and its test selection and sources (the shared integration tests above). All of these are CLEAN.

### THM-0071: STALE_DEPENDENCY_CLAIM (record 551ba14be)

- Pure propagation, confirmed.
- `depends_on = [THM-0069, THM-0046, THM-0081, THM-0070, THM-0085]` is unchanged.
- The only moved component is `theorem_dependencies`, and no supporting-unit component moved (census `units = {}`).
- Current claim fingerprint `sha256:cc325187…` equals the `to_fingerprint` of `verification/claim-corrections/THM-0071-thm-0070-scope-propagation-2026-11-03.json`. It moved solely because THM-0070's claim digest moved.
- THM-0071 uses THM-0070 only as "the stream is honest about what reached it", which is unchanged.
- Verdict: CLEAN. It is re-recordable together with THM-0070 once the owner approves THM-0070. Owner approval is pending.

### THM-0101: supporting-unit set changed since record f28ec97c3

- Added unit: `unit://proxy.publish_permit_sole_producer`, through #1264 (b3e4eee92, 2026-10-28, after the record).
  - It carries structural probes S76–S79, which were previously registered on a unit that claimed no structural evidence. They ran, but entered no fingerprint.
  - Adding it strengthens the evidence closure: those falsifiers are now fingerprinted.
- Other moved inputs:
  - `proxy.exchange_publication`: source and test selection (#1277, #1256, #1265, #1281).
  - `proxy.exchange_transition_ownership`: source and test sources.
- Verdict: **DISCREPANCY**, carried from #1277 above.
  - The "exactly two routes / exactly three assembly-owned" enumeration no longer covers `Refused`, now stated through `ExchangeProgress::refuse()`.
  - The ownership control cannot see it.
  - The new unit's description is also stale on "only by shared reference".
- The unit addition itself is CLEAN.

