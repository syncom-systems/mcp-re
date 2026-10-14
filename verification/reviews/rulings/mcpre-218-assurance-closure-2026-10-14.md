<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCPRE-218 assurance closure — owner rulings, 2026-10-14

Campaign #1171. The post-architecture re-review of the 92 theorems whose specification review went
stale across epics #1106 and #1143 is in
`verification/reviews/packets/assurance-closure-rereview-2026-10-14.md`. This is the owner's
disposition of that packet. It is signed in `docs/security/owner-approvals-2026-10-14.jsonl` as
`owner-signature:mcpre-218-assurance-closure-2026-10-14`, whose `text` is the ruling below.

## The ruling

> Owner rulings for MCPRE-218 / #1171.
>
> ## 1. Batch ratification — 87 clean theorem re-reviews
>
> APPROVED.
>
> I ratify the 87 theorem re-reviews in groups A–F as described in the assurance-closure packet.
>
> This includes the eight reviews carrying note-only observations such as stale probe descriptions or labels, provided those notes do not change the proposition or the evidence semantics.
>
> You may now write the specification-review records for those 87 theorems at their exact current theorem fingerprints and review digests.
>
> Do not manufacture a review record if the fingerprint/review digest has moved since the packet was produced; fail and re-read that item instead.
>
> ## 2. THM-0092 — choose Option 1
>
> Do NOT narrow THM-0092.
>
> The security property became stronger by moving one refusal earlier in the lifecycle. The theorem should follow the property to its new owner rather than discard that part of the guarantee.
>
> Add:
>
> `unit://proxy.replay_configuration_state`
>
> to THM-0092's support.
>
> Correct the theorem narrowly so it states the actual two-stage behavior:
>
> - a fleet-strict configuration with no declared replay tier is refused at the configuration boundary before a serving deployment exists;
> - for a configuration that reaches replay admission, the existing admission gate still refuses the below-minimum tier and incompatible/self-reported store class before dispatch/store admission proceeds as specified;
> - store outage still refuses rather than becoming Fresh;
> - the Redis/etcd durability-premise treatment remains unchanged.
>
> The security consequence must not be weakened.
>
> Correct the scope as well: it must no longer say that the undeclared-tier operator statement is “checked here” by replay admission. Name the configuration owner for that clause and the admission owner for the runtime clauses.
>
> Keep the existing logical dependencies unless the correction itself demonstrates another genuine dependency defect.
>
> In particular, do NOT add THM-0077 as a dependency of THM-0092. THM-0077 already composes this replay proposition; reversing that edge would be the wrong logical direction.
>
> Record this as a claim correction preserving the existing system promise while correcting the locus of enforcement.
>
> ## 3. Four stale prose claims
>
> Approve one narrow claim-correction PR for:
>
> - THM-0082
> - THM-0049
> - THM-0094
> - THM-0095
>
> Do not ratify their presently stale wording first. Correct the wording, then record the reviews against the corrected fingerprints.
>
> ### THM-0082
>
> Remove the obsolete statement that the root reads the key source through the role-separation witness's “borrowed projection”.
>
> #1111 deleted that projection and the key source no longer leaves the witness.
>
> Restate only the current ownership path established by the implementation: the materialized signing-role owner retains the source and hands out the established products/roles the root consumes. Do not change the theorem's security consequence or expand its scope.
>
> ### THM-0049
>
> Correct:
>
> “Three are live”
>
> to the current four-rule set:
>
> - X2a
> - X6
> - X9
> - X10
>
> X10 is the `ChannelCredentialCustodyState × ShardTopology` delegated-TLS-depth relation.
>
> Do not otherwise widen THM-0049.
>
> ### THM-0094 / THM-0095
>
> Correct the scope's ownership description.
>
> The common binding semantics are now owned by:
>
> `unit://sdk_binding_core.adapter`
>
> The Python/TypeScript native units are the language-specific PyO3/napi marshalling adapters around that owner.
>
> Preserve ASM-0088 for the PyO3 marshalling boundary and ASM-0087 for the napi boundary.
>
> Do not change the SDK-root security promises; this correction only states accurately which unit owns the common adapter behavior and which units own language marshalling.
>
> For all four corrections, retain explicit old -> new text in the correction record.
>
> ## 4. #1119 ClaimWindow semantics
>
> CONFIRMED.
>
> The default applied in MCPRE-194 / #1119 is approved as the authoritative rule:
>
> - `exp + skew <= now` => REFUSE
> - `exp <= nbf` => REFUSE
> - `iat > now + skew` => REFUSE
>
> Equivalently, the expiration boundary is half-open: acceptance ends before the instant `exp + skew`.
>
> Delegation must not keep its former exceptional inclusive edge.
>
> This is the one `ClaimWindow` policy for all four compact-JWS consumers.
>
> No additional owner ruling is required for these edge semantics.
>
> ## 5. ASM-0069 / PR #1174
>
> Proceed with #1174 under the existing ruling once its required fast checks are green.
>
> No extra full verification is required merely for the assumption approval/review records.
>
> ## 6. Evidence reuse
>
> After the 87 records and the five held-item corrections/reviews land:
>
> 1. recompute every unit fingerprint;
> 2. compare them with the exact fingerprints established by run `38513625401`;
> 3. if they remain byte-identical, reuse that run's evidence;
> 4. issue attestations from that evidence;
> 5. measure all three assurance axes.
>
> Target:
>
> - REVIEW_CURRENT = 133 / 133
> - EVIDENCE_ESTABLISHED = 133 / 133
> - CURRENTLY_VERIFIED = 133 / 133
>
> Do not launch another full verification unless a unit fingerprint actually moves.
>
> A theorem claim fingerprint moving because we corrected theorem prose is expected and requires a new theorem review record; it does not by itself mean the expensive unit evidence must be regenerated.
>
> ## 7. Count correction
>
> Correct the wording “1,234 unit fingerprints”.
>
> The final verification repository has 308 declared verification units. PR #1174 reports 1,234 lines of fingerprint-command output, not 1,234 units.
>
> Do not propagate the incorrect unit count into the campaign record.

— Mats Sundvall (owner)

## Encoding

**The 87 ratified re-reviews.** Each `verification/reviews/specification/THM-NNNN.json` is
re-recorded at its current `review_digest`. Before writing, every one of the 133 theorem
fingerprints and review digests was recomputed at the packet's base `72127a07` and at `5dc20f6a`
and found identical, so no record names a digest the packet did not read.

**THM-0092.** The statement and scope now name the two loci: the configuration boundary
(`proxy.replay_configuration_state`) refuses a fleet-strict deployment with no declared tier
before a serving deployment exists; replay admission (`proxy.replay_admission_gate`) refuses a
below-minimum tier and the single-process store class before any store side effect, and an
unanswered store is an outage. `unit://proxy.replay_configuration_state` joins `supported_by`.
The security consequence, `depends_on` and the Redis/etcd premise paragraphs are unchanged;
THM-0077 is not added as a dependency.

**THM-0049.** "Three are live" becomes the four relations X2a, X6, X9 and X10. X10's refusal and its
battery live in `unit://proxy.delegated_tls_depth_refusal` (`proxy.cross_machine_legality`'s own
description names it as X10's owner), so that unit joins `supported_by`; without it the scope
would name a relation the closure carries no control for. The statement and the security
consequence are unchanged. The ledger's entry approval for THM-0049 is re-signed at the new
entry text (`owner-signature:thm-0049-four-live-relations-2026-10-14`), because an entry
approval over the earlier text would otherwise refute the new review.

**THM-0082.** The "one borrowed projection" clause is replaced by the current path: the
role-separation witness retains the key source, and the root consumes its channel credential, its
response public key and the witness itself as the response signer. Consequence and scope are
unchanged.

**THM-0094 / THM-0095.** The scope's ownership sentence names `sdk_binding_core.adapter` as the
owner of the binding semantics both SDKs share and the native units as the PyO3 / napi marshalling
adapters around it. ASM-0088 and ASM-0087 are unchanged and remain the marshalling premises.

Each of the five carries its old and new text in
`verification/claim-corrections/THM-NNNN-mcpre-218-assurance-closure-2026-10-14.json`, and its
specification review names the corrected fingerprint.

**Dependency cascade.** Correcting THM-0092, THM-0049 and THM-0082 moves the
`theorem_dependencies` component of THM-0074 (through THM-0092), THM-0077 (through THM-0049) and
THM-0075 (through THM-0082). Nothing else in their fingerprints moved. Each was re-read against
the corrected dependency text, which states the same promise, and its review is recorded at the
new fingerprint as part of the ratified batch. No theorem outside the 92 moved.

**#1119.** The `ClaimWindow` edges are confirmed as applied in MCPRE-194: refused when
`exp + skew <= now`, when `exp <= nbf`, and when `iat > now + skew`. No record changes for it.

**Evidence.** The unit fingerprints (`tools/verification/fingerprint`, all 308 declared units)
are byte-identical to those at `72127a07` that full run 38513625401 attested, so that run's
evidence is reused and no verification run is launched for these records.
