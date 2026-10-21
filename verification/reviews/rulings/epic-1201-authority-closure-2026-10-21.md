<!-- SPDX-License-Identifier: Apache-2.0 -->

# Epic #1201 (ADR-MCPRE-070) final authority closure — owner directions, 2026-10-21

**What this file is.** A transcription, by the agent running `/exec #1201`, of the owner's
in-session directive of 2026-10-21 ("MCP-RE `/exec #1201` — Final authority closure"). The
binding directions are quoted verbatim below. They decide the items the pre-assurance packet
[`packets/epic-1201-assurance-closure-2026-10-21.md`](../packets/epic-1201-assurance-closure-2026-10-21.md)
left to the owner.

**What this file is not.** It is not an owner signature. No line in
`docs/security/owner-approvals-*.jsonl` signs it, and nothing here may be read as one. The
ledger lines the owner's sign-off needs are listed in §3, prepared but not appended:
appending them is the owner's act.

## 1. The binding directions (verbatim)

> 1. O4 approved: preserve the existing best-effort audit stream contract. Document the separate required-commitment behavior.
>
> 2. O5 approved as a documented availability limitation, not as an unqualified correctness guarantee. Create a focused follow-up for the signature-window/G2 wait interaction and establish appropriate negative-test coverage. No false-success claim is permitted.
>
> 3. Add `unit://proxy.audit_posture` to THM-0077's support.
>
> 4. Add THM-0135 to THM-0074's dependency closure, preserving THM-0074's existing proposition.
>
> 5. Do not automatically attach THM-0136 to THM-0075. Examine the logical dependency graph and identify the correct success-visibility or response-completion authority. Produce an exact proposed edge with its logical justification. Do not force an unrelated theorem dependency merely to make root coverage green.
>
> 6. NP-290 requires an explicit, narrow public-Web-PKI trust assumption. Keep this distinct from ASM-0070's configured-root premise. Record the external trust boundary and actual validation responsibilities.
>
> 7. Re-review ASM-0070 and ASM-0082 against the current TLS implementation, library versions and connector construction. Preserve their original trust boundaries. Prepare the required owner-review records with source evidence.
>
> 8. Defer the optional ASM-0090/0091 liveness-unit split until after assurance closure.

The directive also says: "Preserve V0 evidence classifications. Do not claim that tests and
structural probes constitute machine-checked proofs. Do not falsely assert that an
agent-authored review record constitutes an authenticated owner signature. Restore
claim-surface currency through the proper review-record process, not blind digest
replacement." and "Do not merge the PR stack or initiate the expensive verification campaign."

## 2. How each direction was carried out

| direction | carried out | where |
|---|---|---|
| 1 O4 | ADR §15 "Owner rulings, 2026-10-21": the best-effort stream contract is preserved; the required-commitment behaviour is documented as separate. | `docs/architecture/audit-commitment.md` |
| 2 O5 | ADR §14 item 11 records the limitation as an availability limitation; follow-up #1224; negative test `outcome_before_success_test.rs::required::a_window_that_lapses_during_g2_is_refused_by_the_client_never_accepted`. | ADR, test, #1224 |
| 3 | THM-0077 `supported_by` gains `unit://proxy.audit_posture`. | `verification/policy/theorems.toml` |
| 4 | THM-0074 `depends_on` gains THM-0135; its statement, consequence and scope are unchanged; §7.1 row. | `theorems.toml`, `docs/spec/security-boundary.md` §7.1 |
| 5 | Not applied. Proposed edge `THM-0078.depends_on += "THM-0136"`, with its justification, rejected alternatives and one owner note. | packet, Addendum 2 |
| 6 | ASM-0092, the public Web PKI premise, scoped to `unit://proxy.outbound_destination` and `boundary://boundary.tls_mechanism`, distinct from ASM-0070; NP-290's `root_relationship` names it. | `verification/policy/assumptions.toml`, `control-dispositions.toml`, `control-dispositions.md` |
| 7 | ASM-0070 and ASM-0082 HOLD at unchanged text; source evidence in the packet; notes appended to both records. | packet, Addendum 2; `verification/reviews/assumption/` |
| 8 | Deferred. | — |

**Records.** The 70 specification records and the four assumption records (ASM-0089, ASM-0090,
ASM-0091, ASM-0092) are written at the final measured identities by
`tools/verification/review --fingerprint` and `_fingerprint.assumption_digest`. Each names
`agent:claude-opus-5-5 (exec #1201; prepared for owner ratification, not an owner signature)` as
its reviewer, and its notes say the same. The packet's Addendum 2 lists the 21 identities that
moved after its inventory, with the cause of each.

What the tooling does with them, stated so nobody reads more into it:

- A theorem specification record is read as the review authority for that theorem
  (`_approvals.ledger_state`, `allow_ruling=True`). So these records make the 70 theorems read
  REVIEWED and the claim-surface gate pass **before** the owner has signed anything. That is a
  property of the tooling, not an owner act: until the adoption line in §3 is in the
  ledger, these records attest the agent's reading only.
- An assumption record counts only with an ENTRY approval at the entry's current text. The four
  new ones read UNBACKED until the owner signs them, and every theorem whose premise closure
  holds them reads PREMISE_UNREVIEWED: THM-0135, THM-0136 and THM-0077 (ASM-0089..0091), and
  THM-0090 (ASM-0092). Two declared roots hold them in their closure and so wait on those
  signatures for root completeness: THM-0074 (through THM-0135, THM-0077 and THM-0090) and
  THM-0077 (itself and THM-0090). No dependency cycle exists (checked over the whole registry).

## 3. Owner-approval ledger lines this closure needs

Appending a line to `docs/security/owner-approvals-*.jsonl` is the owner's signature. None is
appended here. The exact lines are prepared, outside the ledger glob, in
`work/exec/1201/owner-ledger-draft-2026-10-21.jsonl`. Their `baseline_commit` is the candidate
commit, and every `sha256` is `sha256(text)`.

| line | kind | what it signs | `sha256(text)` | mechanically required? |
|---|---|---|---|---|
| `owner-signature:asm-0089-epic-1201-closure-2026-10-21` | ENTRY | ASM-0089, whole entry | `788d52df2019b617af5da09b0b2b5b80f6174e42109ff1e5e7a06bbbe99302c0` | yes: until signed, ASM-0089 is UNBACKED, and THM-0135, THM-0136 and THM-0077 are PREMISE_UNREVIEWED |
| `owner-signature:asm-0090-epic-1201-closure-2026-10-21` | ENTRY | ASM-0090, whole entry | `23f8ca3576ff9473fed712999323c39d32b151dc9e4132f0a7c8c6d468231b9c` | yes, as above |
| `owner-signature:asm-0091-epic-1201-closure-2026-10-21` | ENTRY | ASM-0091, whole entry | `e7616a02d2d3363dc313d44f6c668003bc99b2d61739c309fbebae34a430d042` | yes, as above |
| `owner-signature:asm-0092-epic-1201-closure-2026-10-21` | ENTRY | ASM-0092, whole entry | `a1b5488b3aaf012ac0a8b2193e46b10737fbac00904ae0a898ea5ce8e9a48ae5` | yes: until signed, THM-0090 is PREMISE_UNREVIEWED |
| `owner-signature:epic-1201-assurance-closure-2026-10-21` | RULING | ratifies the 70 re-reviews and records; re-acknowledges ASM-0070 and ASM-0082 (original wording, signed in `owner-approvals-2026-10-21.jsonl`) | `4ad041b56782226aa807baa9b06768a15eee89c9bda9888ce6e26e2c1836dcc6` | not by the tooling (a theorem record is its own authority, and ASM-0070/0082 are still signed at their current text); required by the review process this repository uses, so that an owner act stands behind each record |

An entry approval signs exact bytes: if any of the four entries is edited before signing, its
digest changes and the line must be re-derived (`_approvals.entry_text`, then `text_digest`).
The optional direction-5 edge, if the owner takes it, moves THM-0078 and needs its own record
after the edit.

## 4. The owner's second directive of 2026-10-21 (security sign-off and integration closure)

Transcribed, as §1 is; not an owner signature.

- **ASM-0092 and the outbound trust model.** "Retain the current public Web PKI model for MCP-RE
  OSS v0.19." The owner accepts the architectural trust boundary ASM-0092 describes: the public
  certificate-authority trust model, the dependence on correct chain and hostname verification,
  the external trust placed in the public CA ecosystem, the non-claims on revocation, Certificate
  Transparency and root-store freshness, and the need to revisit the assumption when the TLS
  implementation or trust-root dependencies change. No new outbound trust architecture, trust-policy
  abstraction or certificate pinning enters this campaign. "This decision approves the security
  architecture and trust assumption. It is not permission to fabricate an authenticated owner
  signature."
- **Architectural acceptance of ASM-0089..0092.** Approved. The four entry approvals in §3 are
  still the owner's personal act over the exact entry bytes.
- **The fifth line's wording.** Corrected so that it records the owner adopting the documented
  agent-prepared review rather than claiming to have repeated every source-level review, and so
  that it names the V0 classes as tests, structural controls and mutation evidence. The counts,
  the THM-0101/THM-0122 corrections and the ASM-0070/0082 re-acknowledgement are unchanged. The
  owner signed the original wording first; a ledger line cannot be edited, so the corrected text is
  a new line, `owner-signature:epic-1201-assurance-closure-adoption-2026-10-21`
  (`sha256` `aaacb22d9199056eb291ec3d63d5fac2aff2f36db95b2100888b57cafe2562ab`), that names the
  original in `supersedes`. Appending it is the owner's act, as §3 is.
