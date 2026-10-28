<!-- SPDX-License-Identifier: Apache-2.0 -->

# THM-0101 permit-publish correction and THM-0074 reaffirmation — owner ruling, 2026-10-27

**What this file is.** A transcription, by the agent preparing #1258, of the owner's in-session
ruling of 2026-10-27 over the packet
[`packets/thm-0101-permit-publish-2026-10-27.md`](../packets/thm-0101-permit-publish-2026-10-27.md).

**What this file is not.** It is not an owner signature. No line in
`docs/security/owner-approvals-*.jsonl` signs it. The ledger line the owner's sign-off needs is
prepared in §3 but not appended, because appending it is the owner's act.

## 1. The ruling (verbatim)

> I accept the minimal THM-0101 correction in #1258 and reaffirm THM-0074's unchanged claim at its
> updated dependency fingerprint, retaining their existing scope and evidence limitations.
>
> Prepare the two specification-review records for these reviewed claims, using fingerprints
> recalculated at the final candidate. Preserve the historical correction records and review
> provenance.

## 2. The records

Both records were rewritten at the identities `tools/verification/review --fingerprint` measures on
the candidate. Each keeps its earlier `notes` and appends this ruling. Each names
`agent:claude-opus-5-5 (owner ruling of 2026-10-27 on #1258; prepared for owner ratification, not an owner signature)`
as its reviewer.

| theorem | `reviewed_fingerprint` | `review_digest` | what moved |
|---|---|---|---|
| THM-0101 | `sha256:9f9745bcb0bf2af74553369994a9ebb140e60965c42b8762f2d55e8be76a9641` | `sha256:d721b975…` | its claim (`728308eb…` → `f5f6b4e5…`). Supporting semantics: `proxy.exchange_publication` `source_inputs`, `mutation_probes` and `test_selection`; `proxy.exchange_transition_ownership` `source_inputs` and `test_sources` (#1253, #1256, #1257) |
| THM-0074 | `sha256:d5f490dbe84378272fb8afa20efcc9aa0f97b2033a94b126e84192de39d81614` | `sha256:be22e2f9…` | its dependency digest for THM-0101 only; its own claim is unchanged. Supporting semantics: `proxy.dispatch_commitment` `source_inputs` and `test_sources`; `proxy.exchange_relation` `source_inputs` (#1253, #1256, #1257) |

Nothing in `verification/claim-corrections/` is added, edited or deleted. The nine historical
THM-0074 correction records and THM-0101's records stay as they were. The review is the
authority that carries both theorems to their corrected fingerprints, so no correction chain has to
be extended.

Scope and evidence limitations are as registered. THM-0101 rests on source-text and structural
evidence, class V0. The V0 units under THM-0074 are tested and probed. None of this is a
machine-checked proof.

## 3. Owner-approval ledger line this ruling needs

The tooling reads a theorem specification record as its own authority (`_approvals.ledger_state`,
`allow_ruling=True`). So these two records make the claim-surface gate pass before the owner has
signed anything. That is a property of the tooling, not an owner act. Until the owner appends the
line below, the records attest the agent's reading under the ruling, nothing more.

| line | kind | what it signs |
|---|---|---|
| `owner-signature:thm-0101-permit-publish-2026-10-27` | RULING | §1: acceptance of the THM-0101 correction and reaffirmation of THM-0074, at the fingerprints in §2 |

The exact line, with `sha256(text)` and the candidate commit as its `baseline_commit`, is in
`work/exec/1258/owner-ledger-draft-2026-10-27.jsonl`.
