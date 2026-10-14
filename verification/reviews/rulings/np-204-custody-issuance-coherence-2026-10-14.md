<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-204 — issuance coherence belongs to the delegated-signing custody unit, owner ruling, 2026-10-14

NP-204 identified four controls in `mcp-re-http-profile` that establish a property no unit
claimed: the identity, key, credential id and lifecycle record of one delegated issuance agree.
Its likely owner, `unit://http_profile.delegated_signing_custody`, held both carriers in its
paths, but its description covered only the lifecycle clauses, so registering them needed the
description amended. That amendment is the owner's to make, because the unit supports THM-0063.

## The ruling

> YES — amend `unit://http_profile.delegated_signing_custody` to cover NP-204.
>
> NP-204 belongs to this custody owner.
>
> The existing custody authority covers the integrity of one delegated issuance and its signing
> window. NP-204 adds the missing issuance-coherence clause:
>
> - the delegated identity admitted for the snapshot names this issuance's delegated key;
> - an identity/request naming another delegated key is refused;
> - the credential id is read from this issuance's credential rather than supplied independently;
> - lifecycle retirement/reissue identifies the predecessor under its own credential id and
>   validity window.
>
> This is NOT the root-rotation authority that was previously refused for this unit. Root
> rotation changes the trust authority held fixed by the delegated-key lifecycle. NP-204 instead
> states coherence among the identity, key, credential and lifecycle record of the SAME delegated
> issuance.
>
> Amend the unit description narrowly to state that property. Do not broaden it into
> root-authority rotation, verifier trust-anchor selection, or general credential-chain
> correctness.
>
> Then register the four NP-204 controls with `http_profile.delegated_signing_custody`:
>
> - `an_identity_naming_another_keyid_is_refused`
> - `an_identity_the_request_did_not_name_is_refused`
> - `the_credential_id_is_read_out_of_the_credential`
> - `a_reissue_retires_the_predecessor_under_its_own_credential_id_and_window`
>
> Retire/resolve NP-204 through the normal control-disposition mechanism once those controls are
> legitimately contained by the amended unit.
>
> `http_profile.delegated_signing_custody` supports THM-0063. Therefore the unit-description
> change is a semantic change, not documentation-only.

## What was done

- The unit's description gains one clause stating issuance coherence, in the ruling's four
  parts, and nothing about root rotation, trust-anchor selection or chain correctness.
- The four controls join the unit's `tested_symbols` (ADR-MCPRE-069 D1 *register*), so their
  `new-proposition` rows CD-20026..CD-20029 are deleted: a registered control leaves the census
  by construction, and a row about it would be refused as an orphan.
- NP-204 records `ratified_as = "http_profile.delegated_signing_custody"`.
- THM-0063 is the only theorem the unit supports, and the only one whose review data moves
  (measured by diffing `tools/verification/review --json` against `origin/main`). Its claim
  fingerprint does not move, so no dependent theorem's fingerprint does. Its specification
  review is re-recorded at the new review digest
  (`verification/reviews/specification/THM-0063.json`).
