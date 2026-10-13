<!-- SPDX-License-Identifier: Apache-2.0 -->

# THM-0060 — an out-of-range clock skew is refused, owner ruling, 2026-10-13

MCPRE-200 (#1125, PR #1160) made `MaxClockSkew` a typed bound that refuses an out-of-range
configured value instead of saturating it. THM-0060's claim had described the clamping
implementation, so its statement moved and its specification review went stale.

## The ruling

> An operator-supplied clock skew outside the supported range is REFUSED.
>
> It is not saturated or clamped.
>
> Reason: this is security policy supplied by an operator. Silently converting 301 seconds into
> 300 seconds changes the policy the operator stated and hides invalid configuration. The typed
> `MaxClockSkew` should establish the invariant at admission.
>
> If some future internally DERIVED value genuinely requires saturating arithmetic, that can have
> a separately named producer with its own semantics. It is not the policy for operator
> configuration.
>
> Approve the THM-0060 claim correction accordingly.
>
> The old theorem text described the old clamping implementation. The new claim should state the
> actual invariant: the skew is bounded by construction/type, an out-of-range configured value is
> refused, and verification does not silently clamp it.
>
> Proceed with the claim-surface approval required for PR #1160.
>
> Do not weaken the refusal behavior merely to preserve the old theorem wording.

— Mats Sundvall (owner)

## Encoding

`verification/reviews/specification/THM-0060.json` names the fingerprint and review digest of
the statement this ruling approved: `DelegationPolicy` takes the skew as a `MaxClockSkew` in a
private field, an out-of-range configured value is refused where it is configured and never
clamped, and both freshness windows read the one skew through the policy's single projection.
