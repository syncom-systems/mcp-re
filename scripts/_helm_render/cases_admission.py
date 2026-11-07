# SPDX-License-Identifier: Apache-2.0
"""Render cases: admission ceilings and the admission currency."""

from __future__ import annotations

from _helm_render.render import merged

# (name, values, must_render, message_fragment_required_on_failure)
#
# `must_render=False` means the chart MUST refuse. The fragment is asserted so a
# guard cannot pass this gate by failing for an unrelated reason (a YAML typo
# elsewhere also makes `helm template` non-zero).
ADMISSION_CASES: list[tuple[str, dict, bool, str]] = [
    # --- admission ceilings (MCPRE-114) ---
    (
        "admission ceiling of 0 is refused, not read as unset",
        merged({"admission": {"maxInFlight": 0, "maxInFlightTotal": ""}}),
        False,
        "must be a positive integer",
    ),
    (
        "admission total of 0 is refused",
        merged({"admission": {"maxInFlight": "", "maxInFlightTotal": 0}}),
        False,
        "must be a positive integer",
    ),
    (
        "a non-numeric admission ceiling is refused",
        merged({"admission": {"maxInFlight": "many", "maxInFlightTotal": ""}}),
        False,
        "must be a positive integer",
    ),
    (
        "both admission ceilings set is refused (one would be discarded)",
        merged({"admission": {"maxInFlight": 32, "maxInFlightTotal": 256}}),
        False,
        "not both",
    ),
    # The drain invariant. The kubelet's clock starts at pod DELETION, so the preStop
    # delay is spent inside terminationGracePeriodSeconds; get it wrong and in-flight
    # requests are SIGKILLed with no signed response and no rejection evidence.
    (
        "preStop + proxy drain >= kubelet grace is refused",
        merged({"drainPreStopSeconds": 6, "proxyDrainGraceSeconds": 30,
                "drainGracePeriodSeconds": 30}),
        False,
        "SIGKILLs",
    ),
    (
        "a proxy drain below the 30s request deadline is refused",
        merged({"proxyDrainGraceSeconds": 10}),
        False,
        "request deadline",
    ),
    (
        "a drain budget that fits renders",
        merged({"drainPreStopSeconds": 6, "proxyDrainGraceSeconds": 30,
                "drainGracePeriodSeconds": 45}),
        True,
        "",
    ),
    # The connection-age bound is the only re-check of an established peer's
    # certificate against an expiry or a reloaded CRL.
    (
        "a disabled connection-age bound is refused",
        merged({"maxConnectionAgeSeconds": 0}),
        False,
        "keeps one connection open",
    ),
    (
        "a connection outliving the cert lifetime is refused",
        merged({"maxConnectionAgeSeconds": 7200, "maxClientCertLifetimeSeconds": 3600}),
        False,
        "outlive the certificate",
    ),
    (
        "a live revocation tier without a trust reload cadence is refused",
        merged({"fleet": False, "replicaCount": 1},
               {"revocation": {"tier": "live", "trustEpochRedisUrl": "", "trustEpochKey": "",
                               "trustReloadSeconds": ""}}),
        False,
        "trustReloadSeconds",
    ),
    (
        "an unknown auditSink is refused",
        merged({"auditSink": "syslog"}),
        False,
        "auditSink",
    ),
    (
        "an unknown auditCommitment is refused",
        merged({"auditCommitment": "durable"}),
        False,
        "auditCommitment",
    ),
    (
        "a required audit delivery with no observer is refused",
        merged({"auditCommitment": "required", "auditSink": "none"}),
        False,
        "needs the stderr observer",
    ),
    (
        "an unknown verifiedContextCarrier is refused",
        merged({"verifiedContextCarrier": "yes"}),
        False,
        "verifiedContextCarrier",
    ),
    # --- ADR-MCPRE-053 §7 admission currency ---
    #
    # Distinct from the `admission:` in-flight ceiling above in every respect. The
    # naming collision is the reason these cases are explicit about which control
    # they exercise: an operator who set `admission.maxInFlightTotal` and believed
    # admission control was configured had configured a concurrency bound.
    (
        "an unknown admissionCurrency.mode is refused",
        merged({"admissionCurrency": {"mode": "on"}}),
        False,
        "admissionCurrency.mode",
    ),
    # A gate that looks enabled and verifies nothing is the worst of the three
    # states, so the trust anchor cannot be left out of a mode that checks.
    (
        "admission currency without an authority is refused",
        merged({"admissionCurrency": {"mode": "required"}}),
        False,
        "authorityKid",
    ),
    (
        "admission currency without the shared record is refused",
        merged({"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5"}}),
        False,
        "requires admissionCurrency.redisUrl",
    ),
    # This hop decides whether a caller is still admitted, so it gets the same
    # plaintext-Redis rule as the nonce and trust-epoch hops.
    (
        "plaintext admission-currency redis is refused under fleet",
        merged({"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "redis://r:6379"}}),
        False,
        "admissionCurrency.redisUrl is plaintext",
    ),
    # The record budget is the deployment's revocation-currentness promise, so a gate that
    # verifies signed records cannot be rendered without one. Zero is not a stricter
    # setting: it refuses every record the instant it is signed, so a correctly publishing
    # authority admits nobody.
    (
        "an enforcing gate without a record-currentness budget is refused",
        merged({"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379"}}),
        False,
        "recordMaxAgeSecs",
    ),
    (
        "an unbounded degraded window is refused",
        merged({"admissionCurrency": {"mode": "optional", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379",
                                      "recordMaxAgeSecs": 60,
                                      "allowDegraded": True, "degradedBoundSecs": 0}}),
        False,
        "degradedBoundSecs",
    ),
    (
        "a degraded window past the CLI ceiling is refused at render",
        merged({"admissionCurrency": {"mode": "optional", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379",
                                      "recordMaxAgeSecs": 60,
                                      "allowDegraded": True, "degradedBoundSecs": 3601}}),
        False,
        "at most 3600",
    ),
    # The half-configured state that reads as "admission control is on" to anyone
    # auditing the rendered args while nothing is enforced.
    (
        "admission-currency settings with mode off are refused, not silently ignored",
        merged({"admissionCurrency": {"mode": "", "authorityKid": "adm-1"}}),
        False,
        "mode is off",
    ),
]
