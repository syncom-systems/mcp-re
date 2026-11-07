# SPDX-License-Identifier: Apache-2.0
"""Render cases: the drain invariant with the audit flush inside it, and the hops a
single-replica install still guards."""

from __future__ import annotations

from _helm_render.render import merged

# (name, values, must_render, message_fragment_required_on_failure)
#
# `must_render=False` means the chart MUST refuse. The fragment is asserted so a
# guard cannot pass this gate by failing for an unrelated reason (a YAML typo
# elsewhere also makes `helm template` non-zero).
DRAIN_CASES: list[tuple[str, dict, bool, str]] = [
    # --- the drain invariant, with the post-serve audit flush inside it ---
    # The base values are 6 + 30 + 2 = 38 < 45 and render. These two sit either side of
    # the boundary the audit flush moves: 13 + 30 = 43 < 45 was legal while the chart
    # budgeted only the drain, and is not, because the process is still flushing at 45
    # and the kubelet SIGKILLs at 45.
    (
        "a drain that fits only without the audit flush is refused",
        merged({"drainPreStopSeconds": 13, "proxyDrainGraceSeconds": 30,
                "drainGracePeriodSeconds": 45}),
        False,
        "audit flush",
    ),
    (
        "the same drain renders once the grace period covers the flush",
        merged({"drainPreStopSeconds": 13, "proxyDrainGraceSeconds": 30,
                "drainGracePeriodSeconds": 60}),
        True,
        "",
    ),
    # THE SINGLE-REPLICA HOLE. Every plaintext-Redis case above renders under the base
    # values, and the base values set `fleet: true` — so the whole rule was only ever
    # measured on one side of a conjunct. The admission-currency guard carried
    # `and .Values.fleet` while values.yaml documented the refusal as holding "at any
    # replica count", and no case could see the difference. What is at stake on all three
    # hops is who can write the keyspace, which does not depend on replica count.
    (
        "plaintext admission-currency redis is refused with fleet off",
        merged({"fleet": False},
               {"replay": {"redisUrl": "rediss://r:6379", "durabilityTier": "linearizable"}},
               {"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "redis://r:6379"}}),
        False,
        "admissionCurrency.redisUrl is plaintext",
    ),
    (
        "plaintext replay redis is refused with fleet off",
        merged({"fleet": False},
               {"replay": {"redisUrl": "redis://r:6379", "durabilityTier": "linearizable"}}),
        False,
        "replay.redisUrl is plaintext",
    ),
    (
        "plaintext trust-epoch redis is refused with fleet off",
        merged({"fleet": False},
               {"revocation": {"tier": "push:60", "trustEpochRedisUrl": "redis://r:6379",
                               "trustEpochKey": "mcp-re:trust:epoch"}}),
        False,
        "trustEpochRedisUrl is plaintext",
    ),
    # The mirror, without which the three above are satisfied by a chart that refuses
    # everything at fleet=false.
    (
        "a single-replica install with encrypted hops still renders",
        merged({"fleet": False},
               {"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379",
                                      "recordMaxAgeSecs": 60}}),
        True,
        "",
    ),
    (
        "a fully configured admission currency renders",
        merged({"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379",
                                      "recordMaxAgeSecs": 60}}),
        True,
        "",
    ),
]
