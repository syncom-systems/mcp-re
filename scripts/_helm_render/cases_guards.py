# SPDX-License-Identifier: Apache-2.0
"""Render cases: the base values and the guards on placement, placeholders, binding and custody."""

from __future__ import annotations

from _helm_render.render import merged

# (name, values, must_render, message_fragment_required_on_failure)
#
# `must_render=False` means the chart MUST refuse. The fragment is asserted so a
# guard cannot pass this gate by failing for an unrelated reason (a YAML typo
# elsewhere also makes `helm template` non-zero).
GUARD_CASES: list[tuple[str, dict, bool, str]] = [
    ("base values render", merged(), True, ""),
    # --- inner plane ---
    (
        "no inner backend is refused",
        merged({"inner": {"httpUrls": []}}),
        False,
        "inner plane required",
    ),
    # --- fleet vs node-local replay ---
    (
        "fleet with no shared replay store is refused",
        merged({"replay": {"redisUrl": "", "durabilityTier": "redis-wait-quorum:2:2000"}}),
        False,
        "requires replay.redisUrl",
    ),
    (
        "fleet with a node-local durability tier is refused",
        merged({"replay": {"redisUrl": "rediss://r:6379", "durabilityTier": "redis-async"}}),
        False,
        "requires replay.durabilityTier",
    ),
    # --- plaintext Redis on the nonce / epoch hops ---
    (
        "plaintext replay redis is refused under fleet",
        merged({"replay": {"redisUrl": "redis://r:6379", "durabilityTier": "linearizable"}}),
        False,
        "replay.redisUrl is plaintext",
    ),
    (
        "plaintext trust-epoch redis is refused under fleet",
        merged({"revocation": {"tier": "push:60", "trustEpochRedisUrl": "redis://r:6379",
                               "trustEpochKey": "mcp-re:trust:epoch"}}),
        False,
        "trustEpochRedisUrl is plaintext",
    ),
    (
        "plaintext replay redis renders with the named opt-out",
        merged({"fleet": False, "replicaCount": 1},
               {"replay": {"redisUrl": "redis://r:6379", "durabilityTier": "linearizable",
                           "allowPlaintextRedis": True}},
               {"revocation": {"tier": "push:60", "trustEpochRedisUrl": "",
                               "trustEpochKey": "mcp-re:trust:epoch"}}),
        True,
        "",
    ),
    # --- delegated signing across replicas needs a trust-epoch source (no override) ---
    (
        "more than one replica without a trust-epoch source is refused",
        merged({"fleet": False, "replicaCount": 2},
               {"revocation": {"tier": "push:60", "trustEpochRedisUrl": "", "trustEpochKey": ""}}),
        False,
        "requires revocation.tier push:<T> and revocation.trustEpochRedisUrl",
    ),
    (
        "fleet=true on one replica without a trust-epoch source is refused",
        merged({"fleet": True, "replicaCount": 1},
               {"revocation": {"tier": "push:60", "trustEpochRedisUrl": "", "trustEpochKey": ""}}),
        False,
        "requires revocation.tier push:<T> and revocation.trustEpochRedisUrl",
    ),
    (
        "more than one replica on a non-push tier is refused",
        merged({"fleet": False, "replicaCount": 3},
               {"revocation": {"tier": "live", "trustEpochRedisUrl": "rediss://r:6379"}}),
        False,
        "requires revocation.tier push:<T> and revocation.trustEpochRedisUrl",
    ),
    (
        "one non-fleet replica without a trust-epoch source renders",
        merged({"fleet": False, "replicaCount": 1},
               {"revocation": {"tier": "push:60", "trustEpochRedisUrl": "", "trustEpochKey": ""}}),
        True,
        "",
    ),
    (
        "a fleet with a push-tier trust-epoch source renders",
        merged({"fleet": True, "replicaCount": 3},
               {"revocation": {"tier": "push:60", "trustEpochRedisUrl": "rediss://r:6379"}}),
        True,
        "",
    ),
    # --- shipped placeholders (one dispatch boundary per install) ---
    (
        "did:example: audience placeholder is refused",
        merged({"identity": {"audience": "did:example:server-1"}}),
        False,
        "did:example:",
    ),
    (
        "example.com trust-domain placeholder is refused",
        merged({"identity": {"trustDomain": "example.com"}}),
        False,
        "example.com placeholder",
    ),
    (
        "epoch-1 delegated-epoch placeholder is refused",
        merged({"identity": {"delegatedTrustEpoch": "epoch-1"}}),
        False,
        "epoch-1 placeholder",
    ),
    (
        "the shipped defaults render ONLY under allowExampleFixtures",
        merged({"identity": {"audience": "did:example:server-1",
                             "serverSigner": "did:example:server-1",
                             "trustDomain": "example.com",
                             "delegatedTrustEpoch": "epoch-1",
                             "allowExampleFixtures": True}}),
        True,
        "",
    ),
    (
        "empty targetUri is refused",
        merged({"identity": {"targetUri": ""}}),
        False,
        "identity.targetUri is required",
    ),
    # --- transport binding: only "" and exact can start ---
    ("transportBinding=none is refused", merged({"transportBinding": "none"}), False, "cannot start"),
    (
        "transportBinding=lb-assertion is refused",
        merged({"transportBinding": "lb-assertion"}),
        False,
        "cannot start",
    ),
    ("transportBinding=exact renders", merged({"transportBinding": "exact"}), True, ""),
    # --- key custody ---
    (
        "keySource=gcpKms with no keyVersion is refused",
        merged({"keySource": "gcpKms"}),
        False,
        "requires gcpKms.keyVersion",
    ),
    (
        "an unknown keySource is refused",
        merged({"keySource": "vault"}),
        False,
        "keySource must be",
    ),
    (
        "keySource=awsKms with no region is refused",
        merged({"keySource": "awsKms", "awsKms": {"keyId": "alias/k"}}),
        False,
        "requires awsKms.region",
    ),
    (
        "keySource=awsKms with no keyId is refused",
        merged({"keySource": "awsKms", "awsKms": {"region": "eu-north-1"}}),
        False,
        "requires awsKms.keyId",
    ),
    # The custody claim the chart exists to make is "no key material in the pod".
    # Under awsKms that holds only on the IRSA path, so the weaker one cannot be
    # reached by leaving a boolean at a convenient value.
    (
        "awsKms static credentials are refused unless deliberately accepted",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/k",
                           "useWebIdentity": False,
                           "credentialsSecretName": "aws-creds"}}),
        False,
        "LONG-LIVED IAM key pair",
    ),
    (
        "accepted awsKms static credentials still need the Secret naming them",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/k",
                           "useWebIdentity": False,
                           "allowStaticCredentials": True,
                           "credentialsSecretName": ""}}),
        False,
        "requires awsKms.credentialsSecretName",
    ),
    # Without the annotation EKS injects no AWS_ROLE_ARN and the proxy fails closed
    # at startup: a CrashLoop that says nothing about the missing annotation.
    (
        "awsKms IRSA without the role-arn annotation is refused",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/k",
                           "useWebIdentity": True}}),
        False,
        "eks.amazonaws.com/role-arn",
    ),
]
