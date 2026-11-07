# SPDX-License-Identifier: Apache-2.0
"""Rendered-argv cases: key custody, replay tuning, admission currency and retention."""

from __future__ import annotations

from _helm_render.render import merged

# (name, values, args that MUST appear as an adjacent pair, args that must NOT appear)
CUSTODY_ARGV_CASES: list[tuple[str, dict, list[tuple[str, str]], list[str]]] = [
    (
        "gcpKms custody never passes a signing-key seed",
        merged({"keySource": "gcpKms",
                "gcpKms": {"keyVersion": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                           "useMetadata": True, "endpoint": "", "tlsKeyVersion": "",
                           "accessTokenSecretName": ""}}),
        [("--key-source", "gcp-kms")],
        ["--signing-key-seed"],
    ),
    (
        "file custody does pass the signing-key seed",
        merged(),
        [("--key-source", "file")],
        [],
    ),
    (
        "delegated TLS custody omits the exported TLS key",
        merged({"keySource": "gcpKms",
                "gcpKms": {"keyVersion": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                           "tlsKeyVersion": "projects/p/locations/l/keyRings/r/cryptoKeys/t/cryptoKeyVersions/1",
                           "useMetadata": True, "endpoint": "", "accessTokenSecretName": ""}}),
        [("--gcp-kms-tls-key-version",
          "projects/p/locations/l/keyRings/r/cryptoKeys/t/cryptoKeyVersions/1")],
        ["--tls-key"],
    ),
    # The awsKms twins of the three gcpKms cases above. The seed one is the reason
    # the "is this KMS custody" question moved into a helper: asked per-cloud, the
    # awsKms path would have kept mounting a seed the proxy never reads.
    (
        "awsKms IRSA custody renders the web-identity flag and no signing-key seed",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/mcp-re",
                           "useWebIdentity": True},
                "serviceAccount": {"create": True, "name": "",
                                   "annotations": {"eks.amazonaws.com/role-arn":
                                                   "arn:aws:iam::455880745808:role/mcp-re"}}}),
        [("--key-source", "aws-kms"),
         ("--aws-kms-region", "eu-north-1"),
         ("--aws-kms-key-id", "alias/mcp-re"),
         "--aws-kms-use-web-identity"],
        ["--signing-key-seed"],
    ),
    (
        "awsKms delegated TLS omits the exported TLS key",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/mcp-re",
                           "tlsKeyId": "alias/mcp-re-tls", "useWebIdentity": True},
                "serviceAccount": {"create": True, "name": "",
                                   "annotations": {"eks.amazonaws.com/role-arn":
                                                   "arn:aws:iam::455880745808:role/mcp-re"}}}),
        [("--aws-kms-tls-key-id", "alias/mcp-re-tls")],
        ["--tls-key"],
    ),
    (
        "accepted awsKms static credentials do NOT render the web-identity flag",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/mcp-re",
                           "useWebIdentity": False,
                           "allowStaticCredentials": True,
                           "credentialsSecretName": "aws-creds"}}),
        [("--key-source", "aws-kms")],
        ["--aws-kms-use-web-identity", "--signing-key-seed"],
    ),
    # Ruling 12 item 21. Unset must leave the proxy's own default in force rather than render
    # a zero that would read as a declared "the replicas share one clock"; zero is a real
    # declaration and must still render.
    (
        "an unset replay clock divergence renders no flag",
        merged(),
        [("--replay-durability-tier", "redis-wait-quorum:2:2000")],
        ["--replay-clock-divergence-secs"],
    ),
    (
        "a declared replay clock divergence renders, including zero",
        merged({"replay": {"clockDivergenceSecs": 12}}),
        [("--replay-clock-divergence-secs", "12")],
        [],
    ),
    (
        "a declared zero replay clock divergence is rendered, not dropped as empty",
        merged({"replay": {"clockDivergenceSecs": 0}}),
        [("--replay-clock-divergence-secs", "0")],
        [],
    ),
    (
        "an unset replay pool size renders no flag: the proxy's default applies",
        merged(),
        [("--replay-redis-url", "rediss://mcp-re-redis:6379")],
        ["--replay-redis-pool-size"],
    ),
    (
        "a declared replay pool size renders beside the replay store it sizes",
        merged({"replay": {"poolSize": 32}}),
        [("--replay-redis-pool-size", "32")],
        [],
    ),
    # ADR-MCPRE-053 §7. "The guards refuse a bad config" is only half the property:
    # the chart previously rendered NO admission flag under any values at all, so
    # every chart-deployed fleet ran AdmissionKind::Off. The flag has to appear.
    (
        "no admissionCurrency means no admission flag at all",
        merged(),
        [],
        ["--admission", "--admission-authority-kid", "--admission-authority-pubkey",
         "--admission-redis-url", "--admission-allow-degraded",
         "--admission-degraded-bound-secs"],
    ),
    (
        "admission currency renders the mode and all four anchors",
        merged({"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379",
                                      "recordMaxAgeSecs": 60}}),
        [("--admission", "required"),
         ("--admission-authority-kid", "adm-1"),
         ("--admission-authority-pubkey", "cHVia2V5"),
         ("--admission-redis-url", "rediss://r:6379"),
         ("--admission-record-max-age-secs", "60")],
        # Degraded serving is opt-in; leaving it unset must not render a bound that
        # would read as an authorised window.
        ["--admission-allow-degraded", "--admission-degraded-bound-secs"],
    ),
    (
        "a bounded degraded window renders both flags together",
        merged({"admissionCurrency": {"mode": "optional", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379",
                                      "recordMaxAgeSecs": 60,
                                      "allowDegraded": True, "degradedBoundSecs": 30}}),
        [("--admission", "optional"),
         ("--admission-allow-degraded", "true"),
         ("--admission-degraded-bound-secs", "30"),
         # The two windows are different facts and both are rendered. P bounds serving
         # while the authority is UNREACHABLE; the record budget bounds how old a signed
         # record may be while the store is answering.
         ("--admission-record-max-age-secs", "60")],
        [],
    ),
    # SCT-2 / SCT-3 retention. The flag is only half of it — with
    # readOnlyRootFilesystem set, a rendered path with no writable volume under it
    # is a proxy that fails on its first write.
    (
        "no retainedEvidence.dir means no retention flag",
        merged(),
        [],
        ["--retained-evidence-dir"],
    ),
    (
        "retainedEvidence.dir renders the retention flag",
        merged({"retainedEvidence": {"dir": "/var/lib/mcp-re/retained", "sizeLimit": "2Gi"}}),
        [("--retained-evidence-dir", "/var/lib/mcp-re/retained")],
        [],
    ),
]
