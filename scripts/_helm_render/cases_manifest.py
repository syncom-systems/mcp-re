# SPDX-License-Identifier: Apache-2.0
"""Pod-spec cases: the fields the argv cannot express."""

from __future__ import annotations

from _helm_render.render import merged

# (name, values, YAML lines that MUST appear, YAML lines that must NOT appear)
#
# Pod-spec posture rather than argv: these are fields, not flags, so `container_args`
# cannot see them. Compared as whole stripped lines so indentation changes do not
# make a nested field pass for a top-level one.
MANIFEST_CASES: list[tuple[str, dict, list[str], list[str]]] = [
    # The pod holds the response-signing seed and the TLS private key and calls no
    # Kubernetes API. Asserted on BOTH objects: the ServiceAccount field is what a
    # reviewer reads, the pod-spec field is what still governs when an existing
    # account is reused with serviceAccount.create=false.
    (
        "the apiserver token is not automounted, on either object",
        merged(),
        ["automountServiceAccountToken: false"],
        [],
    ),
    (
        "the pod spec refuses the token even when the ServiceAccount is not created",
        merged({"serviceAccount": {"create": False, "name": "existing-sa"}}),
        ["automountServiceAccountToken: false"],
        ["kind: ServiceAccount"],
    ),
    # An attacker with code execution in the key-holding container is confined to
    # memory rather than able to stage tooling on the writable layer.
    (
        "the proxy container filesystem is read-only",
        merged(),
        ["readOnlyRootFilesystem: true"],
        [],
    ),
    (
        "retention gets the pod's only writable path, and it is bounded",
        merged({"retainedEvidence": {"dir": "/var/lib/mcp-re/retained", "sizeLimit": "2Gi"}}),
        ["readOnlyRootFilesystem: true", "- name: retained-evidence",
         "mountPath: \"/var/lib/mcp-re/retained\"", "emptyDir:", "sizeLimit: \"2Gi\""],
        [],
    ),
    (
        "no retention means no volume to write to",
        merged(),
        [],
        ["- name: retained-evidence", "emptyDir:"],
    ),
]
