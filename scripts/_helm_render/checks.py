# SPDX-License-Identifier: Apache-2.0
"""The registry of text checks and the files they read."""

from __future__ import annotations

from _helm_render.config import TABLE_RELATIVE
from _helm_render.text_documented import (
    check_audit_commitment_enumeration,
    check_audit_flush_budget,
    check_documented_continuation_bound,
    check_documented_handshake_signing_bounds,
    check_documented_in_flight_default,
)
from _helm_render.text_image import (
    check_image_declares_non_root,
    check_image_serves_every_key_source,
)

#: The checks that read the tree's text rather than a render, by what each asserts.
TEXT_CHECKS = (
    ("the default image serves every offered keySource", check_image_serves_every_key_source),
    ("the proxy image declares the chart's non-root uid", check_image_declares_non_root),
    ("the documented in-flight default is the code's", check_documented_in_flight_default),
    ("the documented handshake-signing capacity is the code's",
     check_documented_handshake_signing_bounds),
    ("the documented continuation bound is the code's", check_documented_continuation_bound),
    ("the drain arithmetic budgets the code's audit flush", check_audit_flush_budget),
    ("the chart's audit deliveries are the parser's", check_audit_commitment_enumeration),
)

#: The files the text checks read, repository-relative.
TEXT_INPUTS = (
    "deploy/docker/Dockerfile",
    "deploy/helm/mcp-re-proxy/values.yaml",
    "deploy/helm/mcp-re-proxy/templates/deployment.yaml",
    "deploy/helm/mcp-re-proxy/templates/_helpers.tpl",
    "mcp-re-proxy/src/config_state/in_flight_limit.rs",
    "mcp-re-proxy/src/delegated_tls/sign_capacity.rs",
    "mcp-re-proxy/src/continuation_store/capacity.rs",
    "mcp-re-proxy/src/audit_sink/drain.rs",
    "mcp-re-proxy/src/cli/audit_flags.rs",
    "scripts/stage_image_binaries.sh",
    TABLE_RELATIVE,
)
