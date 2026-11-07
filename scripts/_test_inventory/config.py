# SPDX-License-Identifier: Apache-2.0
"""Where the gate reads from, how it recognises a test, and the lanes allowed to hold one apart."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))

TEST_ATTR = re.compile(r"^\s*#\[(?:tokio::)?test\b")

#: Tests a non-manual binary does not list, each with the lane that does run them.
ALLOWED: dict[str, str] = {
    "mcp-re-proxy tests/tls_load_harness_bench.rs#*":
        "LANE: `manual` because its tests start a Docker Redis fleet; ci.yml's release-gates "
        "job runs it (`Release gate — load harness`), and :tls_load_harness_bench_builds "
        "compiles it on every `bazel test //...`",
    "mcp-re-proxy tests/gcp_kms_live_test.rs#*":
        "LANE: `manual` live-cloud suite; cloud-kms-live.yml runs it against a real GCP KMS",
}
