# SPDX-License-Identifier: Apache-2.0
"""The owner module, the reviewed spawn sites, and the spelling the gate looks for."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))

# The one module allowed to start a thread: it is the thing that owns them.
OWNER_MODULE = "src/managed_worker/mod.rs"

# Every thread in the system that is not started through `WorkerSet`, and why it is
# sound. Two kinds appear here and they are not equivalent:
#
#   - satisfies §9 by hand: the handle IS owned and joined, just not by `WorkerSet`
#     (the fleet, the retention writer, the anchor refresher)
#   - out of §9's scope: a per-connection, per-operation or per-process thread whose
#     lifetime is not a runtime's (the signal bridges, the connection handlers, the
#     audit writer)
#
# Adding an entry is a decision, and the asymmetry is the point: an existing entry has
# to stay explainable, a new one has to argue for itself.
#
# Each entry is (site count, reason), and the count is load-bearing: the reason justifies
# a NAMED thread, so a file-granular exemption would let the serving and evidence paths
# acquire further detached threads for free. The count is what makes a second spawn in an
# exempt file a gate failure that has to be argued rather than a silent pass.
#
# An allowance follows its SITE, not the path it was written at. When MCPRE-175 split three
# of these files into owner subtrees the reviewed spawns moved with their owners — the
# client's shutdown bridge to `startup.rs`, its per-connection handler to `serve/mod.rs`,
# the retention writer to `transparency/durability.rs`, and later to its own
# `transparency/writer_thread.rs` (EX-019) — and each entry was re-pointed at
# the exact new file with its count and reason unchanged. Nothing was widened to a
# directory: a subtree-granular allowance would let a sibling acquire a detached thread for
# free, which is the same defect as a file-granular one one level up. The gate reports a
# stale entry as loudly as a new spawn ("allowlisted for N ... but has 0"), which is what
# made the three moves visible rather than silently permissive.
ALLOWED = {
    "mcp-re-proxy/src/signing_plane/bounded_root_issuer.rs": (1, (
        "the root-issuer call worker is a PER-CALL timeout thread, not a runtime worker: the "
        "caller waits on it for at most the call bound, and the in-flight flag it holds "
        "refuses a second call while an abandoned one is still running, so at most one is "
        "ever outstanding"
    )),
    "mcp-re-client/src/startup.rs": (1, (
        "the client binary's SIGTERM bridge, the same process-lifetime signal thread as "
        "the proxy's — it belongs to the process, not to a runtime"
    )),
    "mcp-re-proxy/src/audit_sink/writer.rs": (1, (
        "the stderr audit writer drains a `static` OnceLock channel and is scoped to the "
        "PROCESS by construction; there is no runtime whose lifetime it could take"
    )),
    "mcp-re-proxy/src/transparency/writer_thread.rs": (1, (
        "the retention writer already satisfies §9 by hand: `WriterThread` owns the "
        "handle, closing the job channel is its halt, and `Drop` joins it"
    )),
    "mcp-re-proxy/src/async_fleet/mod.rs": (1, (
        "the per-core serving threads satisfy §9 by hand: their handles are `Fleet.workers` "
        "and `Fleet::shutdown_and_join` stops and joins every one of them"
    )),
    "mcp-re-client/src/anchors/refresher.rs": (1, (
        "the anchor-refresh thread's handle is owned by the refresher it belongs to, which "
        "sets its stop flag and joins on drop"
    )),
    "mcp-re-client/src/serve/mod.rs": (1, (
        "the client's per-connection handler lives as long as one connection; its capacity "
        "slot is released by the same destructor on success, unwind, and spawn failure"
    )),
}

# Both spellings that start an OS thread. `Builder` is not a hypothetical bypass: two
# production sites already used it, and a gate that watched only `thread::spawn` would
# have reported a clean tree over them.
SPAWN = re.compile(r"\bthread\s*::\s*(?:spawn\b|Builder\b)")
