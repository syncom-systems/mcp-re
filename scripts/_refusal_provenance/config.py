# SPDX-License-Identifier: Apache-2.0
"""What the refusal-provenance gate reads: the units it measures and the sites it declares."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools" / "verification"))

REFUSAL = ["mcp-re-proxy/src/refusal/mod.rs", "mcp-re-proxy/src/refusal/cause.rs"]
#: The serving path. A DIRECTORY since MCPRE-175 split the assembly into one module per
#: region of the exchange: `authorization_stage` and most of the `Refusal::` construction
#: sites moved out of `mod.rs`, so a gate still reading that one file would find no stage
#: to poison-pill and no call sites to check — a clean pass over the subject.
SERVING = "mcp-re-proxy/src/http_profile_serve"
#: The record. A DIRECTORY since r11 W2-A gave the record's scalar spelling its own owner:
#: the type and the field composition stayed in `mod.rs` while `text.rs` and `scalar.rs`
#: carry the grammar, so a gate still reading that one file would be reading a subset of its
#: subject and calling it the whole.
RECORD = "mcp-re-proxy/src/audit_record"
CORE_AUDIT = "mcp-re-core/src/audit.rs"

#: The transport frame the async fleet serves through, and the module that owns the served
#: response type. Clause 12 reads both: the exchange lifecycle can only be shown total over
#: the refusal sites if the sites OUTSIDE it are enumerable, and these are where they live.
TRANSPORT = "mcp-re-proxy/src/async_serve/request.rs"

#: Every production call site of the one mint outside the exchange. A set rather than a
#: count, because "one site" is only reassuring if it is also the RIGHT site: a second
#: production caller anywhere would be a refusal reached with no exchange to place it in, and
#: this file is the pre-handler frame, where that is the whole point.
DECLARED_TRANSPORT_REFUSAL_SITES = {TRANSPORT}

#: The mint itself. Declared separately from its call sites so the definition module is not
#: mistaken for a caller.
SERVED_JSON = "ServedHttpResponse::json"

#: Where `ServedHttpResponse::json` is DEFINED. Not a refusal site.
SERVED_RESPONSE_OWNER = "mcp-re-proxy/src/async_serve/mod.rs"
