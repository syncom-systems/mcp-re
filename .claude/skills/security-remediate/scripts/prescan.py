#!/usr/bin/env python3
"""Stage-1 deterministic structural pre-scan — POLYGLOT and ROLE-AWARE.

NOT a vulnerability scanner. It asserts the *structural floor* a codebase must
clear before a full multi-agent security audit is worth its tokens, and it does
so for both Python and Rust, applying each check only where the file's ROLE makes
it meaningful. Language-aware is not enough: a Rust library legitimately defines
types its downstream consumers construct ("exists but not wired here" is not a
defect), whereas a Rust binary/proxy/demo that serves requests without a
verification path is the analogue of "FastAPI app with no auth middleware" — a
BLOCK.

Pipeline:
  classify language  ->  classify role  ->  language+role-specific checks  ->  one GO/NO-GO

Roles: library | binary | comproot | adapter | demo | test | generated | migration | script

Checks (role-sensitive):
  Rust, any production file:
    - todo!() / unimplemented!() on a production path                         BLOCK
    - unsafe (unless allowlisted)                                             BLOCK
    - panic/unwrap/expect/assert in a SECURITY-path file (unless allowlisted) BLOCK
  Rust binary / comproot / demo crate:
    - serving surface (TcpListener/serve/accept) with no verification call    BLOCK
    - a Noop/Null/InMemory security impl wired in the binary's comproot        BLOCK
  Rust library crate:
    - a security struct/impl never constructed in-repo                        advisory
  Python SERVICE (has a composition root or HTTP surface):
    - dead-wired orchestration class / not-in-comproot long-runner           BLOCK
    - Noop/Null impl wired in the composition root                            BLOCK
    - HTTP endpoints with no inbound auth wired                               BLOCK
    - NotImplementedError-only methods                                        warn
  Python LIBRARY (no comproot, no endpoints): dead-wiring downgraded to advisory.
  Tests / generated / migrations / scripts: excluded from production checks.

Deterministic, stdlib-only, zero LLM cost. HEURISTICS with false positives — a
NO-GO is decisive; a GO means "audit-ready", never "secure". Confirm every finding
from source before asserting it.

Allowlist (for the strict unsafe / panic / serve-without-verify blocks):
  - inline: a comment containing `prescan-allow: <kind>` on the offending line;
  - file:   --allow <json> mapping kind -> list of substrings (file path or symbol)
            to suppress, e.g. {"unsafe": ["sandbox_linux.rs"], "panic": []}.

Usage:
  python3 prescan.py <dir> [--json <out.json>] [--allow <allow.json>]
"""

import os
import sys

# Sibling helper modules live beside this script, which may be loaded by path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _prescan_allow import Allowlist, load_allow  # noqa: E402,F401
from _prescan_classify import (  # noqa: E402,F401
    base_role, is_test_path, language, python_role)
from _prescan_crate import (  # noqa: E402,F401
    crate_info, find_crate_root, rust_role)
from _prescan_cli import main  # noqa: E402
from _prescan_python import python_pass  # noqa: E402,F401
from _prescan_rust import rust_pass  # noqa: E402,F401
from _prescan_rust_text import (  # noqa: E402,F401
    enclosing_fn, line_of, line_text, mask_const_eval, rust_prod_slice)
from _prescan_vocab import *  # noqa: E402,F401,F403

if __name__ == "__main__":
    sys.exit(main())
