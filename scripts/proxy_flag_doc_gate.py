#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CLI-flag documentation gate — a guide cannot teach a flag the CLI does not have.

WHAT THIS PROVES, exactly: every `--flag` appearing in a fenced code block that invokes
one of this workspace's executables is a flag THAT executable's parser actually accepts.
That is a syntactic check over the documentation and each tool's parser source, and the
claim stops there.

There are two tools, and they are checked against DIFFERENT parsers. `mcp-re-proxy` serves
and `mcp-re-auditor` reads what it retained; they share no flag vocabulary, so a gate that
pooled their flags would accept `--bind` in an auditor command line — a command that does
not run — while reporting green.

WHAT IT DOES NOT PROVE: that the flag's VALUE is accepted. `--authz reference`,
`--revocation-list <path>`, `--client-ocsp require`,
`--transport-binding lb-assertion|attested-ingress` and the two sub-strict
`--replay-durability-tier` values are all
spelled with flags that exist and are then refused by configuration validation, so a
command line built entirely from flags this gate accepts can still fail to start. Value
admissibility is `unsafe_config_violations`' business and is tested there.

Nor does it read prose: only fenced blocks that invoke the proxy. A paragraph may name a
removed flag in order to say it was removed, which is exactly what several guides do.

WHY IT EXISTS. `docs/sidecar-deployment-guide.md` — the current guide for the shipped
sidecar, not a superseded one — carried a worked command line passing `--authz reference`
and `--revocation-list`, neither of which starts, plus a flag table row
for `--allow-env-keysource`, which stopped existing in `0a99957`. An operator
following it gets a proxy that refuses to start and no reason to suspect the document. A
flag that was DELETED is the case this gate catches outright; a flag whose VALUE became
inadmissible is the case it cannot, which is why the limitation is stated above rather
than implied.

Run:  python3 scripts/proxy_flag_doc_gate.py
      python3 scripts/proxy_flag_doc_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _proxy_flag_doc.check import check  # noqa: E402,F401
from _proxy_flag_doc.cli import verdict  # noqa: E402
from _proxy_flag_doc.config import (  # noqa: E402,F401
    AUDITOR_MODULE,
    CLI_FLAG_LITERAL,
    CLI_MODULE,
    CLI_MODULE_DIR,
    DOC_ROOTS,
    FENCE,
    FLAG,
    LAUNCHER_FLAGS,
    MIN_SCANNED_DOCS,
    REPO,
    SKIP_PARTS,
    SKIP_PATTERNS,
    SUPERSEDED,
    SUPERSEDED_DOCS,
    TOOLS,
    Tool,
    launches,
)
from _proxy_flag_doc.scan import (  # noqa: E402,F401
    doc_files,
    documented_flags,
    is_superseded,
    known_flags,
)
from _proxy_flag_doc.selftest import selftest  # noqa: E402


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    return verdict()


if __name__ == "__main__":
    sys.exit(main())
