#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch a transparency service's verification key once, and pin it (MCPRE-501 slice 2).

Offline receipt verification needs the service's public key, and fetching it at verify
time would destroy the property being claimed — a verifier that calls the service is not
verifying offline, and an auditor holding only archived bytes could not reproduce it. So
discovery happens ONCE, here, and writes a `ScittServiceTrustPinV1` artifact that the
verifier consumes with no network at all. `mcp-re-http-profile` is a pure crate; this is
why the fetch is a tool and not a function in it.

**What the pin proves.** Exactly which key a run verified against, and where it came
from. Nothing more. It does not say the service is honest, that its log is append-only,
or that its operator is independent of us — a pinned key from a malicious service is
still a pinned key. Its value is that the interoperability result becomes reproducible
and falsifiable instead of resting on a key nobody wrote down.

Supported discovery:
  * `well-known-scitt-keys` — SCRAPI `GET /.well-known/scitt-keys`, a CBOR COSE_Key Set.
  * `jwks` — `GET <uri>`, an RFC 7517 JWK Set, for services that expose JOSE discovery.
  * `did-web` — `GET <uri>`, a W3C DID document whose `verificationMethod` entries carry
    `publicKeyJwk`. Added for `capsule-anchor`, which publishes its authority key that way
    and no other. The DID document is read as a KEY SET and nothing more: no DID
    resolution, no `did:` URL dereferencing, no controller check. Those are claims about
    an identifier, and a pin is a record of one key at one moment — the tool must not look
    as though it established more than it fetched.

    pip install cbor2 requests
    python tools/scitt_fetch_service_key.py \
        --service-uri https://transparency.example --kid <kid> \
        --leaf-profile statement-bytes --position-profile bound --out service-key-pin.json

The `kid` should be the one the receipt names; pass `--any-single-key` for a service
whose key set holds exactly one key and whose receipts carry no `kid`.

**Why the profiles are arguments and not defaults.** A pin carries two properties of the
SERVICE that no receipt can be asked for, because the receipt is the value under attack:
which bytes the log hashes as its Merkle entry (`--leaf-profile`), and whether its
receipts commit to their own `(tree_size, leaf_index)` (`--position-profile`). The Rust
verifier refuses a pin that omits either, and both are required rather than defaulted:
each is a thing an operator has to have established about the service and written down.
Under `unbound` a relayer may restate a small log's receipt as a position in a larger
one and it still verifies; a wrong leaf profile makes every receipt from the service
fail to verify, or verify over bytes the log did not hash.

**Re-running against an existing pin.** The tool refuses to overwrite a pin whose key,
leaf profile or position profile differs from the one it would write, unless
`--replace-pin` is given. A same-key run that would downgrade `bound` to `unbound` is a
replacement like any other.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _scitt_pin.cli import build_parser  # noqa: E402
from _scitt_pin.command import run  # noqa: E402
from _scitt_pin.selftest import selftest  # noqa: E402


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return run(build_parser(__doc__).parse_args())


if __name__ == "__main__":
    sys.exit(main())
