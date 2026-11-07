# SPDX-License-Identifier: Apache-2.0
"""The command line: every flag, and the two profile flags that have no default."""

from __future__ import annotations

import argparse

from _scitt_pin.pin import LEAF_PROFILES, POSITION_PROFILES


def _add_profile_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--position-profile", choices=POSITION_PROFILES, required=True,
                    help="whether this service's receipts MUST carry a position "
                         "commitment. 'bound' refuses a receipt without one; 'unbound' "
                         "is the pre-v2 contract, under which tree_size and leaf_index "
                         "are unauthenticated hints a relayer may restate. Required "
                         "because the verifier refuses a pin that does not state it, "
                         "and the choice is the operator's to make.")
    ap.add_argument("--leaf-profile", choices=LEAF_PROFILES, required=True,
                    help="which bytes this service's log hashes as the Merkle entry: the "
                         "Signed Statement's own octets or a digest of them. Required "
                         "because it cannot be inferred from a receipt and the verifier "
                         "refuses a pin that does not state it.")


def build_parser(description: str | None) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--service-uri", required=True, help="service base URI, or the full JWKS URI")
    ap.add_argument("--method", choices=("well-known-scitt-keys", "jwks", "did-web"),
                    default="well-known-scitt-keys")
    ap.add_argument("--kid", help="the kid the receipt names")
    ap.add_argument("--any-single-key", action="store_true",
                    help="accept the only key in the set when receipts carry no kid")
    ap.add_argument("--service-identifier", help="how this deployment names the service")
    ap.add_argument("--out", required=True, help="where to write the pin")
    ap.add_argument("--expect-thumbprint",
                    help="the RFC 9679 COSE key thumbprint confirmed OUT OF BAND; the fetch "
                         "is refused unless it matches. Without it the pin is trust-on-first-use "
                         "and the network chose the key.")
    ap.add_argument("--replace-pin", action="store_true",
                    help="allow overwriting an existing pin that differs in key, leaf "
                         "profile or position profile")
    _add_profile_arguments(ap)
    return ap
