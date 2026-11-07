# SPDX-License-Identifier: Apache-2.0
"""Running the tool: discover the key, guard the overwrite, write the pin, say what it means."""

from __future__ import annotations

import hashlib
import json
import os

from _scitt_pin import keys
from _scitt_pin.fetch import fetch
from _scitt_pin.pin import Discovered, build_pin, replaced_pin_fields


def _cose_discovery(document: bytes, uri: str, args) -> tuple:
    decoded = keys.cbor2().loads(document)
    # A COSE_Key Set is an array of COSE_Key maps; some services wrap it in a map
    # under a "keys" label.
    entries = decoded if isinstance(decoded, list) else decoded.get("keys") or decoded.get(1)
    if not isinstance(entries, list):
        raise SystemExit(f"{uri} did not return a COSE_Key Set")

    def kid_of(entry):
        raw = entry.get(keys.KID)
        return raw.decode(errors="replace") if isinstance(raw, bytes) else raw

    entry, kid = keys.select(entries, args.kid, args.any_single_key, kid_of)
    return kid, keys.key_from_cose(entry)


def _jwk_discovery(document: bytes, args) -> tuple:
    entries = (
        keys.did_verification_keys(document)
        if args.method == "did-web"
        else json.loads(document).get("keys", [])
    )
    entry, kid = keys.select(entries, args.kid, args.any_single_key, lambda e: e.get("kid"))
    return kid, keys.key_from_jwk(entry)


def discovery_uri(args) -> str:
    if args.method == "well-known-scitt-keys":
        return args.service_uri.rstrip("/") + "/.well-known/scitt-keys"
    return args.service_uri


def discover(args) -> Discovered:
    uri = discovery_uri(args)
    document = fetch(uri)
    # The digest is over the EXACT bytes fetched, so a later reader can tell whether the
    # document it gets is the one this pin was cut from.
    digest = keys.b64u(hashlib.sha256(document).digest())
    if args.method == "well-known-scitt-keys":
        kid, fields = _cose_discovery(document, uri, args)
    else:
        kid, fields = _jwk_discovery(document, args)
    return Discovered(kid, fields, uri, digest)


def _refuse_unacknowledged_replacement(args, pin: dict) -> None:
    if not os.path.exists(args.out) or args.replace_pin:
        return
    with open(args.out, encoding="utf-8") as handle:
        existing = json.load(handle)
    changed = replaced_pin_fields(existing, pin)
    if changed:
        raise SystemExit(
            f"{args.out} already pins a different {', '.join(changed)}; refusing to "
            "overwrite it. Pass --replace-pin to replace it deliberately, having "
            "confirmed the new values out of band."
        )


def _refuse_unconfirmed_key(args, found: Discovered) -> None:
    thumbprint = found.fields["thumbprint"]
    if args.expect_thumbprint and args.expect_thumbprint != thumbprint:
        raise SystemExit(
            f"fetched key thumbprint {thumbprint} does not match the expected "
            f"{args.expect_thumbprint}: refusing to write a pin for a key nobody confirmed."
        )


def _write(path: str, pin: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(pin, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _report(pin: dict, found: Discovered, out: str) -> None:
    print(f"pinned {found.fields['algorithm']} key kid={pin['kid']!r}")
    print(f"  thumbprint  {found.fields['thumbprint']}")
    print(f"  from        {found.uri}")
    print(f"  doc digest  {found.document_digest}")
    print(f"  written to  {out}")
    print(f"  leaf        {pin['leaf_profile']}")
    print(f"  position    {pin['position_profile']}")
    if pin["position_profile"] == "unbound":
        print("\nWARNING: pinned UNBOUND. Receipts from this service are accepted without a")
        print("position commitment, so tree_size and leaf_index stay unauthenticated hints:")
        print("a relayer may restate this receipt at another position and it still verifies.")
        print("Use --position-profile bound for a service whose receipts carry one.")
    print("\nThis records WHICH key was used. It is not a statement that the service is")
    print("trustworthy, that its log is append-only, or that its operator is independent.")


def run(args) -> int:
    found = discover(args)
    pin = build_pin(args, found)
    _refuse_unacknowledged_replacement(args, pin)
    _refuse_unconfirmed_key(args, found)
    _write(args.out, pin)
    _report(pin, found, args.out)
    return 0
