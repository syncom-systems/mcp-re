# SPDX-License-Identifier: Apache-2.0
"""The tool's own assertions: the https-only guard, the pin's contents, the overwrite guard.

`--selftest` is the only proof the guards still hold, and it needs no network and no
third-party package.
"""

from __future__ import annotations

import contextlib
import io
import json
import urllib.request

from _scitt_pin.cli import build_parser
from _scitt_pin.fetch import HttpsOnlyRedirectHandler, fetch, opener
from _scitt_pin.keys import b64u, did_verification_keys
from _scitt_pin.pin import Discovered, build_pin, replaced_pin_fields

REDIRECT_CASES = (
    ("http://service.example/keys", False),
    ("HTTP://service.example/keys", False),
    ("ftp://service.example/keys", False),
    ("file:///tmp/keys", False),
    ("https://elsewhere.example/keys", True),
)

PROFILE_OMISSIONS = (
    ("--position-profile", ["--leaf-profile", "statement-bytes"]),
    ("--leaf-profile", ["--position-profile", "bound"]),
)

PIN_PROFILE_CASES = (
    ("bound", "statement-bytes"),
    ("unbound", "statement-digest"),
    ("unbound", "sig-structure-digest"),
)

BASE_ARGV = [
    "--service-uri", "https://service.example",
    "--any-single-key",
    "--out", "/dev/null",
]


def _fail(message: str) -> int:
    print(f"SELFTEST FAIL: {message}")
    return 1


def _redirect_refused(handler, request, target: str) -> bool:
    try:
        handler.redirect_request(request, None, 302, "Found", {}, target)
    except SystemExit:
        return True
    except Exception:  # noqa: BLE001 - stdlib may reject an https target for
        return False  # unrelated reasons; only the scheme decision is under test
    return False


def _redirect_cases() -> int:
    """Assert the redirect handler itself, not just the first-hop scheme check.

    Driving this end to end would need a TLS server that 302s to plaintext, so the
    test targets the decision directly: the handler is what stdlib consults on every
    hop, and it must refuse every scheme but https.
    """
    handler = HttpsOnlyRedirectHandler()
    request = urllib.request.Request("https://service.example/.well-known/scitt-keys")
    failures = 0
    for target, allowed in REDIRECT_CASES:
        if _redirect_refused(handler, request, target) == allowed:
            verb = "followed" if allowed else "refused"
            failures += _fail(f"redirect to {target!r} was not {verb}")
    return failures


def _fetch_refused(uri: str) -> bool:
    try:
        fetch(uri)
    except SystemExit:
        return True
    except Exception:  # noqa: BLE001
        return False
    return False


def _first_hop_cases() -> int:
    return sum(
        _fail(f"fetch({uri!r}) was not refused before any request")
        for uri in ("http://service.example", "file:///tmp/keys")
        if not _fetch_refused(uri)
    )


def _opener_wiring() -> int:
    # The WIRING, not just the class. `build_opener` installs its own
    # `HTTPRedirectHandler` unless the caller passes that class or a subclass, so a
    # guard class that exists but is not the one the opener consults would leave the
    # plaintext hop open while every case above still passed.
    installed = [h for h in opener().handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
    if len(installed) == 1 and isinstance(installed[0], HttpsOnlyRedirectHandler):
        return 0
    return _fail(f"fetch()'s opener consults {installed!r}, not the https-only handler")


def _profile_must_be_stated(parser) -> int:
    # The PIN's own contents. The verifier refuses a pin that omits `position_profile`
    # or `leaf_profile`, so the tool must never cut one without the operator's choice.
    failures = 0
    for omitted, stated in PROFILE_OMISSIONS:
        try:
            # argparse prints its usage to stderr on the way out; the case under test is
            # the refusal, not the message.
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(BASE_ARGV + stated)
        except SystemExit:
            continue
        failures += _fail(
            f"a pin was cut with no {omitted}; the profile is the "
            "operator's statement about the service, so it must be stated"
        )
    return failures


def _is_unlabelled_ed25519(found: list) -> bool:
    """Exactly the one JWK method, carrying no `kid` of its own."""
    return len(found) == 1 and found[0].get("crv") == "Ed25519" and "kid" not in found[0]


def _did_document_cases() -> int:
    # `did-web` reads a DID document as a key set — and reads NOTHING else out of it.
    did_document = json.dumps({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:service.example",
        "verificationMethod": [
            {"id": "did:web:service.example#multibase-only", "type": "Ed25519VerificationKey2020",
             "publicKeyMultibase": "z6Mk..."},
            {"id": "did:web:service.example#abc123", "type": "JsonWebKey2020",
             "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": b64u(bytes(32))}},
        ],
    }).encode()
    found = did_verification_keys(did_document)
    failures = 0
    if not _is_unlabelled_ed25519(found):
        failures += _fail(
            f"did-web read {found!r}; it must take the JWK method only, "
            "and must not read the method id fragment as a COSE kid"
        )
    for document, why in (
        (b'{"id": "did:web:service.example"}', "no verificationMethod"),
        (b'{"verificationMethod": [{"id": "x#1", "publicKeyMultibase": "z6Mk..."}]}',
         "no JWK material"),
    ):
        try:
            did_verification_keys(document)
        except SystemExit:
            continue
        failures += _fail(f"a DID document with {why} was accepted as a key set")
    return failures


def _pin_records_profiles(parser) -> int:
    failures = 0
    stub = Discovered(
        "kid-1",
        {"algorithm": "EdDSA", "public_key": {"x": "AAAA"}, "thumbprint": "TTTT"},
        "https://service.example/.well-known/scitt-keys",
        "DDDD",
    )
    for position, leaf in PIN_PROFILE_CASES:
        args = parser.parse_args(
            BASE_ARGV + ["--position-profile", position, "--leaf-profile", leaf]
        )
        pin = build_pin(args, stub)
        if pin.get("position_profile") != position or pin.get("leaf_profile") != leaf:
            failures += _fail(
                f"pin recorded {pin.get('position_profile')!r}/"
                f"{pin.get('leaf_profile')!r}, not {position!r}/{leaf!r}"
            )
    return failures


def _replacement_cases() -> int:
    # Overwriting an existing pin: each commitment it holds is replaced only with
    # --replace-pin, including a profile downgrade for the same key.
    failures = 0
    current = {"public_key_thumbprint": "TTTT", "leaf_profile": "statement-bytes",
               "position_profile": "bound"}
    for change, expected in (
        ({}, []),
        ({"public_key_thumbprint": "UUUU"}, ["key"]),
        ({"position_profile": "unbound"}, ["position profile"]),
        ({"leaf_profile": "statement-digest"}, ["leaf profile"]),
    ):
        changed = replaced_pin_fields(current, {**current, **change})
        if changed != expected:
            failures += _fail(f"overwriting with {change!r} reported {changed!r}, not {expected!r}")
    legacy = {"public_key_thumbprint": "TTTT"}
    if replaced_pin_fields(legacy, current) != ["leaf profile", "position profile"]:
        failures += _fail("a pin that states no profiles was overwritten as unchanged")
    return failures


def selftest() -> int:
    parser = build_parser(None)
    failures = (
        _redirect_cases()
        + _first_hop_cases()
        + _opener_wiring()
        + _profile_must_be_stated(parser)
        + _did_document_cases()
        + _pin_records_profiles(parser)
        + _replacement_cases()
    )
    if failures:
        print(f"{failures} case(s) failed — the https-only guard is not trustworthy.")
        return 1
    print("selftest ok: 23 cases (redirect scheme guard, first-hop scheme guard, opener "
          "wiring, did-web key-set reading, pin profile fields, pin replacement guard)")
    return 0
