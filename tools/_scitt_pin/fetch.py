# SPDX-License-Identifier: Apache-2.0
"""Fetching a discovery document over https only, on the first hop and on every redirect."""

from __future__ import annotations

import urllib.request


def refuse_scheme(uri: str, how: str) -> SystemExit:
    return SystemExit(
        f"refusing to fetch a trust pin over {uri.split(':', 1)[0]!r} ({how}): the pin "
        "records WHICH key was trusted, so an unauthenticated fetch lets whoever "
        "controls the network choose it. Use https://."
    )


def is_https(uri: str) -> bool:
    return uri.lower().startswith("https://")


class HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only while the target stays https.

    The scheme check on the URI the operator typed is not the check that matters:
    stdlib's default `HTTPRedirectHandler` accepts http, https and ftp targets, so a
    single 302 from the service restores exactly the plaintext leg the guard exists
    to prevent — and the key written into the pin is then whoever is on the path's
    choice. The redirect is where the scheme has to be re-checked, because it is the
    hop the operator never sees.
    """

    def redirect_request(self, req, *hop):
        # urllib calls this with (req, fp, code, msg, headers, newurl); the signature is
        # fixed by the base class.
        _fp, code, _msg, _headers, newurl = hop
        if not is_https(newurl):
            raise refuse_scheme(newurl, f"HTTP {code} redirect from {req.full_url}")
        return super().redirect_request(req, *hop)


def opener() -> urllib.request.OpenerDirector:
    """An opener that cannot leave https, on the first hop or any later one."""
    return urllib.request.build_opener(HttpsOnlyRedirectHandler)


def fetch(uri: str) -> bytes:
    """Fetch the key set over HTTPS only, redirects included.

    The pin is the ONE thing that says which key an interoperability run verified
    against, so whoever controls the network at pin time chooses that key. A bare
    `urlopen` with no scheme restriction accepted `http://` and `file://` — the first
    hands the choice to anyone on the path, the second to anyone who can drop a file
    where the operator points the tool.

    TLS is not a claim about the SERVICE (see the closing note the tool prints); it is
    what makes the pin a record of the key that service published rather than of the
    key an on-path party substituted.
    """
    if not is_https(uri):
        raise refuse_scheme(uri, "requested URI")
    with opener().open(uri, timeout=30) as response:  # noqa: S310 - checked above
        return response.read()
