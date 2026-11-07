# SPDX-License-Identifier: Apache-2.0
"""Rendered-argv cases: admission, capacity, trust and revocation flags."""

from __future__ import annotations

from _helm_render.render import merged

# (name, values, args that MUST appear as an adjacent pair, args that must NOT appear)
FLAG_ARGV_CASES: list[tuple[str, dict, list[tuple[str, str]], list[str]]] = [
    (
        "unset admission ceilings omit both flags",
        merged(),
        [],
        ["--max-in-flight", "--max-in-flight-total"],
    ),
    (
        "maxInFlight renders the per-core flag only",
        merged({"admission": {"maxInFlight": 32, "maxInFlightTotal": ""}}),
        [("--max-in-flight", "32")],
        ["--max-in-flight-total"],
    ),
    (
        "maxInFlightTotal renders the fleet-wide flag only",
        merged({"admission": {"maxInFlight": "", "maxInFlightTotal": 256}}),
        [("--max-in-flight-total", "256")],
        ["--max-in-flight"],
    ),
    # The handshake-signing capacity has no chart default: unset must leave the
    # proxy's, and a set value must reach the proxy verbatim — 0 included, which the
    # proxy refuses. A truthiness test would turn that 0 into the default silently.
    (
        "unset handshake-signing capacity omits both flags",
        merged(),
        [],
        ["--tls-handshake-sign-rate", "--tls-handshake-sign-burst"],
    ),
    (
        "handshake-signing capacity renders both flags verbatim",
        merged({"tlsHandshakeSigning": {"ratePerSec": 250, "burst": 400}}),
        [("--tls-handshake-sign-rate", "250"), ("--tls-handshake-sign-burst", "400")],
        [],
    ),
    (
        "a zero handshake-signing term reaches the proxy rather than the default",
        merged({"tlsHandshakeSigning": {"ratePerSec": 0, "burst": None}}),
        [("--tls-handshake-sign-rate", "0")],
        ["--tls-handshake-sign-burst"],
    ),
    # The continuation live-entry bound follows the same rule: no chart default, and a
    # set value — 0 included, which the proxy refuses — reaches the proxy verbatim.
    (
        "unset continuation bound omits the flag",
        merged(),
        [],
        ["--continuation-max-live-entries"],
    ),
    (
        "a continuation bound renders verbatim",
        merged({"continuationControl": {"redisUrl": "rediss://r:6379",
                                        "maxLiveEntries": 5000}}),
        [("--continuation-max-live-entries", "5000")],
        [],
    ),
    (
        "a zero continuation bound reaches the proxy rather than the default",
        merged({"continuationControl": {"redisUrl": "rediss://r:6379", "maxLiveEntries": 0}}),
        [("--continuation-max-live-entries", "0")],
        [],
    ),
    # The proxy refuses the example.com trust domain itself, so the chart's fenced-fixture
    # acknowledgement must reach it as a flag — and only when given.
    (
        "the fixture acknowledgement is omitted by default",
        merged(),
        [],
        ["--allow-example-fixtures"],
    ),
    (
        "allowExampleFixtures renders the proxy's fixture acknowledgement",
        merged({"identity": {"trustDomain": "example.com", "allowExampleFixtures": True}}),
        [("--trust-domain", "example.com"), "--allow-example-fixtures"],
        [],
    ),
    # ADR-MCPS-035: a chart-rendered pod must carry the per-request security record,
    # and the revocation flags the posture claims must actually be emitted.
    (
        "the audit sink and revocation bounds are rendered by default",
        merged(),
        [("--audit-sink", "stderr"), ("--audit-commitment", "best-effort"),
         ("--max-connection-age-secs", "300"), ("--drain-grace-secs", "30")],
        ["--verified-context-carrier"],
    ),
    (
        "the trust reload cadence is rendered by default",
        merged(),
        [("--trust-reload-secs", "60")],
        [],
    ),
    (
        "clientCrl paths render the CRL flags",
        merged({"clientCrl": {"paths": ["/etc/mcp-re/client-crl.pem"], "reloadSeconds": 300}}),
        [("--client-crl", "/etc/mcp-re/client-crl.pem"),
         ("--client-crl-reload-secs", "300")],
        [],
    ),
    (
        "no CRL paths means no CRL flags at all",
        merged({"clientCrl": {"paths": [], "reloadSeconds": 300}}),
        [],
        ["--client-crl", "--client-crl-reload-secs"],
    ),
    (
        "the trusted verified-context carrier is opt-in and rendered when asked",
        merged({"verifiedContextCarrier": "trusted"}),
        [("--verified-context-carrier", "trusted")],
        [],
    ),
]
