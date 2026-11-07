# SPDX-License-Identifier: Apache-2.0
"""A miniature graph with every construct that previously confused the scanner."""

from __future__ import annotations

from _module_map.graph import code_only, edges_for

SAMPLE = "\n".join(
    [
        "//! Module doc mentioning [`crate::cli::DeploymentRequest`] as an intra-doc link.",
        "use crate::cli;",
        "use crate::tls::ServerLimits;",
        "impl Thing {",
        "    #[cfg(test)]",
        "    fn helper() -> u8 { 1 }",  # inline attribute, mid-file
        "}",
        "/// Doc link to [`crate::trust_plane::Thing`] — a reference, not a dependency.",
        "fn production(c: &cli::DeploymentRequest) -> &str {",
        '    let _ = "crate::evidence::AuditSink";',  # a path inside a string
        "    // crate::replay_plane::Plan in a comment",
        "    ServerLimits::NAME",
        "}",
        "#[cfg(test)]",
        "mod tests {",
        "    use crate::signing_plane;",
        "    fn t() -> signing_plane::Thing { todo!() }",
        "}",
    ]
)
KNOWN = {"cli", "tls", "trust_plane", "evidence", "replay_plane", "signing_plane"}


def _checks(got: dict[str, set[str]]) -> list[tuple[bool, str]]:
    return [
        (
            "cli" in got and "DeploymentRequest" in got["cli"],
            "a bare `use crate::cli;` plus `cli::DeploymentRequest` AFTER an inline #[cfg(test)]",
        ),
        (
            "tls" in got and "ServerLimits" in got["tls"],
            "a qualified `use crate::tls::ServerLimits;`",
        ),
        ("trust_plane" not in got, "a rustdoc intra-doc link must NOT be an edge"),
        ("evidence" not in got, "a path inside a string literal must NOT be an edge"),
        ("replay_plane" not in got, "a path inside a comment must NOT be an edge"),
        ("signing_plane" not in got, "a dependency used only by #[cfg(test)] code"),
    ]


def selftest() -> int:
    checks = _checks(edges_for("subject", code_only(SAMPLE), KNOWN))
    failures = [why for ok, why in checks if not ok]
    for ok, why in checks:
        print(f"  {'ok  ' if ok else 'FAIL'} {why}")
    if failures:
        print(f"\nmodule_map selftest: FAIL ({len(failures)})")
        return 1
    print("\nmodule_map selftest: PASS")
    return 0
