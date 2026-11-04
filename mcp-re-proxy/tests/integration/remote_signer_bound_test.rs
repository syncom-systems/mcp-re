// SPDX-License-Identifier: Apache-2.0
//! Every remote-signer exchange is bounded by the shared `NETWORK_TIMEOUT` (G18).
//!
//! The bound was DECLARED and measured nowhere. `wire_limits.rs`'s only control over it,
//! `the_network_timeout_is_short_enough_to_refuse_rather_than_queue`, asserts
//! `NETWORK_TIMEOUT <= Duration::from_secs(10)` — a comparison between two literals written
//! in the same file. Delete every `.bounded_by(NETWORK_TIMEOUT)` from the AWS and GCP
//! transports and it stays green, as does every other control in the three units that cite
//! G18 (r11 `R11-534`, `R11-535`, `R11-536`).
//!
//! The body-cap half of G18 is genuinely test-backed: `read_error_body` is a real function
//! with a real truncation control. This file is the timeout half.
//!
//! # Why a source scan and not a type
//!
//! `ureq`'s builder is foreign and a per-request bound is optional by construction — a
//! request without one compiles and waits on the agent's. Nothing this project owns can make an
//! unbounded remote-signer request unconstructible, so this is EVIDENCE about which
//! requests this crate BUILDS, never unconstructibility. That is also why the count rule
//! below is stated as an equality rather than a presence check: a presence check passes as
//! soon as ONE request in a file is bounded.
//!
//! What this does NOT establish: that `ureq` honours the duration, or that a signer behind
//! a stalled TLS handshake returns within it. Those are the transport's, and ASM-0040's
//! neighbours cover what a foreign dependency is trusted for.

use std::path::PathBuf;

/// The transports that reach a remote signer. Named rather than globbed: a glob would
/// silently stop covering a transport that moved, and the failure mode of a stale matcher
/// is a clean pass over unmeasured code.
const TRANSPORTS: &[&str] = &["aws_sts.rs", "aws_kms_keysource.rs", "gcp_kms_keysource.rs"];

/// The shared bound, by name.
const BOUND: &str = "NETWORK_TIMEOUT";

/// Applying a per-request deadline, by name: `outbound_fetch::RequestBound`.
const TIMEOUT_CALL: &str = ".bounded_by(";

/// ureq's own per-request deadline, which `bounded_by` wraps. A transport naming it directly
/// sets a bound the rule above does not count.
const RAW_TIMEOUT_CALLS: &[&str] = &[".timeout_global(", ".timeout_per_call(", ".timeout("];

/// Putting bytes on the wire, by name. Every one of these must be preceded by a bounded
/// builder in the same file.
const DISPATCHES: &[&str] = &[".fetch()", ".fetch_with(", ".call()", ".send("];

/// The code of `source`, comments and literals blanked, so a doc comment NAMING the bound
/// cannot satisfy a rule about calling it — the same trap `client_verifier_posture_test`
/// guards against — and the `//` of a URL literal cannot hide a dispatch after it.
fn code_only(source: &str) -> String {
    mcp_re_test_paths::rust_source::code_only(source)
}

/// The directory the named transports live in.
///
/// Resolved through an anchor the path resolver knows in both lanes rather than through
/// `CARGO_MANIFEST_DIR`: this suite also compiles under Bazel, whose sandbox delivers
/// sources through runfiles and has no manifest directory for a path to be relative to.
/// A file-not-found there would fail every rule below on the read instead of on the
/// property, which is a red that says nothing. `client_verifier_posture_test` walks the
/// same seam from the same anchor.
fn transport_root() -> PathBuf {
    let anchor = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    anchor
        .parent()
        .unwrap_or_else(|| panic!("{anchor:?} has no parent directory"))
        .to_path_buf()
}

fn transport_source(file: &str) -> String {
    let path = transport_root().join(file);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("a named transport must exist: {path:?}: {e}"));
    code_only(&source)
}

fn count_of(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

fn dispatch_count(source: &str) -> usize {
    DISPATCHES.iter().map(|d| count_of(source, d)).sum()
}

/// **The rule.** In every remote-signer transport, each dispatch is matched by one
/// `.bounded_by(NETWORK_TIMEOUT)`, and no other duration appears.
///
/// An equality and not a presence check: a presence check is satisfied by one bounded
/// request in a file that also makes three unbounded ones.
#[test]
fn every_remote_signer_dispatch_is_bounded_by_the_shared_timeout() {
    let mut measured = 0usize;
    for file in TRANSPORTS {
        let source = transport_source(file);
        let dispatches = dispatch_count(&source);
        assert!(
            dispatches > 0,
            "{file} reaches a remote signer, so it must dispatch; a transport that stopped \
             would make this rule vacuously true"
        );
        assert_eq!(
            count_of(&source, &format!("{TIMEOUT_CALL}{BOUND})")),
            dispatches,
            "{file}: every dispatch must carry .bounded_by({BOUND}); an unmatched dispatch \
             is a remote-signer exchange with no bound of its own"
        );
        assert_eq!(
            count_of(&source, TIMEOUT_CALL),
            dispatches,
            "{file}: a `.bounded_by(` that is not `{BOUND}` is a SECOND bound — G18 claims one"
        );
        for raw in RAW_TIMEOUT_CALLS {
            assert_eq!(
                count_of(&source, raw),
                0,
                "{file}: `{raw}` is a deadline outside `.bounded_by({BOUND})` — a SECOND bound"
            );
        }
        measured += dispatches;
    }
    assert!(measured >= 5, "the transports made {measured} bounded dispatches, fewer than the five measured at this rule's writing — a transport has gone missing from TRANSPORTS");
}

/// The agent layer carries the same bound, so a request that somehow omitted its own still
/// meets a bounded egress rather than an unbounded one.
#[test]
fn every_credential_egress_a_transport_builds_carries_the_shared_timeout() {
    for file in TRANSPORTS {
        let source = transport_source(file);
        let built = count_of(&source, "egress(") + count_of(&source, "CredentialEgress::to(");
        assert!(
            built > 0,
            "{file} must build the egress it dispatches through"
        );
        assert_eq!(
            count_of(&source, &format!("egress({BOUND})"))
                + count_of(
                    &source,
                    &format!("CredentialEgress::to(&destination, {BOUND})")
                ),
            built,
            "{file}: an egress built with any other duration is a second bound"
        );
    }
}

/// **The rules detect what they claim to.**
///
/// Four rules over source text are vacuously true the moment a matcher stops matching, so
/// the battery that would report a clean pass over a moved transport is the battery that
/// must also demonstrate it still detects each regression.
#[test]
fn the_rules_would_catch_each_regression() {
    let bounded = "let r = a.post(\"\").bounded_by(NETWORK_TIMEOUT).fetch_with(&b);";
    assert_eq!(dispatch_count(bounded), 1, "a real dispatch must be seen");
    assert_eq!(
        count_of(bounded, ".bounded_by(NETWORK_TIMEOUT)"),
        1,
        "a real bound must be seen"
    );

    // The regression the equality exists for: a dispatch with no timeout at all.
    let unbounded = "let r = a.post(\"\").fetch_with(&b);";
    assert_eq!(dispatch_count(unbounded), 1);
    assert_eq!(
        count_of(unbounded, ".bounded_by(NETWORK_TIMEOUT)"),
        0,
        "an unbounded dispatch must NOT read as bounded"
    );

    // The regression the second equality exists for: a bound that is not the shared one.
    let literal = "let r = a.post(\"\").bounded_by(Duration::from_secs(600)).call();";
    assert_eq!(count_of(literal, TIMEOUT_CALL), 1);
    assert_eq!(
        count_of(literal, ".bounded_by(NETWORK_TIMEOUT)"),
        0,
        "a literal duration must NOT read as the shared bound"
    );

    // A doc comment naming the bound must not satisfy a rule about applying it.
    assert_eq!(
        count_of(
            &code_only("/// Bounded by `.bounded_by(NETWORK_TIMEOUT)`."),
            ".bounded_by("
        ),
        0,
        "a comment naming the call must not read as the call"
    );

    // A `//` inside a URL literal is the literal's, and must not hide a dispatch after it.
    assert_eq!(
        dispatch_count(&code_only(
            "let r = a.post(\"https://sts.x/\").fetch_with(&b);"
        )),
        1,
        "a dispatch after a URL literal must be seen"
    );

    // ureq's own deadline, set directly, is seen as one.
    let raw = "let r = a.post(\"\").config().timeout_global(Some(d)).build().send(&b);";
    assert_eq!(count_of(raw, RAW_TIMEOUT_CALLS[0]), 1);

    // And a transport that vanished must fail rather than pass vacuously.
    assert_eq!(dispatch_count(""), 0, "an empty file makes no dispatches");
}
