// SPDX-License-Identifier: Apache-2.0
//! The composition root reads only ORDINARY validated parameters from the request.
//!
//! "The composition root" is every production file that reads the request through
//! `ValidatedDeployment::config()` — `app.rs` and `startup_plan.rs` today — found by scanning
//! the source tree rather than listed, so a new composition file is measured when it starts
//! reading.
//!
//! ADR-MCPRE-056's completion criterion has a fourth clause, and this is it: after layer A
//! has classified a deployment, the original request stops being a semantic authority. A
//! plane must not reach back for a posture (that is `plane_config_reachback_test`), and the
//! ROOT must not reach back for a decision — which is a different failure, because the root
//! is entitled to read the request. It builds things out of it.
//!
//! So the rule cannot be "no reads". It is:
//!
//! > No post-validation consumer may read `ValidatedDeployment::config()` to make a
//! > security-sensitive decision.
//!
//! # Why an inventory, and not a cleverer rule
//!
//! "Security-sensitive" is not mechanically decidable, and a gate that pretends otherwise
//! either passes vacuously or blocks honest work. What IS decidable is *which fields* the
//! root reads, so this pins the set. Adding a read fails the test; the fix is to add the
//! field here with the sentence saying why it is ordinary — or, far more often, to find the
//! owner it belongs to.
//!
//! That is the same shape as the validation residue's `INVENTORY`: a list checked against
//! the file it describes rather than trusted, so a number in prose cannot drift from the
//! code.
//!
//! # What "ordinary" means here
//!
//! An ordinary validated parameter is one where *this value changing, while every owner
//! state stays unchanged, cannot change a security-sensitive decision or effect.* A
//! certificate path is ordinary: which file is loaded is a deployment's own business, and
//! the custody state decides how its contents are used. A skew bound is NOT ordinary, which
//! is why it left this list and became `FreshnessWindow`.

use std::collections::BTreeSet;

/// Every `DeploymentRequest` field the composition root still reads directly, and the
/// reason each is an ordinary validated parameter rather than an unowned decision.
///
/// Read the reasons before adding to this list. Six fields that looked ordinary on a first
/// pass were not: the skew bound, the trust locator, the certificate lifetime, the
/// connection age, the key-file posture flag and the topology pair all became owners, and
/// two of them were holding live defects.
const ORDINARY: &[(&str, &str)] = &[
    (
        "audience",
        "the audience coordinate requests are verified against; no owner classifies it, and \
         it names no posture",
    ),
    (
        "bind",
        "the listen address, resolved to a SocketAddr here because resolution is an \
         environment act",
    ),
    (
        "peer_trust_anchors",
        "a locator: which roots are loaded. How a loaded root is used is the TLS plane's, \
         and whether the file may be group-readable is KeyFileAccessPolicy's",
    ),
    (
        "inner_http_urls",
        "the backends the pool forwards to; the pool is built here and nothing about \
         forwarding is a classified posture",
    ),
    (
        "limits",
        "the resource ceilings, already normalized by layer A, including the handshake \
         signing capacity the channel plan carries. The one member that WAS a decision — \
         max_connection_age — is owned by ClientCredentialWindow and read from there",
    ),
    ("route", "the request path this deployment answers on"),
    (
        "channel_credential",
        "read for its credential-chain locator alone, for the same reason as \
         peer_trust_anchors. WHICH custody holds the channel key is not read here: that is \
         ChannelCredentialCustodyState's, and the composition root consumes its projection",
    ),
];

/// The production half of `source`, line comments dropped, with the whitespace around every
/// `.` removed, so a read rustfmt splits across lines (`values\n    .bind`) reads as one.
///
/// Comments go first: joining would otherwise read a sentence ending "these two values."
/// above a `let` as a read of a field named `let`. A `//` starts a comment only at the start
/// of a line or after whitespace, so the `//` of a URL in a string literal is not one.
fn joined(source: &str) -> String {
    let production = mcp_re_test_paths::rust_source::production_half(source);
    let code: String = production
        .lines()
        .map(|line| {
            let comment = line
                .match_indices("//")
                .map(|(at, _)| at)
                .find(|&at| at == 0 || line[..at].ends_with(char::is_whitespace));
            comment.map_or(line, |at| &line[..at])
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut out = String::with_capacity(code.len());
    let mut after_dot = false;
    for c in code.chars() {
        if c.is_whitespace() {
            if !after_dot {
                out.push(c);
            }
            continue;
        }
        if c == '.' {
            while out.ends_with(char::is_whitespace) {
                out.pop();
            }
        }
        after_dot = c == '.';
        out.push(c);
    }
    out
}

fn is_ident(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
}

/// The field named after each `marker` in `text`. A marker that starts with a name must
/// start a word: `request.` does not match inside `my_request.` or `x.request.`.
fn fields_after(text: &str, marker: &str, found: &mut BTreeSet<String>) {
    for (index, _) in text.match_indices(marker) {
        let before = text.get(..index).and_then(|head| head.chars().last());
        if !marker.starts_with('.')
            && before.is_some_and(|c| is_ident(c) || c.is_ascii_uppercase() || c == '.')
        {
            continue;
        }
        let rest = text.get(index + marker.len()..).unwrap_or_default();
        let field: String = rest.chars().take_while(|c| is_ident(*c)).collect();
        if !field.is_empty() {
            found.insert(field);
        }
    }
}

/// Every request field the production half of `source` reads through `config()`.
///
/// Two forms: a field read off the call itself (`config.config().limits`), and a field read
/// off a name bound to it (`let values = config.config();` then `values.audience`). The
/// binding's name is read from the statement, so a root that renames it stays measured.
fn raw_reads(source: &str) -> BTreeSet<String> {
    let text = joined(source);
    let mut found = BTreeSet::new();
    fields_after(&text, ".config().", &mut found);
    for (index, _) in text.match_indices(".config();") {
        let head = text.get(..index).unwrap_or_default();
        let Some(statement) = head.rfind("let ").and_then(|at| head.get(at + 4..)) else {
            continue;
        };
        let statement = statement.strip_prefix("mut ").unwrap_or(statement);
        let name: String = statement.chars().take_while(|c| is_ident(*c)).collect();
        if !name.is_empty() && !statement.contains(';') {
            fields_after(&text, &format!("{name}."), &mut found);
        }
    }
    found
}

/// Every production source of the crate that reads the request through `config()`, by
/// path: the composition root and whatever else composes from the request. Found by
/// scanning the whole source tree, so a new composition file is measured the day it
/// starts reading, not the day someone adds it to a list.
fn composition_sources() -> Vec<(std::path::PathBuf, String)> {
    let app = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    let src = app.parent().expect("app.rs lives in src/").to_path_buf();
    let mut pending = vec![src];
    let mut found = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}")) {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let source =
                    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
                let text = joined(&source);
                if text.contains(".config();") || text.contains(".config().") {
                    found.push((path, source));
                }
            }
        }
    }
    found.sort();
    found
}

/// The root reads exactly the inventory, and nothing else.
#[test]
fn the_composition_root_reads_only_ordinary_validated_parameters() {
    let declared: BTreeSet<String> = ORDINARY.iter().map(|(f, _)| f.to_string()).collect();
    let sources = composition_sources();
    let names: Vec<String> = sources
        .iter()
        .filter_map(|(path, _)| path.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    for expected in ["app.rs", "startup_plan.rs"] {
        assert!(
            names.iter().any(|n| n == expected),
            "{expected} reads the request and was not found by the scan: {names:?}"
        );
    }
    let actual: BTreeSet<String> = sources
        .iter()
        .flat_map(|(_, source)| raw_reads(source))
        .collect();

    let undeclared: Vec<&String> = actual.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "the composition root reads {undeclared:?} raw. Before adding to ORDINARY, ask whether this value \
         changing — with every owner state unchanged — could change a security-sensitive \
         decision. If it could, it needs an owner, not an entry."
    );

    let stale: Vec<&String> = declared.difference(&actual).collect();
    assert!(
        stale.is_empty(),
        "ORDINARY names {stale:?}, which the composition root no longer reads. A field that acquired an \
         owner should leave this list, so the list stays a measurement rather than a memory."
    );
}

/// The rule detects what it claims to.
///
/// Without this, a matcher that never matches leaves the assertion above vacuously true and
/// a green run would mean nothing at all.
#[test]
fn the_rule_would_catch_a_new_raw_read() {
    let reaching = "fn run(c: &V) { let values = c.config(); let _ = values.max_clock_skew; }\n\
                    #[cfg(test)]\nmod tests {}\n";
    assert!(
        raw_reads(reaching).contains("max_clock_skew"),
        "the matcher must see a raw read"
    );
    assert!(
        !raw_reads("fn run() { let _ = state.max_clock_skew; }").contains("max_clock_skew"),
        "an owner projection is not a raw read"
    );
    assert!(
        raw_reads(
            "#[cfg(test)]\nmod tests { fn f(c: &V) { let values = c.config(); let _ = values.audience; } }"
        )
        .is_empty(),
        "test code is out of scope, so a fixture cannot make the gate fail or pass"
    );
    assert!(
        raw_reads("fn run(c: &V) { let values = c.config();\n    let _ = values\n        .bind; }")
            .contains("bind"),
        "a read split across a line break must still be seen"
    );
    assert!(
        raw_reads(
            "fn run(c: &V) { let values = c.config();\n    // sized from these two values.\n    \
             let n = 1; let u = \"https://x/y\"; let _ = values.route; }"
        ) == BTreeSet::from(["route".to_string()]),
        "a comment is not a read, and a URL in a string is not a comment"
    );
    assert!(
        raw_reads("fn plan(c: &V) -> L { c.config().limits.tls_handshake_signing }")
            .contains("limits"),
        "a read off the call itself must be seen"
    );
    assert!(
        raw_reads("fn run(c: &V) { let request = c.config(); let _ = request.route; }")
            .contains("route"),
        "a binding under another name must be seen"
    );
    assert!(
        !raw_reads("fn run(v: &V, c: &V) { let x = c.config(); let _ = v.values.route; }")
            .contains("route"),
        "a field of an unrelated value is not a raw read"
    );
    // The control the truncating form could not pass: production below a test module is
    // still production. `app.rs` may grow one at any time, and a scan that stopped at the
    // first `#[cfg(test)]` would have reported a clean inventory over unread code.
    assert!(
        raw_reads(
            "#[cfg(test)]\nmod tests {\n    let _ = values.audience;\n}\n\
             fn late(c: &V) { let values = c.config(); let _ = values.max_clock_skew; }\n"
        )
        .contains("max_clock_skew"),
        "a raw read below the test module must still be seen"
    );
}

/// The inventory is not a bare list: every entry states why the field is ordinary.
///
/// A reason nobody wrote is a field nobody classified, and this list only means anything
/// while adding to it costs a sentence.
#[test]
fn every_ordinary_field_states_why_it_is_ordinary() {
    for (field, reason) in ORDINARY {
        assert!(
            reason.len() > 30,
            "{field} has no real justification: {reason:?}"
        );
    }
}
