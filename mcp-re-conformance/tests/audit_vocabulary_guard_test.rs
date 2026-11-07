//! ADR-MCPS-035 — audit-evidence vocabulary drift guard.
//!
//! The MCP-RE audit-evidence vocabulary (`mcp-re-core/src/audit.rs`) derives its
//! rejection reasons from the FROZEN `McpReError::wire_code()` taxonomy
//! (`mcp-re-core/src/error.rs` is the sole authority) and adds ONLY the two
//! success events the error enum cannot express, plus the three delegated-key
//! lifecycle events authorized by ADR-MCPRE-052 §7. This guard FAILS on any drift
//! between the two files:
//!
//!   1. a rejection `reason` the audit layer can emit is NOT a member of
//!      `McpReError::wire_code()` (a minted parallel token);
//!   2. the success-event set is not EXACTLY the two-item allowlist
//!      (`mcp-re.request.accepted`, `mcp-re.response.signed`);
//!   3. the key-lifecycle set is not EXACTLY the three-item allowlist
//!      (`mcp-re.delegated_key.{issued,rotated,retired}`, ADR-MCPRE-052 §7), or the
//!      execution set is not EXACTLY the one-item allowlist (`mcp-re.execution.intent`,
//!      ADR-MCPRE-070 D1, vocabulary revision 2), or the accounting set is not EXACTLY the
//!      one-item allowlist (`mcp-re.audit.accounting`, ADR-MCPRE-070 D2/Q3, revision 3);
//!   4. an audit `event_type` collides with a frozen `wire_code()` token (a
//!      rejection sub-name masquerading as an event type);
//!   5. an `authorization_hash_mismatch` notion reappears as an audit reason
//!      (Core binds, never interprets — ADR-MCPS-013);
//!   6. any producer OUTSIDE `mcp-re-core/src/error.rs` mints an `mcp-re.*` token of its
//!      own instead of naming a Core verdict and deriving the token from it
//!      (ADR-MCPRE-066 Slice 2).
//!
//! Both source files are delivered through Bazel `data` runfiles and read from
//! DISK at test time (resolved via `$(rlocationpath)` against
//! `TEST_SRCDIR`/`RUNFILES_DIR`, the SAME scheme as the conformance drift_guard
//! and the method-name drift guard) through `mcp-re-test-paths` —
//! so adding an `McpReError` variant (a new frozen wire_code) or editing the audit
//! vocabulary is re-read from reality, never trusted as written. The guard does
//! not hardcode any absolute path.
//!
//! std only (no new crates).

#[path = "audit_vocabulary_guard_test/corpus.rs"]
mod corpus;
#[path = "audit_vocabulary_guard_test/producers.rs"]
mod producers;
#[path = "audit_vocabulary_guard_test/source.rs"]
mod source;
#[path = "audit_vocabulary_guard_test/vocabulary.rs"]
mod vocabulary;

use std::collections::BTreeSet;

use corpus::{crate_packages, crate_root_of, emit_measurement, minting_files};
use source::Source;
use vocabulary::{
    all_event_types, token_set, AuditSource, ACCOUNTING, EXECUTION, EXPECTED_KEY_LIFECYCLE_EVENTS,
    EXPECTED_REJECTION_EVENTS, EXPECTED_SUCCESS_EVENTS,
};

/// The fewest source files a workspace walk may read before it is judged to measure nothing.
const MINIMUM_FILES_SCANNED: usize = 200;

// --- drift conditions --------------------------------------------------------

/// Condition (1): every `mcp-re.*` token the audit vocabulary uses is EITHER a
/// frozen `wire_code()` rejection token OR one of the four fixed `event_type`
/// tokens. No third category — i.e. the audit layer cannot mint a rejection
/// reason outside `wire_code()`.
#[test]
fn every_audit_token_is_a_wire_code_or_a_fixed_event_type() {
    let codes = Source::runfile("MCP_RE_CORE_SRC_ERROR").frozen_wire_codes();
    let tokens = Source::runfile("MCP_RE_CORE_SRC_AUDIT").production_literals();
    let allowed_event_types: BTreeSet<&str> = all_event_types().collect();

    let foreign: Vec<&String> = tokens
        .iter()
        .filter(|token| !codes.contains(*token) && !allowed_event_types.contains(token.as_str()))
        .collect();
    assert!(
        foreign.is_empty(),
        "audit.rs mentions mcp-re.* token(s) that are neither a frozen McpReError::wire_code() nor \
         one of the fixed audit event_types (four verdict + three ADR-MCPRE-052 key-lifecycle + one \
         ADR-MCPRE-070 execution + one ADR-MCPRE-070 accounting) — a minted rejection reason outside the frozen taxonomy is forbidden (ADR-MCPS-035): {foreign:?}"
    );
}

/// Condition (2): the audit module's success allowlist is EXACTLY the two
/// expected success events — derived from the `SUCCESS_EVENT_TYPES` slice
/// declared in `audit.rs`, parsed from disk.
#[test]
fn success_event_set_is_exactly_the_two_item_allowlist() {
    AuditSource::load().assert_exact(
        "SUCCESS_EVENT_TYPES",
        EXPECTED_SUCCESS_EVENTS,
        "audit.rs SUCCESS_EVENT_TYPES must be EXACTLY the two-item allowlist \
         (mcp-re.request.accepted, mcp-re.response.signed) — no third success event without an ADR \
         (ADR-MCPS-035 §3)",
    );
}

/// Condition (2b): the delegated-key lifecycle allowlist is EXACTLY the three
/// expected events — derived from the `KEY_LIFECYCLE_EVENT_TYPES` slice declared
/// in `audit.rs`, parsed from disk (ADR-MCPRE-052 §7). No fourth lifecycle event
/// without an ADR.
#[test]
fn key_lifecycle_event_set_is_exactly_the_three_item_allowlist() {
    AuditSource::load().assert_exact(
        "KEY_LIFECYCLE_EVENT_TYPES",
        EXPECTED_KEY_LIFECYCLE_EVENTS,
        "audit.rs KEY_LIFECYCLE_EVENT_TYPES must be EXACTLY the three-item allowlist \
         (mcp-re.delegated_key.issued/rotated/retired) — no fourth lifecycle event without an ADR \
         (ADR-MCPRE-052 §7)",
    );
}

/// Condition (2c): the execution allowlist is EXACTLY the one expected event — derived from
/// the `EXECUTION_EVENT_TYPES` slice declared in `audit.rs`, parsed from disk (ADR-MCPRE-070
/// D1). The intent is a category of its own, so it can join neither the success set (pinned
/// at two above) nor any other.
#[test]
fn execution_event_set_is_exactly_the_one_item_allowlist() {
    AuditSource::load().assert_own_category(&EXECUTION);
}

/// Condition (2d): the accounting allowlist is EXACTLY the one expected event — derived from
/// the `ACCOUNTING_EVENT_TYPES` slice declared in `audit.rs`, parsed from disk (ADR-MCPRE-070
/// D2, Q3). A category of its own: it joins neither the success set, so the two success
/// events keep their meanings, nor any other.
#[test]
fn accounting_event_set_is_exactly_the_one_item_allowlist() {
    AuditSource::load().assert_own_category(&ACCOUNTING);
}

/// Condition (3): no audit `event_type` is itself a frozen `wire_code()` token.
/// A rejection sub-name like `mcp-re.request.rejected.bad_signature` would either
/// shadow a wire_code or duplicate it; the fixed event_types must stay disjoint
/// from the taxonomy.
#[test]
fn event_types_do_not_collide_with_frozen_wire_codes() {
    let codes = Source::runfile("MCP_RE_CORE_SRC_ERROR").frozen_wire_codes();
    for ev in all_event_types() {
        assert!(
            !codes.contains(ev),
            "audit event_type {ev:?} collides with a frozen McpReError::wire_code() token — \
             event_types and rejection reasons must stay disjoint (ADR-MCPS-035)"
        );
    }
}

/// Condition (4): no `authorization_hash_mismatch` notion is an audit reason.
/// Core binds `authorization_hash` but never interprets the artifact, so it can
/// never emit a "mismatch" (ADR-MCPS-013). The frozen taxonomy has no such code,
/// and the audit vocabulary must not introduce one.
#[test]
fn no_authorization_hash_mismatch_audit_reason() {
    let codes = Source::runfile("MCP_RE_CORE_SRC_ERROR").frozen_wire_codes();
    assert!(
        !codes.contains("mcp-re.authorization_hash_mismatch"),
        "the frozen Core taxonomy must NOT contain authorization_hash_mismatch (Core binds, \
         never interprets — ADR-MCPS-013)"
    );
    // And the audit production region must not mention it as a token at all.
    let tokens = Source::runfile("MCP_RE_CORE_SRC_AUDIT").production_literals();
    assert!(
        !tokens.contains("mcp-re.authorization_hash_mismatch"),
        "audit.rs must not introduce an authorization_hash_mismatch reason (Core binds, never \
         interprets — ADR-MCPS-013)"
    );
}

/// ADR-MCPRE-066 Slice 2 — **no producer outside Core mints a wire token.**
///
/// This test used to check set CONTAINMENT: it parsed the `mcp-re.*` string literals out of
/// each producer's own `wire_code` table and asserted they were a subset of the frozen
/// taxonomy's. That was the right check while the sink took a string, and it had the defect
/// its own subject describes — its scope was a hand-maintained list of files, so it
/// described yesterday's producer set on exactly the day a producer moved (ADR-MCPRE-066
/// §2.1). #637 found a fourth producer it had never been told about.
///
/// Slice 2 removed the string-taking constructors, so the containment is now a type
/// property and the interesting claim changed with it: not *are the carriers' strings a
/// subset*, but **do the carriers have strings at all**. A producer that mints one has
/// re-created the parallel namespace, whether or not the token happens to be a frozen
/// member today, because a string is what let one authority's verdict pass for another's.
///
/// So: exactly one file in the workspace decides what an `mcp-re.*` token says, and it is
/// `mcp-re-core/src/error.rs`. Every carrier states which Core verdict it IS, with an
/// exhaustive `From<&_> for McpReError`, and derives its token from that.
#[test]
fn no_producer_outside_core_mints_a_wire_token() {
    producers::assert_no_carrier_mints_a_token();

    // Positive control on the parser and the runfiles wiring: the ONE file that is
    // supposed to mint them still does, so an empty result above means "no tokens here"
    // rather than "this test reads nothing".
    let frozen = Source::runfile("MCP_RE_CORE_SRC_ERROR").frozen_wire_codes();
    assert!(
        frozen.len() >= 15,
        "the sole minting authority parsed {} tokens — the runfiles wiring is broken, and          every assertion above is then vacuous",
        frozen.len()
    );

    // And each projection really is where that producer's verdicts are decided, so the
    // files scanned above are the ones that replaced a table rather than empty stubs.
    producers::assert_projections_decide_the_verdicts();
}

/// ADR-MCPRE-066 §2.1, closed — **which files decide what an `mcp-re.*` verdict token says
/// is MEASURED, not listed.**
///
/// `no_producer_outside_core_mints_a_wire_token` scans a hand-maintained set of producer
/// files, and the ADR names that shape's defect in its own words: such a list describes
/// yesterday's producer set on exactly the day a producer moves. #637 found a producer it
/// had never been told about, and the v0.17 policy-authority slice found a fifth —
/// `BindingSpecRefusal`, rendered by both published SDKs from a table of two string
/// literals.
///
/// So this control does not read a list of producers. It walks EVERY workspace crate's
/// source tree, takes each file's production half, and asserts that the set of files
/// holding a verdict-token literal is exactly the two frozen vocabularies:
///
/// ```text
/// mcp-re-core/src/error.rs      McpReError    — the Core verification taxonomy (ADR-MCPS-035)
/// mcp-re-policy/src/error.rs    PolicyError   — the authorization taxonomy (ADR-MCPS-013)
/// ```
///
/// A **verdict token** is `mcp-re.<name>` with no further dot. The dotted spellings are
/// audit EVENT types (`mcp-re.request.accepted`, `mcp-re.delegated_key.issued`), a separate
/// vocabulary the three allowlist tests above pin exactly.
///
/// The crate list is itself derived rather than remembered: it comes from the build graph's
/// target table at compile time, and a crate with no registered source tree fails here
/// instead of going unscanned. Its scope is therefore exactly the first-party Rust crates
/// Bazel builds, both SDK bindings included — see [`NOT_SCANNED`] for the one exclusion.
///
/// The walk is [`corpus::minting_files`]; the crate list is [`CRATE_SOURCE_TREES`], and the
/// one exclusion is [`NOT_SCANNED`].
#[test]
fn exactly_two_files_decide_what_a_verdict_token_says() {
    let expected = token_set(SOLE_MINTING_FILES);

    let (found, files_scanned) = minting_files(CRATE_SOURCE_TREES);

    // THE MEASUREMENT, emitted in the form the ADR-MCPRE-068 `measured://` lane reads.
    emit_measurement(&found, CRATE_SOURCE_TREES.len());

    // Positive control on the walk and the runfiles wiring: an empty or tiny scan would
    // make the equality below hold vacuously.
    assert!(
        files_scanned >= MINIMUM_FILES_SCANNED,
        "the workspace walk read only {files_scanned} source files — the runfiles wiring is          broken, and this control measures nothing"
    );
    assert_eq!(
        found, expected,
        "the set of files deciding what an mcp-re.* VERDICT token says is not the two frozen          vocabularies. A file that appears here and is not one of them has re-created the          parallel namespace ADR-MCPRE-066 Slice 2 removed: state which verdict the failure IS          (an exhaustive `From<&_> for McpReError` or a `PolicyError`) and derive the token from          that. A file that DISAPPEARS from here has moved a frozen vocabulary, which is an ADR."
    );
}

/// The corpus reaches the example binaries, not only the libraries.
///
/// The walk skips a crate directory that is absent, which is right for the crates with no
/// examples and wrong if the runfiles stopped carrying them: then the proof-front proxy,
/// which the build graph compiles and the live proofs run, would be scanned by nobody while
/// the measurement still read 2. So the one example tree that exists is required to be
/// present where the walk looks.
#[test]
fn the_scanned_corpus_includes_the_compiled_examples() {
    let crate_root = crate_root_of("MCP_RE_SRC_TREE_PROXY");
    assert!(
        crate_root
            .join("examples")
            .join("http_profile_proxy.rs")
            .is_file(),
        "mcp-re-proxy/examples is not in the scanned corpus — the guard_src_files runfiles \
         wiring no longer carries the example binaries the build graph compiles"
    );
}

/// The APPARATUS CONTROL — ADR-MCPRE-068 Ruling 4, and the reason a measured proposition
/// owes no mutation probe.
///
/// Deleting a production property does not make a measurement false; it makes it a
/// measurement of a different tree. What a measurement CAN be wrong about, independently of
/// the world, is its own apparatus: a walk that reads nothing, or one wired to a corpus it
/// is not actually looking at, reports a number that cannot move and is not a measurement.
///
/// So this perturbs the input the measurement is scoped over — one crate removed from the
/// scanned set — and reports how many observations changed. The contract the `measured://`
/// lane reads is the COUNT, not the exit status: a control that selected nothing exits 0
/// exactly like one that perturbed everything, and this repository has shipped that
/// distinction being lost before.
#[test]
fn the_measurement_moves_when_the_scanned_set_shrinks() {
    let (baseline, baseline_files) = minting_files(CRATE_SOURCE_TREES);
    assert!(
        baseline_files >= MINIMUM_FILES_SCANNED,
        "the unperturbed walk read only {baseline_files} files; a control over a dead \
         apparatus demonstrates nothing"
    );

    // `mcp-re-core` holds one of the two frozen vocabularies, so removing it from the
    // scanned set MUST remove an observation. Chosen rather than arbitrary: a crate whose
    // absence changed nothing would make this control pass over an apparatus that had
    // stopped reading anything at all.
    let shrunk: Vec<(&str, &str)> = CRATE_SOURCE_TREES
        .iter()
        .filter(|(crate_dir, _)| *crate_dir != "mcp-re-core")
        .copied()
        .collect();
    let (perturbed, perturbed_files) = minting_files(&shrunk);

    let moved = baseline.difference(&perturbed).count();
    println!("APPARATUS-MOVED: {moved}");

    assert!(
        perturbed_files < baseline_files,
        "removing a crate from the scanned set read the same number of files ({baseline_files}); \
         the walk is not reading the set it is given"
    );
    assert_eq!(
        moved, 1,
        "removing mcp-re-core from the scanned set changed {moved} observation(s), expected \
         exactly the one frozen vocabulary it holds. Either the apparatus is not scoped to \
         the set it is handed, or the file set moved and this control needs re-adjudicating."
    );
}

/// Every first-party crate package, and the sentinel naming its source tree. Derived against
/// the build graph by [`the_scanned_crate_set_is_the_workspace`], so a new crate cannot be
/// scanned by nobody.
///
/// The SDK bindings are crates like any other: thin PyO3/napi wrappers over the shared
/// `mcp-re-binding-core` adapter, and none of the three may mint a verdict token.
/// The TypeScript SDK's `.ts` files spell tokens it RECEIVES, and are not Rust sources.
const CRATE_SOURCE_TREES: &[(&str, &str)] = &[
    ("mcp-re-core", "MCP_RE_SRC_TREE_CORE"),
    ("mcp-re-proxy", "MCP_RE_SRC_TREE_PROXY"),
    ("mcp-re-host", "MCP_RE_SRC_TREE_HOST"),
    ("mcp-re-client-core", "MCP_RE_SRC_TREE_CLIENT_CORE"),
    ("mcp-re-client", "MCP_RE_SRC_TREE_CLIENT"),
    ("mcp-re-client-proxy", "MCP_RE_SRC_TREE_CLIENT_PROXY"),
    ("mcp-re-transport", "MCP_RE_SRC_TREE_TRANSPORT"),
    ("mcp-re-policy", "MCP_RE_SRC_TREE_POLICY"),
    ("mcp-re-http-profile", "MCP_RE_SRC_TREE_HTTP_PROFILE"),
    ("mcp-re-demo", "MCP_RE_SRC_TREE_DEMO"),
    ("mcp-re-test-paths", "MCP_RE_SRC_TREE_TEST_PATHS"),
    (
        "mcp-re-operator-display",
        "MCP_RE_SRC_TREE_OPERATOR_DISPLAY",
    ),
    ("sdk/binding-core", "MCP_RE_SRC_TREE_SDK_BINDING_CORE"),
    ("sdk/python", "MCP_RE_SRC_TREE_SDK_PYTHON"),
    ("sdk/typescript", "MCP_RE_SRC_TREE_SDK_TYPESCRIPT"),
];

/// Crate packages deliberately not scanned, each with its reason. Named rather than
/// inferred: excluding a package is a decision, and this list is where it is made.
const NOT_SCANNED: &[(&str, &str)] = &[(
    "config/clippy-strict",
    "the lint gate's activation probes: deliberately violating files no product target links",
)];

/// The build graph's target table, `tools/verification/rust-targets --check` holds it equal
/// to `bazel query`.
const TARGET_TABLE: &str = include_str!("../../verification/generated/rust-targets.json");

/// The rule kinds that compile a crate a consumer links, as opposed to a test, a doc test,
/// or a prover or extractor run over one.
const CRATE_KINDS: &[&str] = &[
    "rust_library",
    "rust_binary",
    "rust_shared_library",
    "rust_static_library",
    "rust_proc_macro",
];

/// The directories of a crate package whose Rust sources a compiled target is built from:
/// the library, and the example binaries the build graph also compiles. `tests/` is not
/// here — a test source is not a producer.
const COMPILED_SOURCE_DIRS: &[&str] = &["src", "examples"];

/// The two files that may hold a verdict-token literal, and the only two.
const SOLE_MINTING_FILES: &[&str] = &["mcp-re-core/src/error.rs", "mcp-re-policy/src/error.rs"];

/// The scanned set is the workspace, so nothing is scanned by nobody.
///
/// Read from the build graph's target table at COMPILE time: a crate Bazel builds is a row
/// there, so a new one cannot enter the build without entering this set.
#[test]
fn the_scanned_crate_set_is_the_workspace() {
    let packages = crate_packages(TARGET_TABLE);
    assert!(
        packages.len() >= 10,
        "parsed {} crate packages — the table reader is broken and every membership \
         assertion below is vacuous",
        packages.len()
    );
    let accounted: BTreeSet<String> = CRATE_SOURCE_TREES
        .iter()
        .map(|(dir, _)| (*dir).to_string())
        .chain(NOT_SCANNED.iter().map(|(dir, _)| (*dir).to_string()))
        .collect();
    let unscanned: Vec<&String> = packages
        .iter()
        .filter(|p| !accounted.contains(*p))
        .collect();
    assert!(
        unscanned.is_empty(),
        "crate package(s) {unscanned:?} are scanned by no source-tree sentinel. Add one to \
         CRATE_SOURCE_TREES (with its runfiles wiring), or to NOT_SCANNED with the reason."
    );
    let stale: Vec<&String> = accounted
        .iter()
        .filter(|p| !packages.contains(*p))
        .collect();
    assert!(
        stale.is_empty(),
        "{stale:?} are listed here and build no crate — a sentinel over a tree the graph does \
         not compile scans something no deployment runs"
    );
}

#[test]
fn guard_inputs_are_non_empty() {
    let codes = Source::runfile("MCP_RE_CORE_SRC_ERROR").frozen_wire_codes();
    assert!(
        codes.len() >= 15,
        "parsed too few frozen wire_code tokens from error.rs ({}) — runfiles wiring is broken",
        codes.len()
    );
    // A representative frozen token is present (positive control on the parser).
    assert!(
        codes.contains("mcp-re.invalid_signature"),
        "expected mcp-re.invalid_signature among the parsed frozen wire_codes"
    );
    let tokens = Source::runfile("MCP_RE_CORE_SRC_AUDIT").production_literals();
    for ev in EXPECTED_SUCCESS_EVENTS
        .iter()
        .chain(EXPECTED_REJECTION_EVENTS.iter())
    {
        assert!(
            tokens.contains(*ev),
            "expected audit event_type {ev:?} to appear in audit.rs production region — wiring broken"
        );
    }
}
