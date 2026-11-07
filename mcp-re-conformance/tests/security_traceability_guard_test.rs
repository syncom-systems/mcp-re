//! MCPS-070 (MCP-RE-EPIC-P6.6C) — security traceability manifest drift guard.
//!
//! The committed manifest at
//! `components/mcp-re/mcp-re-conformance/security_traceability_manifest.json` is the
//! SINGLE SOURCE OF TRUTH mapping each MCP-RE security property (P6.6A + P6.6B) to
//! the Bazel test target AND the named test function that proves it. Docs say
//! "see the manifest" instead of quoting a literal count that rots.
//!
//! This guard FAILS on any drift:
//!
//!   1. an entry names a `bazel_target` that no `BUILD.bazel` (among the mcp-re
//!      packages this guard is handed) declares as an `nt_rust_test` rule — i.e.
//!      a target was renamed or removed;
//!   2. an entry names a `test_fn` that does not appear as a `fn <name>(` in the
//!      entry's `source` test file on disk — i.e. a test function was renamed or
//!      removed;
//!   3. an entry's `source` path does not match its `bazel_target` package, or the
//!      named source does not exist on disk;
//!   4. the recorded `counts.entries` disagrees with the actual number of entries;
//!   5. the four required server-cert-verification cases (trusted accepted,
//!      untrusted rejected, wrong identity, expired) are not all present;
//!   6. the guard's own runfile table (`SOURCE_ENVS`) and the manifest's source
//!      set disagree in either direction — a source with no runfile cannot be
//!      read, and a runfile for a source nobody claims is a stale wiring claim.
//!
//! Every input is delivered through Bazel `data` runfiles and read from DISK at
//! test time (resolved via `$(rlocationpath)` against `TEST_SRCDIR`/`RUNFILES_DIR`,
//! the same scheme as the conformance drift_guard) — so a renamed target or fn is
//! caught by re-reading reality, never by a trusted-as-written assertion.
//!
//! std + serde_json only (no new crates).

use std::collections::BTreeSet;

#[path = "security_traceability_guard_test/build_files.rs"]
mod build_files;
#[path = "security_traceability_guard_test/claim_matrix.rs"]
mod claim_matrix;
#[path = "security_traceability_guard_test/manifest.rs"]
mod manifest;
#[path = "security_traceability_guard_test/runfiles.rs"]
mod runfiles;

use build_files::declared_test_targets;
use claim_matrix::parse_section_a;
use manifest::Manifest;
use runfiles::{declares_fn, read, read_source, SOURCE_ENVS};

// --- drift conditions --------------------------------------------------------

/// Condition (1): every `bazel_target` in the manifest is declared by some
/// BUILD.bazel as an `nt_rust_test`. A renamed/removed target fails here.
#[test]
fn every_bazel_target_is_declared_in_a_build_file() {
    let declared = declared_test_targets();
    let mut missing: Vec<String> = Manifest::load()
        .entries()
        .map(|e| e.target())
        .filter(|target| !declared.contains(*target))
        .map(str::to_string)
        .collect();
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "manifest references bazel_target(s) that no BUILD.bazel declares as nt_rust_test \
         (renamed/removed?). Fix security_traceability_manifest.json or the BUILD file: {missing:?}"
    );
}

/// Condition (3a): every entry's `source` workspace-relative path agrees with its
/// `bazel_target` package prefix, so the source we grep belongs to the target we
/// assert. (`//mcp-re-demo:x` ⇒ source must start with `mcp-re-demo/`.)
#[test]
fn entry_source_matches_target_package() {
    let mismatches: Vec<String> = Manifest::load()
        .entries()
        .filter(|e| !e.source_is_in_target_package())
        .map(|e| format!("{} <-> {}", e.target(), e.source()))
        .collect();
    assert!(
        mismatches.is_empty(),
        "manifest entries whose source path does not belong to the target's package: {mismatches:?}"
    );
}

/// The runfile table is exactly the manifest's source set — in BOTH directions.
///
/// `source_env_for` panics on a source it cannot deliver, which covers
/// manifest ⊆ table. The reverse containment needs asserting: a table entry
/// whose manifest entry is withdrawn stops being consulted, and an unreachable
/// mapping is not inert — it is a claim that a source is still wired up, in a
/// table `mcp-re-test-paths` mirrors.
#[test]
fn the_source_table_names_exactly_the_manifest_sources() {
    let manifest = Manifest::load();
    let declared: BTreeSet<&str> = manifest.entries().map(|e| e.source()).collect();
    let tabled: BTreeSet<&str> = SOURCE_ENVS.iter().map(|(source, _)| *source).collect();
    let orphaned: Vec<&&str> = tabled.difference(&declared).collect();
    assert!(
        orphaned.is_empty(),
        "SOURCE_ENVS wires runfiles for source(s) the manifest no longer names — delete the \
         entry (and its mirror in mcp-re-test-paths) once nothing claims it: {orphaned:?}"
    );
    let unwired: Vec<&&str> = declared.difference(&tabled).collect();
    assert!(
        unwired.is_empty(),
        "manifest names source(s) with no runfile wired in SOURCE_ENVS: {unwired:?}"
    );
}

/// Condition (2) + (3b): every entry's `test_fn` appears as `fn <name>(` in the
/// entry's `source` file read from disk. A renamed/removed test fn fails here.
#[test]
fn every_test_fn_appears_in_its_source() {
    let missing: Vec<String> = Manifest::load()
        .entries()
        .filter(|e| !declares_fn(&read_source(e.source()), e.test_fn()))
        .map(|e| format!("{} (in {})", e.test_fn(), e.source()))
        .collect();
    assert!(
        missing.is_empty(),
        "manifest references test_fn(s) absent from their source file (renamed/removed?). \
         Fix security_traceability_manifest.json or the test source: {missing:?}"
    );
}

/// Condition (4): the recorded count must equal the actual number of entries.
#[test]
fn recorded_count_is_derived_not_stale() {
    let manifest = Manifest::load();
    let recorded = manifest.recorded_count();
    let actual = manifest.len() as u64;
    assert_eq!(
        recorded, actual,
        "counts.entries ({recorded}) disagrees with the entries array length ({actual})"
    );
}

/// Condition (5): the four required server-cert-verification cases are all
/// present (the acceptance criterion explicitly demands keeping all four). We key
/// on each case's distinguishing `test_fn`, all in mtls_client_test.
#[test]
fn four_server_auth_cases_are_present() {
    let manifest = Manifest::load();
    for required in [
        "trusted_server_and_client_round_trip_succeeds", // trusted accepted
        "untrusted_server_cert_is_rejected",             // untrusted rejected
        "wrong_server_identity_is_rejected",             // wrong identity
        "expired_server_cert_is_rejected",               // expired
    ] {
        assert!(
            manifest.maps("//mcp-re-transport:mtls_client_test", required),
            "required server-auth case missing from the manifest: {required}"
        );
    }
}

/// ADR-MCPS-036 gate item 1 — "no traceability-mapped green test, no proposal
/// claim." EVERY §A capability claim in `docs/spec/v0.5-claim-matrix.md` must map
/// to at least one named test in the manifest. The matrix §A is read from DISK
/// (runfiles, same scheme as the sources) and each row's Required-conformance
/// citation(s) are matched against the manifest `property` set: a citation matches
/// when ALL of its `…`-split fragments are substrings of a single manifest
/// property. A row with no matched citation is an UNMAPPED §A claim and FAILS.
#[test]
fn every_section_a_claim_maps_to_a_manifest_entry() {
    let props = Manifest::load().properties();
    let rows = parse_section_a(&read("MCP_RE_CLAIM_MATRIX"));
    assert!(
        rows.len() >= 13,
        "parsed too few §A capability rows ({}) — claim-matrix wiring/parse broken",
        rows.len()
    );
    let unmapped: Vec<String> = rows
        .iter()
        .filter(|row| !row.is_mapped_by(&props))
        .map(|row| format!("{} (citations: {:?})", row.capability, row.cited))
        .collect();
    assert!(
        unmapped.is_empty(),
        "§A capability claim(s) with NO mapped manifest entry — add a named green test \
         entry to security_traceability_manifest.json (no traceability-mapped green test, \
         no proposal claim — ADR-MCPS-036): {unmapped:?}"
    );
}

/// ADR-MCPS-036 gate items (b)/(c)/(d) — the three required guard pairs are each
/// represented by a named manifest entry, so the gate fails if any is dropped from
/// the spine: the #150 method-transparency PAIR (behavioral + static-drift), the
/// #151 audit-vocabulary drift guard, and the #155 forbidden-claim guard. Each is
/// keyed on its (bazel_target, test_fn) so a rename is caught by the other guards
/// re-reading reality.
#[test]
fn required_gate_guards_are_mapped() {
    let manifest = Manifest::load();
    let required: &[(&str, &str)] = &[
        // #150 method-transparency pair (ADR-MCPS-030/034).
        (
            "//mcp-re-conformance:method_transparency_test",
            "accepted_verdict_is_identical_across_all_methods",
        ),
        (
            "//mcp-re-conformance:method_name_drift_guard_test",
            "no_banned_method_literal_in_non_test_core_src",
        ),
        // #151 audit-vocabulary drift guard (ADR-MCPS-035).
        (
            "//mcp-re-conformance:audit_vocabulary_guard_test",
            "every_audit_token_is_a_wire_code_or_a_fixed_event_type",
        ),
        // #155 forbidden-claim guard (ADR-MCPS-036 item 4).
        (
            "//mcp-re-conformance:forbidden_claim_guard_test",
            "no_forbidden_phrase_is_an_asserted_claim",
        ),
    ];
    let missing: Vec<String> = required
        .iter()
        .filter(|(target, test_fn)| !manifest.maps(target, test_fn))
        .map(|(target, test_fn)| format!("{target}::{test_fn}"))
        .collect();
    assert!(
        missing.is_empty(),
        "required proposal-gate guard(s) not mapped in the traceability manifest \
         (method-transparency pair #150 / audit guard #151 / forbidden-claim guard #155 — \
         ADR-MCPS-036): {missing:?}"
    );
}

/// Sanity: the guard actually parsed something from every source, so a silent
/// empty-set false-pass (e.g. a renamed env var resolving to an empty file)
/// cannot masquerade as "no drift".
#[test]
fn guard_inputs_are_non_empty() {
    assert!(
        Manifest::load().len() > 0,
        "manifest has zero entries — wiring broken"
    );
    assert!(
        declared_test_targets().len() >= 20,
        "parsed too few nt_rust_test targets from BUILD files — parser/wiring broken"
    );
    // The guard test target must itself be a declared target under mcp-re-conformance.
    assert!(
        declared_test_targets().contains("//mcp-re-conformance:security_traceability_guard_test"),
        "BUILD must declare the security_traceability_guard_test target itself"
    );
    // The claim matrix §A was actually read and parsed, so the §A-coverage check
    // cannot silently false-pass on an empty/broken runfile.
    assert!(
        parse_section_a(&read("MCP_RE_CLAIM_MATRIX")).len() >= 13,
        "parsed too few §A capability rows — claim-matrix runfile wiring is broken"
    );
}

/// Self-check of the drift detector (Condition 1 + 2 mechanics): the guard's own
/// matchers MUST reject a renamed target and a renamed fn. This is the
/// "would fail on drift" demonstration kept green: it proves the negative path
/// without mutating the committed manifest. If `nt_rust_test` were renamed or a
/// referenced fn removed, `every_bazel_target_is_declared_in_a_build_file` /
/// `every_test_fn_appears_in_its_source` would fire exactly as asserted here.
#[test]
fn drift_detector_rejects_renamed_target_and_fn() {
    // A target absent from the declared set is reported missing.
    let declared = declared_test_targets();
    assert!(
        !declared.contains("//mcp-re-transport:mtls_client_test_RENAMED"),
        "a renamed target must NOT be found among declared targets (drift would be caught)"
    );
    // A fn absent from a source is reported missing.
    let src = read("MCP_RE_SRC_METHOD_TRANSPARENCY");
    assert!(
        declares_fn(&src, "accepted_verdict_is_identical_across_all_methods"),
        "control: the real fn is found"
    );
    assert!(
        !declares_fn(
            &src,
            "accepted_verdict_is_identical_across_all_methods_RENAMED"
        ),
        "a renamed fn must NOT be found in the source (drift would be caught)"
    );
}
