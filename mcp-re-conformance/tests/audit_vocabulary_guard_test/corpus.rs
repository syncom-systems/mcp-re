//! The workspace walk: which source files hold a verdict-token literal, and which crate
//! packages the build graph compiles.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::source::{locate, Source};
use super::{COMPILED_SOURCE_DIRS, CRATE_KINDS};

/// The crate directory a source-tree sentinel names.
///
/// The sentinel is `<crate>/src/lib.rs`; its grandparent is the crate.
pub(super) fn crate_root_of(env_key: &str) -> PathBuf {
    locate(env_key)
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("{env_key} resolved to a path with no crate root"))
        .to_path_buf()
}

/// The walk itself, as a function of the crate set it is given.
///
/// Extracted from the measurement so the SENSITIVITY CONTROL can run the same apparatus
/// over a different input — ADR-MCPRE-068 Ruling 4 asks a measured proposition for the
/// demonstration that its number can still MOVE, and a control that re-implemented the walk
/// would be demonstrating that a second implementation moves.
///
/// The corpus is every Rust source a compiled target of the crate is built from: the library
/// under `src/`, and the example binaries under `examples/` the build graph also compiles.
///
/// Returns `(the files that mint a verdict token, how many files were read)`.
pub(super) fn minting_files(trees: &[(&str, &str)]) -> (BTreeSet<String>, usize) {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut files_scanned = 0usize;
    for (crate_dir, env_key) in trees {
        let crate_root = crate_root_of(env_key);
        for file in compiled_sources(&crate_root) {
            files_scanned += 1;
            if mints_a_verdict_token(&file) {
                found.insert(format!("{crate_dir}/{}", relative_to(&crate_root, &file)));
            }
        }
    }
    (found, files_scanned)
}

/// Every Rust source under the crate's compiled source directories.
fn compiled_sources(crate_root: &Path) -> Vec<PathBuf> {
    COMPILED_SOURCE_DIRS
        .iter()
        .map(|tree| crate_root.join(tree))
        .filter(|root| root.is_dir())
        .flat_map(|root| rust_sources_under(&root))
        .collect()
}

/// Whether the production half of `file` holds a verdict-token literal.
fn mints_a_verdict_token(file: &Path) -> bool {
    let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
    !Source::new(text).production_verdict_tokens().is_empty()
}

/// `file` relative to the crate root, with `/` separators.
fn relative_to(crate_root: &Path, file: &Path) -> String {
    file.strip_prefix(crate_root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every `.rs` file under `root`, recursively. std only.
fn rust_sources_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for path in children(&dir) {
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out
}

/// The entries directly under `dir`.
fn children(dir: &Path) -> Vec<PathBuf> {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    entries
        .map(|entry| {
            entry
                .unwrap_or_else(|e| panic!("dir entry under {dir:?}: {e}"))
                .path()
        })
        .collect()
}

/// The Bazel packages holding a first-party crate, from the target table.
pub(super) fn crate_packages(table: &str) -> BTreeSet<String> {
    let parsed: serde_json::Value =
        serde_json::from_str(table).unwrap_or_else(|e| panic!("the target table is not JSON: {e}"));
    let targets = parsed
        .get("targets")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("the target table has no `targets` object"));
    targets
        .values()
        .filter(|row| {
            row.get("kind")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| CRATE_KINDS.contains(&kind))
        })
        .filter_map(|row| row.get("package").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect()
}

/// The measurement, in the form the ADR-MCPRE-068 `measured://` lane reads.
///
/// A measured proposition is existential and scoped — over THIS corpus, the observed
/// value was X — and the lane preserves the result as an artifact and digests it. The
/// lines are the result; everything else the harness prints is timing and progress, which
/// two identical runs do not agree on.
pub(super) fn emit_measurement(found: &BTreeSet<String>, crates_scanned: usize) {
    println!("MEASURED: files_deciding_verdict_tokens={}", found.len());
    for file in found {
        println!("MEASURED: minting_file={file}");
    }
    println!("MEASURED: crates_scanned={crates_scanned}");
}
