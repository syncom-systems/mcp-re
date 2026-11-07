// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
//! The serving crate's source as the ownership rules see it: production halves only, over
//! the directories the rules' scope names.

use std::path::{Path, PathBuf};

/// The serving path's production half. A fixture in a test module must not be able to make
/// this gate pass or fail — and production below a test module must still be measured, so
/// the region definition is [`mcp_re_test_paths::rust_source`]'s rather than a truncation.
pub(super) fn production_half(source: &str) -> String {
    mcp_re_test_paths::rust_source::production_half(source)
}

fn serving_anchor() -> PathBuf {
    mcp_re_test_paths::resolve_runfile("MCP_RE_HTTP_PROFILE_SERVE_SRC")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

fn collect_rust_files(dir: &Path, into: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read dir {dir:?}: {e}"));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            into.push(path);
        }
    }
}

/// The sorted `.rs` files under `root`.
fn rust_files_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files);
    files.sort();
    files
}

/// The production halves of `files`, newline-joined.
///
/// Each file's production half separately: concatenating first would let one file's
/// unterminated test region swallow the next file's production code.
fn production_of_all(files: &[PathBuf]) -> String {
    files
        .iter()
        .map(|path| production_half(&read(path)) + "\n")
        .collect()
}

/// Every production line of the serving path — the assembly and every region under it.
///
/// The property is about THE SERVING PATH, not about one file of it. When the pipeline
/// became one module per region, a scan of `mod.rs` alone would have reported a clean pass
/// over an assembly that no longer contains most of the pipeline, and a region that kept an
/// `advance` beside a stage would simply have been out of scope. A gate's scope is part of
/// its measurement.
///
/// The scope is the DIRECTORY the anchor file sits in, walked, rather than a list of region
/// files: a list would have to learn about the next region, and the failure mode of a stale
/// list is a clean pass over unmeasured code. Under Bazel the directory is the runfiles
/// copy, which the target's `glob` populates; otherwise it is the source tree.
pub(super) fn serving_source() -> String {
    let anchor = serving_anchor();
    let root = anchor
        .parent()
        .unwrap_or_else(|| panic!("{anchor:?} has no parent directory"));
    let files = rust_files_under(root);
    assert!(
        files.len() > 1,
        "the serving path is one file at {root:?} — the walk found no regions, and every \
         assertion below would then be about the assembly alone"
    );
    production_of_all(&files)
}

/// The crate's `src/` directory, reached from the serving anchor.
pub(super) fn crate_src() -> PathBuf {
    let anchor = serving_anchor();
    anchor
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("{anchor:?} is not under src/"))
}

/// The production half of one file under `src/`.
pub(super) fn production_of(relative: &str) -> String {
    production_half(&read(&crate_src().join(relative)))
}

/// Every production line of the crate outside the exchange machine itself.
///
/// The refusal route is measured crate-wide, not over the serving directory: `refuse` is
/// `pub(crate)`, so a refusal entered from outside `http_profile_serve/` would be outside a
/// directory-scoped scan and report a clean pass.
pub(super) fn crate_source_outside_the_machine() -> String {
    let src = crate_src();
    let machine = src.join("exchange_state");
    let mut files = rust_files_under(&src);
    files.retain(|p| !p.starts_with(&machine) && *p != src.join("exchange_state.rs"));
    assert!(
        files.len() > 50,
        "the crate walk found {} files under {src:?}: the runfiles glob no longer carries \
         src/, and the refusal route would be measured over nothing",
        files.len()
    );
    production_of_all(&files)
}
