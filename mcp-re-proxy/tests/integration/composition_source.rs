//! The composition root's production text, for the guards that read it as source.
//!
//! The root is `app.rs` and the stages under `app/`: the guards state facts about the whole
//! startup sequence, which the root file alone no longer holds. The text is the production
//! half of each file, the root first and its children in path order.

use mcp_re_test_paths::rust_source::production_half;

/// Production text of `app.rs` followed by every `app/*.rs` stage.
pub(crate) fn composition_production() -> String {
    let root = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    let stages = root.with_extension("");
    let mut children: Vec<_> = std::fs::read_dir(&stages)
        .unwrap_or_else(|e| panic!("read dir {stages:?}: {e}"))
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    children.sort();
    std::iter::once(root)
        .chain(children)
        .map(|path| {
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            production_half(&text)
        })
        .collect::<Vec<_>>()
        .join("\n")
}
