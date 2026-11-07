#![cfg(test)]
//! §A of the v0.5 claim matrix, parsed into capability rows and their manifest citations.

/// One §A capability row: the capability label and the set of manifest-property
/// phrases its Required-conformance cell quotes (each split on the `…`/`...`
/// ellipsis into the fragments that must ALL appear in one manifest property).
pub(super) struct ClaimRow {
    pub(super) capability: String,
    /// Each element is one quoted citation, already split into its `…` fragments.
    pub(super) cited: Vec<Vec<String>>,
}

impl ClaimRow {
    /// A citation matches when ALL of its fragments are substrings of a single manifest
    /// property; the row is mapped when any citation matches.
    pub(super) fn is_mapped_by(&self, properties: &[String]) -> bool {
        self.cited.iter().any(|frags| {
            properties
                .iter()
                .any(|p| frags.iter().all(|f| p.contains(f.as_str())))
        })
    }
}

/// The cells of a capability row of §A, or `None` for anything that is not one: a line
/// outside the table, the `---` separator, a short row, or the header.
fn capability_cells(line: &str) -> Option<Vec<&str>> {
    let t = line.trim();
    if !t.starts_with('|') || t.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ')) {
        return None;
    }
    let cells: Vec<&str> = t.trim_matches('|').split('|').map(|c| c.trim()).collect();
    (cells.len() >= 6 && !cells[0].eq_ignore_ascii_case("capability")).then_some(cells)
}

/// The `…`-split fragments of one quoted citation.
fn fragments(quoted: &str) -> Vec<String> {
    quoted
        .split(['…'])
        .flat_map(|s| s.split("..."))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse §A of the v0.5 claim matrix from DISK into its capability rows. §A is the
/// region between the `## §A` heading and the `## §B` heading; a capability row is
/// a markdown table row (`| … |`) with ≥ 6 cells that is neither the header
/// (`Capability …`) nor the `---` separator. The Required-conformance cell is the
/// 5th column (index 4); every double-quoted phrase in it is a manifest-property
/// citation, split on the `…`/`...` ellipsis into substring fragments.
pub(super) fn parse_section_a(matrix: &str) -> Vec<ClaimRow> {
    let a = matrix
        .split_once("## §A")
        .and_then(|(_, after)| after.split_once("## §B").map(|(a, _)| a))
        .unwrap_or_else(|| panic!("claim matrix has no §A/§B sections"));
    a.lines()
        .filter_map(capability_cells)
        .map(|cells| ClaimRow {
            capability: cells[0].trim_matches('*').trim().to_string(),
            cited: quoted_phrases(cells[4])
                .iter()
                .map(|q| fragments(q))
                .filter(|frags| !frags.is_empty())
                .collect(),
        })
        .collect()
}

/// Every double-quoted (`"…"`) substring of `text`.
fn quoted_phrases(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if let Some(rel) = text[i + 1..].find('"') {
                out.push(text[i + 1..i + 1 + rel].to_string());
                i = i + 1 + rel + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}
