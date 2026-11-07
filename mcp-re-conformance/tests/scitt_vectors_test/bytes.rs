// SPDX-License-Identifier: Apache-2.0
//! Patching the CBOR octets of a receipt without disturbing anything around the patch.

/// CBOR head of `inclusion-proof-content` for a two-leaf log proving leaf 1:
/// `array(3), 2, 1, array(1), bstr(32)` (RFC 9942 §5.2 Figure 3).
pub(super) const PROOF_HEAD: [u8; 6] = [0x83, 0x02, 0x01, 0x81, 0x58, 0x20];

/// CBOR for the protected-header entry `vds(395) => 1` — `uint16 395`, then `1`.
pub(super) const VDS_ENTRY: [u8; 4] = [0x19, 0x01, 0x8b, 0x01];

/// The first occurrence of `needle` in `haystack`.
pub(super) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The offset of the one and only occurrence of `needle`. Panics if the pattern is
/// absent or repeated, because a corpus writer that patched the wrong copy of an
/// ambiguous byte string would freeze a vector testing something else entirely.
pub(super) fn find_once(haystack: &[u8], needle: &[u8]) -> usize {
    let at = find(haystack, needle).unwrap_or_else(|| panic!("pattern {needle:02x?} not found"));
    assert!(
        find(&haystack[at + 1..], needle).is_none(),
        "pattern {needle:02x?} is not unique"
    );
    at
}

/// Replace `needle` with `replacement` of the SAME length, at its unique occurrence.
///
/// Equal length matters for more than convenience: it keeps every surrounding CBOR
/// length header valid, so the receipt still parses and the vector tests the check it
/// names rather than the decoder.
pub(super) fn splice(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), replacement.len(), "same-length patch");
    let at = find_once(bytes, needle);
    let mut out = bytes.to_vec();
    out[at..at + needle.len()].copy_from_slice(replacement);
    out
}
