//! A token's identity as the token reported it, and the check that the token now in a slot
//! is the one selected at open.

use cryptoki_sys::CK_SLOT_ID;
use cryptoki_sys::CK_TOKEN_INFO;

use super::Pkcs11Error;

/// The label and serial number a token reported through `C_GetTokenInfo`, with the
/// fixed-field padding trimmed. Built only from a token's own report, so holding one
/// means these are bytes a token presented, compared as bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenIdentity {
    label: Vec<u8>,
    serial: Vec<u8>,
}

impl TokenIdentity {
    pub(super) fn from_info(info: &CK_TOKEN_INFO) -> Self {
        Self {
            label: trim_ck_field(&info.label),
            serial: trim_ck_field(&info.serialNumber),
        }
    }

    /// The trimmed token label bytes.
    pub fn label(&self) -> &[u8] {
        &self.label
    }
}

/// Refuse to proceed unless the token now in `slot` is the one selected at open.
pub(super) fn verify_selected_token(
    slot: CK_SLOT_ID,
    expected: &TokenIdentity,
    observed: TokenIdentity,
) -> Result<(), Pkcs11Error> {
    if *expected == observed {
        return Ok(());
    }
    Err(Pkcs11Error::Protocol(format!(
        "token in slot {slot} is not the token selected at open (label or serial changed); \
         refusing to send the User PIN"
    )))
}

/// Trim the trailing 0x20 (space) padding PKCS#11 uses for the fixed-width
/// `CK_TOKEN_INFO` text fields (label, serial number) and return the remaining BYTES. A non-space NUL is also
/// trimmed defensively.
///
/// Bytes, not a `String`: a lossy rendering maps every invalid UTF-8 sequence to U+FFFD,
/// so two tokens whose labels differ only in invalid bytes render equal — and the label
/// decides which physical device receives the User PIN.
fn trim_ck_field(label: &[u8]) -> Vec<u8> {
    let end = label
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    label[..end].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn padded_label(bytes: &[u8]) -> [u8; 32] {
        let mut label = [b' '; 32];
        for (slot, byte) in label.iter_mut().zip(bytes.iter()) {
            *slot = *byte;
        }
        label
    }

    /// The PKCS#11 label field is a fixed 32 bytes padded with 0x20. Only that padding
    /// (and a defensive NUL) is trailing noise; an interior space is part of the label.
    #[test]
    fn a_token_label_keeps_its_interior_bytes_and_loses_only_its_padding() {
        assert_eq!(trim_ck_field(&padded_label(b"my token")), &b"my token"[..]);
        assert_eq!(trim_ck_field(&padded_label(b"")), &b""[..]);
        let mut nul_padded = padded_label(b"tok");
        nul_padded[3] = 0;
        assert_eq!(trim_ck_field(&nul_padded), &b"tok"[..]);
    }

    /// The NEGATIVE test for label aliasing: two tokens whose labels differ only in
    /// INVALID UTF-8 must stay distinguishable. Restoring a `String::from_utf8_lossy`
    /// rendering maps both byte sequences to U+FFFD and turns this red.
    #[test]
    fn byte_distinct_token_labels_do_not_compare_equal() {
        let first = trim_ck_field(&padded_label(&[b't', 0xC3, 0x28]));
        let second = trim_ck_field(&padded_label(&[b't', 0xE2, 0x28]));
        assert_ne!(
            first, second,
            "the label decides which device receives the User PIN, so equality is over \
             the bytes the token reported"
        );
    }

    /// The POSITIVE control for the same change: the labels an operator actually
    /// configures are UTF-8, and they must still match byte-for-byte.
    #[test]
    fn an_ordinary_utf8_label_still_matches_its_configured_form() {
        let configured = "mcp-re-tøken";
        assert_eq!(
            trim_ck_field(&padded_label(configured.as_bytes())),
            configured.as_bytes(),
            "a label a deployment can actually set must still select its slot"
        );
    }

    fn identity(label: &[u8], serial: &[u8]) -> TokenIdentity {
        // SAFETY: CK_TOKEN_INFO is a plain C struct of byte arrays and integer words;
        // all-zero is a valid value.
        let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
        info.label = padded_label(label);
        info.serialNumber = [b' '; 16];
        for (dst, src) in info.serialNumber.iter_mut().zip(serial) {
            *dst = *src;
        }
        TokenIdentity::from_info(&info)
    }

    #[test]
    fn a_token_under_the_selected_label_with_another_serial_does_not_receive_the_pin() {
        let selected = identity(b"prod", b"0001");
        assert!(matches!(
            verify_selected_token(3, &selected, identity(b"prod", b"0002")),
            Err(Pkcs11Error::Protocol(_))
        ));
        assert!(matches!(
            verify_selected_token(3, &selected, identity(b"other", b"0001")),
            Err(Pkcs11Error::Protocol(_))
        ));
        assert!(verify_selected_token(3, &selected, identity(b"prod", b"0001")).is_ok());
    }
}
