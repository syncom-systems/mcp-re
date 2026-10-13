// SPDX-License-Identifier: Apache-2.0
//! The one refusal type both SDK bindings raise.

use mcp_re_client_core::BindingSpecRefusal;
use mcp_re_client_core::HttpProfileError;

/// A pinned root-issuer identity field. Each binding names it in its own host's spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerField {
    KeyId,
    Role,
    TrustDomain,
    Subject,
}

/// Why a binding call was refused.
///
/// `Wire` carries a frozen `mcp-re.*` token, and [`BindingError::message`] renders it as
/// `mcp-re: <token>` — the one place that rendering is written. `Local` is a refusal of the
/// caller's arguments that no server verdict describes. `EmptyIssuerField` is kept apart
/// from `Local` because its message names the field, and the name is the host's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    Wire(&'static str),
    Local(String),
    EmptyIssuerField(IssuerField),
}

impl BindingError {
    /// The message a host raises for this refusal, naming an issuer field with `field_name`.
    pub fn message(&self, field_name: impl Fn(IssuerField) -> &'static str) -> String {
        match self {
            BindingError::Wire(code) => format!("mcp-re: {code}"),
            BindingError::Local(reason) => reason.clone(),
            BindingError::EmptyIssuerField(field) => {
                format!("invalid issuer identity: {} is empty", field_name(*field))
            }
        }
    }
}

impl From<HttpProfileError> for BindingError {
    fn from(e: HttpProfileError) -> Self {
        BindingError::Wire(e.wire_code())
    }
}

impl From<BindingSpecRefusal> for BindingError {
    fn from(r: BindingSpecRefusal) -> Self {
        BindingError::Wire(r.wire_code())
    }
}

#[cfg(test)]
mod tests {
    use super::BindingError;
    use super::IssuerField;
    use mcp_re_client_core::HttpProfileError;

    fn snake(field: IssuerField) -> &'static str {
        match field {
            IssuerField::KeyId => "issuer_key_id",
            IssuerField::Role => "issuer_role",
            IssuerField::TrustDomain => "issuer_trust_domain",
            IssuerField::Subject => "issuer_subject",
        }
    }

    #[test]
    fn a_wire_refusal_renders_its_frozen_token_after_the_prefix() {
        let e = BindingError::from(HttpProfileError::InvalidSignature);
        assert_eq!(e.message(snake), "mcp-re: mcp-re.invalid_signature");
    }

    #[test]
    fn a_local_refusal_renders_its_reason_verbatim_and_a_field_by_the_host_name() {
        assert_eq!(
            BindingError::Local("params must be a JSON object".into()).message(snake),
            "params must be a JSON object"
        );
        assert_eq!(
            BindingError::EmptyIssuerField(IssuerField::TrustDomain).message(snake),
            "invalid issuer identity: issuer_trust_domain is empty"
        );
    }
}
