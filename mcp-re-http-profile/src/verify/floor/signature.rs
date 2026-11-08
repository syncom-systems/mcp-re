// SPDX-License-Identifier: Apache-2.0
//! Signature verification under the RESOLVED algorithm.
//!
//! One authority: **the algorithm that was allowlisted is the algorithm that runs.** That
//! is a single fact and it is worth a module, because the alternative was the defect: every
//! path called the Ed25519 verifier unconditionally, so a policy allowlisting an
//! unimplemented algorithm accepted a message declaring it while Ed25519 was what actually
//! ran. `ProfileAlgorithm` now makes such a policy unconstructible AND this dispatch makes
//! the verifier-per-algorithm coupling a compile-time obligation.
//!
//! Getting the signature OFF THE WIRE lives here too. It is one step of one fact — the
//! bytes that are about to be checked — and separating "find the signature" from "check the
//! signature" would put a module boundary in the middle of a single act.

use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;

use crate::error::HttpProfileError;
use crate::message::single_header;
use crate::policy::ProfileAlgorithm;
use crate::digest::base64_standard_decode;

use super::sf_dictionary::member_value;

/// Which message a signature covers. Both refusal tokens follow from it, so a caller names
/// the message and cannot pair one direction's token with the other's.
///
/// `pub(crate)` because the request and response floors, the delegated full-profile
/// verifiers and the bodyless paths all verify from sibling subtrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignedMessage {
    /// A client's signed request.
    Request,
    /// A server's signed response.
    Response,
}

/// A signature and the signature base it claims to cover.
///
/// Verifying one without the other is meaningless, so they travel as one value and a caller
/// cannot pair the base of one message with the signature of another through two operands.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignatureOver<'a> {
    /// The signature base the signature is checked over.
    base: &'a [u8],
    /// The signature, base64url as the core verifier consumes it.
    sig: &'a str,
}

impl<'a> SignatureOver<'a> {
    /// `sig`, the base64url signature, claimed over the signature base `base`.
    pub(crate) fn new(base: &'a [u8], sig: &'a str) -> Self {
        Self { base, sig }
    }
}

/// Verify the signature in `over` under the RESOLVED algorithm.
///
/// The match is exhaustive over [`ProfileAlgorithm`], which is the point: a new
/// algorithm variant does not compile until its verifier is wired here. Before
/// this existed, every path called the Ed25519 verifier unconditionally, so a
/// policy that allowlisted an unimplemented algorithm accepted a message
/// declaring it while Ed25519 was what actually ran — algorithm confusion. The
/// policy now makes such a set unconstructible AND this dispatch makes the
/// verifier-per-algorithm coupling explicit rather than assumed.
pub(crate) fn verify_under(
    algorithm: ProfileAlgorithm,
    over: SignatureOver<'_>,
    key: &mcp_re_core::VerificationKey,
    message: SignedMessage,
) -> Result<(), HttpProfileError> {
    let (on_fail, failure) = match message {
        SignedMessage::Request => (
            McpReError::InvalidSignature,
            HttpProfileError::InvalidSignature,
        ),
        SignedMessage::Response => (
            McpReError::ResponseSigInvalid,
            HttpProfileError::ResponseSignatureInvalid,
        ),
    };
    match algorithm {
        ProfileAlgorithm::Ed25519 => {
            verify_ed25519_with(over.base, over.sig, key, on_fail).map_err(|_| failure)
        }
    }
}

/// The `Signature` header's byte sequence for `label`, transcoded to the
/// base64url form the core verifier consumes.
pub(crate) fn signature_value_b64url(
    headers: &[(String, String)],
    header_error: &'static str,
    label: &str,
) -> Result<String, HttpProfileError> {
    let signature_header = single_header(headers, "signature")?
        .ok_or(HttpProfileError::MissingEvidence(header_error))?;
    let member = member_value(signature_header, label)?;
    let b64 = member
        .strip_prefix(':')
        .and_then(|s| s.strip_suffix(':'))
        .ok_or(HttpProfileError::MalformedEvidence(
            "signature byte sequence",
        ))?;
    let bytes = base64_standard_decode(b64)?;
    Ok(mcp_re_core::b64url_encode(&bytes))
}
