// SPDX-License-Identifier: Apache-2.0
//! Keys, frozen instants and the signed messages several vector groups start from.

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::RequestRoleEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

// Fixed, documented TEST-ONLY seeds; the corpus is deterministic end-to-end.
const CLIENT_SEED: [u8; 32] = [11u8; 32];
const SERVER_SEED: [u8; 32] = [22u8; 32];
pub(super) const CREATED: i64 = 1_700_000_000;
pub(super) const EXPIRES: i64 = 1_700_000_300;
/// The frozen verification instant every runner uses.
pub(super) const NOW: i64 = 1_700_000_100;

pub(super) const CLIENT_KEY_ID: &str = "client-key-1";
pub(super) const SERVER_KEY_ID: &str = "server-key-1";

pub(super) const MCP_ENDPOINT: &str = "https://mcp.example.com/mcp";
pub(super) const JSON: &str = "application/json";

pub(super) fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}

pub(super) fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}

/// Slot-aware trust seam (MCPRE-100): the client key is trusted only for the
/// Request slot, the server key only for the Response slot.
pub(super) fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_key()),
            (SERVER_KEY_ID, SignerSlot::Response) => ("server", server_key()),
            _ => return None,
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: format!("did:example:{role}"),
                keyid: key_id.into(),
            },
            verification_key: key.public_key(),
            slot,
        })
    }
}

/// An unsigned POST to the endpoint carrying `body` and the given extra headers
/// after `Content-Type`.
pub(super) fn post(extra_headers: &[(&str, &str)], body: &[u8]) -> HttpRequest {
    let mut headers: Vec<(String, String)> = vec![("Content-Type".into(), JSON.into())];
    headers.extend(
        extra_headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    HttpRequest {
        method: "POST".into(),
        target_uri: MCP_ENDPOINT.into(),
        headers,
        body: body.to_vec(),
    }
}

pub(super) const READ_CALL: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;

pub(super) fn base_request() -> HttpRequest {
    post(&[], READ_CALL)
}

/// Sign `request` with the client key over the frozen window.
pub(super) fn sign_as_client(request: &mut HttpRequest, nonce: &str) -> RequestRoleEvidence {
    sign_request(
        request,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        nonce,
    )
    .expect("signing succeeds")
}

/// The base request signed by the client, with the evidence its signature produced.
pub(super) fn signed_valid() -> (HttpRequest, RequestRoleEvidence) {
    let mut request = base_request();
    let evidence = sign_as_client(&mut request, "vec-nonce-1");
    (request, evidence)
}

/// The fully signed request the response and rejection vectors bind to.
pub(super) fn valid_request() -> HttpRequest {
    signed_valid().0
}

/// The base request signed by the client under `target_uri`, for splice vectors.
pub(super) fn signed_at(target_uri: &str, nonce: &str) -> HttpRequest {
    let mut request = base_request();
    request.target_uri = target_uri.into();
    sign_as_client(&mut request, nonce);
    request
}

/// The request headers whose frozen value an oracle pins.
#[derive(Clone, Copy)]
pub(super) enum Header {
    ContentDigest,
    Signature,
}

impl Header {
    fn name(self) -> &'static str {
        match self {
            Header::ContentDigest => "content-digest",
            Header::Signature => "signature",
        }
    }
}

/// The value of the first `header` on `request`, compared case-insensitively.
pub(super) fn header_value(request: &HttpRequest, header: Header) -> String {
    let name = header.name();
    request
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .unwrap_or_else(|| panic!("{name} header present"))
        .1
        .clone()
}

/// A change to the covered component list a message states in `Signature-Input`, with the
/// signature itself left untouched.
#[derive(Clone, Copy)]
pub(super) enum SignatureInputEdit {
    DropContentDigest,
    ForeignProfileTag,
    UnlistedAlgorithm,
    DropMcpMethod,
    DropDelegationCredential,
}

impl SignatureInputEdit {
    fn replacement(self) -> (&'static str, &'static str) {
        match self {
            Self::DropContentDigest => (" \"content-digest\"", ""),
            Self::ForeignProfileTag => ("tag=\"mcp-re-http-v1\"", "tag=\"not-mcp-re\""),
            Self::UnlistedAlgorithm => ("alg=\"ed25519\"", "alg=\"ml-dsa-65\""),
            Self::DropMcpMethod => (" \"mcp-method\"", ""),
            Self::DropDelegationCredential => (" \"mcp-re-delegation\"", ""),
        }
    }

    /// Apply the edit to the `Signature-Input` header among `headers`.
    pub(super) fn apply_to(self, headers: &mut [(String, String)]) {
        let (from, to) = self.replacement();
        for header in headers.iter_mut() {
            if header.0.eq_ignore_ascii_case("signature-input") {
                header.1 = header.1.replace(from, to);
            }
        }
    }
}

/// `request` with its `Signature-Input` edited.
pub(super) fn edit_signature_input(request: &HttpRequest, edit: SignatureInputEdit) -> HttpRequest {
    let mut edited = request.clone();
    edit.apply_to(&mut edited.headers);
    edited
}
