// SPDX-License-Identifier: Apache-2.0
//! The canonical bytes of one audit event (ADR-MCPRE-070 D5).
//!
//! Fixed-schema, length-delimited, big-endian, with exactly one encoding per value:
//!
//! ```text
//! off  size  field
//! 0    1     version = 0x01
//! 1    16    id.run
//! 17   8     id.seq            i64 BE, 0 <= seq < i64::MAX
//! 25   1     scope             0x01 Origin | 0x02 Exchange | 0x03 PreAcceptance
//! 26   24    (Exchange only)   coordinate.run[16] || coordinate.seq i64 BE
//! ..   2     field count       u16 BE
//! ..         per field: class u8, then its payload
//!              0x00 Absent   nothing
//!              0x01 Token    u32 BE length || UTF-8
//!              0x02 Number   i64 BE
//!              0x03 Text     u32 BE length || UTF-8
//! ```
//!
//! The field sequence is exactly the record's own `audit_fields()`: the owners' facets are
//! projected, never re-derived (ADR-MCPRE-066 invariant 5). Names are not encoded, because
//! position is schema; the class byte is, because `Token("none")` and `Text("none")` are
//! different facts. There are no varints, no optional padding and no alternative forms, so
//! two encodings of one event are equal byte for byte.
//!
//! # Version and migration
//!
//! - The writer emits exactly [`CANONICAL_VERSION`].
//! - An event's bytes are fixed when it is produced and are never re-encoded: a retry
//!   resends the same bytes.
//! - Any change to the header, the class set, the event set or any arm's field sequence is a
//!   new version. `every_enumerable_record_matches_the_v1_schema_table` fails on such a
//!   change until the version moves with it.
//! - While no commitment provider exists, no canonical bytes leave the process, so a version
//!   change replaces its predecessor whole. From the first provider on, each prior version's
//!   golden vectors are kept and the set of versions a reader accepts is declared.

use super::{EventId, EventIdentityFailure, EventScope};
use crate::audit_record::text::{AuditField, AuditValue};

/// The one version this writer emits.
pub const CANONICAL_VERSION: u8 = 1;

const SCOPE_ORIGIN: u8 = 0x01;
const SCOPE_EXCHANGE: u8 = 0x02;
const SCOPE_PRE_ACCEPTANCE: u8 = 0x03;

const CLASS_ABSENT: u8 = 0x00;
const CLASS_TOKEN: u8 = 0x01;
const CLASS_NUMBER: u8 = 0x02;
const CLASS_TEXT: u8 = 0x03;

/// The canonical bytes of the event `id`, in `scope`, carrying `fields`.
///
/// [`EventIdentityFailure::Unencodable`] when there are more fields than a `u16` counts or
/// a value longer than a `u32` delimits — never a truncated or wrapped length.
pub(super) fn encode(
    id: &EventId,
    scope: &EventScope,
    fields: &[AuditField<'_>],
) -> Result<Vec<u8>, EventIdentityFailure> {
    let mut out = vec![CANONICAL_VERSION];
    push_id(&mut out, id);
    match scope {
        EventScope::Origin => out.push(SCOPE_ORIGIN),
        EventScope::Exchange(coordinate) => {
            out.push(SCOPE_EXCHANGE);
            push_id(&mut out, &coordinate.accepted_event());
        }
        EventScope::PreAcceptance => out.push(SCOPE_PRE_ACCEPTANCE),
    }
    let count = u16::try_from(fields.len()).map_err(|_| EventIdentityFailure::Unencodable)?;
    out.extend_from_slice(&count.to_be_bytes());
    for field in fields {
        push_value(&mut out, &field.value)?;
    }
    Ok(out)
}

fn push_id(out: &mut Vec<u8>, id: &EventId) {
    let (run, seq) = id.parts();
    out.extend_from_slice(&run.bytes());
    out.extend_from_slice(&seq.to_be_bytes());
}

fn push_value(out: &mut Vec<u8>, value: &AuditValue<'_>) -> Result<(), EventIdentityFailure> {
    match value {
        AuditValue::Absent => out.push(CLASS_ABSENT),
        AuditValue::Token(token) => push_delimited(out, CLASS_TOKEN, token)?,
        AuditValue::Number(n) => {
            out.push(CLASS_NUMBER);
            out.extend_from_slice(&n.to_be_bytes());
        }
        AuditValue::Text(text) => push_delimited(out, CLASS_TEXT, text)?,
    }
    Ok(())
}

fn push_delimited(out: &mut Vec<u8>, class: u8, value: &str) -> Result<(), EventIdentityFailure> {
    let len = u32::try_from(value.len()).map_err(|_| EventIdentityFailure::Unencodable)?;
    out.push(class);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The golden vectors below are assembled BY HAND from the layout in the module
    //! documentation, one byte literal per field, and never printed from the encoder: a
    //! vector copied from the encoder's own output pins whatever the encoder does.

    use super::*;
    use crate::admission_enforcer::{AdmissionFacet, AdmissionRefusalClass};
    use crate::audit_record::envelope::{ContentDigest, ExchangeCoordinate, RunId};
    use crate::audit_record::{AuditRecord, AuditSubject};
    use crate::authorization::{
        AuthorizationFacet, AuthorizationPosture, AuthorizationRefusalFacet,
    };
    use mcp_re_core::McpReError;
    use mcp_re_policy::PolicyError;

    const RUN: RunId = RunId::fixed([0x11; 16]);

    fn id(seq: i64) -> EventId {
        EventId::new(RUN, seq)
    }

    fn exchange() -> EventScope {
        EventScope::Exchange(ExchangeCoordinate::of_accepted(id(3)))
    }

    fn accepted() -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::request_accepted(
                &AuthorizationPosture::NoPolicyConfigured,
                AdmissionFacet::NotConfigured,
            ),
            actor_id: Some("actor-a".into()),
            status: 200,
            at_unix: 10,
        }
    }

    fn digest_rejected() -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::request_rejected(
                Some(&McpReError::DigestMismatch),
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
                AdmissionFacet::NotReached,
            ),
            actor_id: None,
            status: 401,
            at_unix: 1,
        }
    }

    fn policy_refused_at_admission() -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::request_refused_at_admission(
                None,
                AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(
                    PolicyError::AuthorizationScopeDenied,
                )),
                AdmissionRefusalClass::NoRecord,
            ),
            actor_id: Some("did:example:agent-1".into()),
            status: 403,
            at_unix: -1,
        }
    }

    fn signed() -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::response_signed(),
            actor_id: Some("actor-a".into()),
            status: 200,
            at_unix: 10,
        }
    }

    fn response_rejected_elsewhere() -> AuditRecord {
        AuditRecord {
            subject: AuditSubject::response_rejected(None),
            actor_id: Some("actor-a".into()),
            status: 500,
            at_unix: 10,
        }
    }

    fn encoded(record: &AuditRecord, seq: i64, scope: &EventScope) -> Vec<u8> {
        encode(&id(seq), scope, &record.audit_fields()).expect("a record encodes")
    }

    /// The header every vector shares: version 1, run 0x11 x 16, seq 7.
    const HEADER: [u8; 25] = [
        0x01, // version
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // run
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // seq = 7
    ];

    /// The Exchange scope of the response vectors: tag, then the coordinate (run, 3).
    const EXCHANGE_SCOPE: [u8; 25] = [
        0x02, // scope Exchange
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // coordinate run
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // coordinate seq = 3
    ];

    /// (a) request.accepted, Origin, no policy, no admission gate, attributed.
    fn golden_accepted() -> Vec<u8> {
        [
            &HEADER[..],
            &[0x01],       // scope Origin
            &[0x00, 0x08], // 8 fields
            &[0x01, 0x00, 0x00, 0x00, 0x17],
            b"mcp-re.request.accepted", // event Token(23)
            &[0x01, 0x00, 0x00, 0x00, 0x08],
            b"Accepted", // decision Token(8)
            &[0x00],     // reason Absent
            &[0x03, 0x00, 0x00, 0x00, 0x07],
            b"actor-a",                                              // actor Text(7)
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8], // status 200
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a], // at 10
            &[0x01, 0x00, 0x00, 0x00, 0x0e],
            b"not-configured", // authz Token(14)
            &[0x01, 0x00, 0x00, 0x00, 0x0e],
            b"not-configured", // admission Token(14)
        ]
        .concat()
    }

    /// (b) request.rejected, PreAcceptance, Core reason, refused before policy, unattributed.
    fn golden_digest_rejected() -> Vec<u8> {
        [
            &HEADER[..],
            &[0x03],       // scope PreAcceptance
            &[0x00, 0x08], // 8 fields
            &[0x01, 0x00, 0x00, 0x00, 0x17],
            b"mcp-re.request.rejected", // event Token(23)
            &[0x01, 0x00, 0x00, 0x00, 0x08],
            b"Rejected", // decision Token(8)
            &[0x01, 0x00, 0x00, 0x00, 0x16],
            b"mcp-re.digest_mismatch", // reason Token(22)
            &[0x00],                   // actor Absent
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x91], // status 401
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], // at 1
            &[0x01, 0x00, 0x00, 0x00, 0x15],
            b"refused-before-policy", // authz Token(21)
            &[0x01, 0x00, 0x00, 0x00, 0x0b],
            b"not-reached", // admission Token(11)
        ]
        .concat()
    }

    /// (c) request.rejected with no Core reason, a policy refusal, and an admission refusal
    /// naming its class.
    fn golden_policy_refused_at_admission() -> Vec<u8> {
        [
            &HEADER[..],
            &[0x03],       // scope PreAcceptance
            &[0x00, 0x0a], // 10 fields
            &[0x01, 0x00, 0x00, 0x00, 0x17],
            b"mcp-re.request.rejected", // event Token(23)
            &[0x01, 0x00, 0x00, 0x00, 0x08],
            b"Rejected", // decision Token(8)
            &[0x00],     // reason Absent
            &[0x03, 0x00, 0x00, 0x00, 0x13],
            b"did:example:agent-1", // actor Text(19)
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x93], // status 403
            &[0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // at -1
            &[0x01, 0x00, 0x00, 0x00, 0x11],
            b"refused-by-policy", // authz Token(17)
            &[0x01, 0x00, 0x00, 0x00, 0x21],
            b"mcp-re.authorization_scope_denied", // Token(33)
            &[0x01, 0x00, 0x00, 0x00, 0x07],
            b"refused", // admission Token(7)
            &[0x01, 0x00, 0x00, 0x00, 0x09],
            b"no-record", // admission_refusal
        ]
        .concat()
    }

    /// (d) response.signed, in the exchange whose accepted event is (run, 3).
    fn golden_signed() -> Vec<u8> {
        [
            &HEADER[..],
            &EXCHANGE_SCOPE,
            &[0x00, 0x06], // 6 fields
            &[0x01, 0x00, 0x00, 0x00, 0x16],
            b"mcp-re.response.signed", // event Token(22)
            &[0x01, 0x00, 0x00, 0x00, 0x06],
            b"Signed", // decision Token(6)
            &[0x00],   // reason Absent
            &[0x03, 0x00, 0x00, 0x00, 0x07],
            b"actor-a",                                              // actor Text(7)
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8], // status 200
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a], // at 10
        ]
        .concat()
    }

    /// (e) response.rejected with no Core reason, in the same exchange.
    fn golden_response_rejected_elsewhere() -> Vec<u8> {
        [
            &HEADER[..],
            &EXCHANGE_SCOPE,
            &[0x00, 0x06], // 6 fields
            &[0x01, 0x00, 0x00, 0x00, 0x18],
            b"mcp-re.response.rejected", // event Token(24)
            &[0x01, 0x00, 0x00, 0x00, 0x08],
            b"Rejected", // decision Token(8)
            &[0x00],     // reason Absent
            &[0x03, 0x00, 0x00, 0x00, 0x07],
            b"actor-a",                                              // actor Text(7)
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf4], // status 500
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a], // at 10
        ]
        .concat()
    }

    /// (f) The authorized arm's field shape, with a client-named target holding the spelling
    /// of a token, a NUL, a LF and a non-ASCII character. Built as fields rather than through
    /// the authority because a real grant's `authz_evidence` is a digest over a request
    /// signed with a fresh nonce, so no fixed vector covers it; the arm's field sequence is
    /// pinned against the real authority by the schema table below.
    fn authorized_fields() -> Vec<AuditField<'static>> {
        vec![
            AuditField::token("authz", "authorized"),
            AuditField::text("authz_authority", "acme"),
            AuditField::text("authz_version", "1"),
            AuditField::text("authz_decision_id", "d-1"),
            AuditField::text("authz_decision_evidence", "sha-256:x"),
            AuditField::text("authz_operation", "tools/call"),
            AuditField::text("authz_target", "none\u{0}\n\u{e9}"),
            AuditField::text("authz_evidence", "e"),
        ]
    }

    fn golden_authorized_fields() -> Vec<u8> {
        [
            &HEADER[..],
            &[0x01],       // scope Origin
            &[0x00, 0x08], // 8 fields
            &[0x01, 0x00, 0x00, 0x00, 0x0a],
            b"authorized", // authz Token(10)
            &[0x03, 0x00, 0x00, 0x00, 0x04],
            b"acme", // authority Text(4)
            &[0x03, 0x00, 0x00, 0x00, 0x01],
            b"1", // version Text(1)
            &[0x03, 0x00, 0x00, 0x00, 0x03],
            b"d-1", // decision_id Text(3)
            &[0x03, 0x00, 0x00, 0x00, 0x09],
            b"sha-256:x", // decision_evidence Text(9)
            &[0x03, 0x00, 0x00, 0x00, 0x0a],
            b"tools/call", // operation Text(10)
            &[0x03, 0x00, 0x00, 0x00, 0x08],
            b"none\x00\n\xc3\xa9", // target Text(8), raw bytes
            &[0x03, 0x00, 0x00, 0x00, 0x01],
            b"e", // evidence Text(1)
        ]
        .concat()
    }

    #[test]
    fn the_v1_golden_vectors_are_byte_exact() {
        assert_eq!(
            encoded(&accepted(), 7, &EventScope::Origin),
            golden_accepted()
        );
        assert_eq!(
            encoded(&digest_rejected(), 7, &EventScope::PreAcceptance),
            golden_digest_rejected()
        );
        assert_eq!(
            encoded(
                &policy_refused_at_admission(),
                7,
                &EventScope::PreAcceptance
            ),
            golden_policy_refused_at_admission()
        );
        assert_eq!(encoded(&signed(), 7, &exchange()), golden_signed());
        assert_eq!(
            encoded(&response_rejected_elsewhere(), 7, &exchange()),
            golden_response_rejected_elsewhere()
        );
        assert_eq!(
            encode(&id(7), &EventScope::Origin, &authorized_fields()).expect("encodes"),
            golden_authorized_fields()
        );
    }

    /// The content identity of two vectors, computed independently of this crate:
    /// `xxd -r -p | (printf 'mcp-re-audit-v1/envelope\0'; cat) | shasum -a 256`.
    #[test]
    fn the_v1_golden_digests_are_pinned() {
        assert_eq!(
            ContentDigest::of(&golden_accepted()).to_string(),
            "7100f871fdd6afd939773491eeaff79d98ee64fddf225e6fe132042181791788"
        );
        assert_eq!(
            ContentDigest::of(&golden_signed()).to_string(),
            "5b2bfb624cffed65c92ccc47cbb921d41dc1c18c14a507bfa868c901e39a3d70"
        );
    }

    #[test]
    fn encoding_is_deterministic() {
        for _ in 0..3 {
            assert_eq!(
                encoded(&accepted(), 7, &EventScope::Origin),
                encoded(&accepted(), 7, &EventScope::Origin)
            );
            assert_eq!(encoded(&signed(), 7, &exchange()), golden_signed());
        }
    }

    /// One changed fact anywhere — identity, scope, or any field — is a changed encoding and
    /// a changed digest.
    #[test]
    fn each_field_change_changes_the_bytes() {
        let base = accepted();
        let mut variants = vec![
            encoded(&base, 7, &EventScope::Origin),
            encoded(&base, 8, &EventScope::Origin),
            encode(
                &EventId::new(RunId::fixed([0x12; 16]), 7),
                &EventScope::Origin,
                &base.audit_fields(),
            )
            .expect("encodes"),
            encoded(&base, 7, &EventScope::PreAcceptance),
            encoded(&base, 7, &exchange()),
            encoded(&digest_rejected(), 7, &EventScope::Origin),
        ];
        let mut push = |change: fn(&mut AuditRecord)| {
            let mut record = accepted();
            change(&mut record);
            variants.push(encoded(&record, 7, &EventScope::Origin));
        };
        push(|r| r.actor_id = None);
        push(|r| r.actor_id = Some("actor-b".into()));
        push(|r| r.actor_id = Some(String::new()));
        push(|r| r.status = 201);
        push(|r| r.at_unix = 11);
        push(|r| {
            r.subject = AuditSubject::request_accepted(
                &AuthorizationPosture::NoPolicyConfigured,
                AdmissionFacet::LiveConfirmed,
            )
        });
        push(|r| {
            r.subject = AuditSubject::request_rejected(
                None,
                AuthorizationFacet::NotConfigured,
                AdmissionFacet::NotConfigured,
            )
        });
        let digests: Vec<String> = variants
            .iter()
            .map(|v| ContentDigest::of(v).to_string())
            .collect();
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate().skip(i + 1) {
                assert_ne!(a, b, "variants {i} and {j} encode alike");
                assert_ne!(digests[i], digests[j], "variants {i} and {j} digest alike");
            }
        }
    }

    #[test]
    fn a_token_and_text_of_one_spelling_encode_differently() {
        let token = encode(
            &id(7),
            &EventScope::Origin,
            &[AuditField::token("t", "none")],
        );
        let text = encode(
            &id(7),
            &EventScope::Origin,
            &[AuditField::text("t", "none")],
        );
        assert_ne!(token.expect("encodes"), text.expect("encodes"));
    }

    #[test]
    fn absent_and_empty_text_encode_differently() {
        let absent = encode(
            &id(7),
            &EventScope::Origin,
            &[AuditField::text_or_absent("t", None::<&str>)],
        );
        let empty = encode(&id(7), &EventScope::Origin, &[AuditField::text("t", "")]);
        assert_ne!(absent.expect("encodes"), empty.expect("encodes"));
    }

    // ---- the strict reference reader ------------------------------------------------------

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Value {
        Absent,
        Token(String),
        Number(i64),
        Text(String),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Scope {
        Origin,
        Exchange([u8; 16], i64),
        PreAcceptance,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Decoded {
        run: [u8; 16],
        seq: i64,
        scope: Scope,
        values: Vec<Value>,
    }

    struct Cursor<'a>(&'a [u8]);

    impl<'a> Cursor<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
            if self.0.len() < n {
                return Err(format!("truncated: wanted {n}, have {}", self.0.len()));
            }
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            Ok(head)
        }
        fn byte(&mut self) -> Result<u8, String> {
            Ok(self.take(1)?[0])
        }
        fn run(&mut self) -> Result<[u8; 16], String> {
            Ok(self.take(16)?.try_into().expect("16 bytes"))
        }
        fn i64(&mut self) -> Result<i64, String> {
            Ok(i64::from_be_bytes(
                self.take(8)?.try_into().expect("8 bytes"),
            ))
        }
        fn utf8(&mut self) -> Result<String, String> {
            let len = u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes"));
            let bytes = self.take(usize::try_from(len).expect("u32 fits"))?;
            String::from_utf8(bytes.to_vec()).map_err(|e| format!("not UTF-8: {e}"))
        }
    }

    /// Reads exactly one canonical v1 event and refuses everything else.
    fn read(bytes: &[u8]) -> Result<Decoded, String> {
        let mut c = Cursor(bytes);
        let version = c.byte()?;
        if version != 0x01 {
            return Err(format!("version {version}"));
        }
        let (run, seq) = (c.run()?, c.i64()?);
        if !(0..i64::MAX).contains(&seq) {
            return Err(format!("seq {seq} outside 0..i64::MAX"));
        }
        let scope = match c.byte()? {
            0x01 => Scope::Origin,
            0x02 => {
                let (r, s) = (c.run()?, c.i64()?);
                if r != run || !(0..seq).contains(&s) {
                    return Err("the coordinate is not an earlier event of this run".into());
                }
                Scope::Exchange(r, s)
            }
            0x03 => Scope::PreAcceptance,
            tag => return Err(format!("scope tag {tag}")),
        };
        let count = u16::from_be_bytes(c.take(2)?.try_into().expect("2 bytes"));
        let mut values = Vec::new();
        for _ in 0..count {
            values.push(match c.byte()? {
                0x00 => Value::Absent,
                0x01 => Value::Token(c.utf8()?),
                0x02 => Value::Number(c.i64()?),
                0x03 => Value::Text(c.utf8()?),
                class => return Err(format!("class {class}")),
            });
        }
        if !c.0.is_empty() {
            return Err(format!("{} trailing byte(s)", c.0.len()));
        }
        check_schema(&scope, &values)?;
        Ok(Decoded {
            run,
            seq,
            scope,
            values,
        })
    }

    fn token(values: &[Value], at: usize) -> Result<&str, String> {
        match values.get(at) {
            Some(Value::Token(t)) => Ok(t),
            other => Err(format!("field {at} is {other:?}, not a token")),
        }
    }

    /// The v1 schema, by position: the six exchange-wide fields, and for a request the
    /// authorization group and the admission group.
    fn check_schema(scope: &Scope, values: &[Value]) -> Result<(), String> {
        let (event, decision) = (token(values, 0)?, token(values, 1)?);
        let request = match (event, decision, scope) {
            ("mcp-re.request.accepted", "Accepted", Scope::Origin)
            | ("mcp-re.request.rejected", "Rejected", Scope::PreAcceptance) => true,
            ("mcp-re.response.signed", "Signed", Scope::Exchange(..))
            | ("mcp-re.response.rejected", "Rejected", Scope::Exchange(..)) => false,
            other => return Err(format!("event, decision and scope disagree: {other:?}")),
        };
        let header_ok = matches!(values.get(2), Some(Value::Token(_) | Value::Absent))
            && matches!(values.get(3), Some(Value::Text(_) | Value::Absent))
            && matches!(values.get(4), Some(Value::Number(_)))
            && matches!(values.get(5), Some(Value::Number(_)));
        if !header_ok {
            return Err("the exchange-wide fields are malformed".into());
        }
        let rest = values.get(6..).unwrap_or_default();
        if !request {
            return rest
                .is_empty()
                .then_some(())
                .ok_or_else(|| "a response carries a facet".to_owned());
        }
        let authz = match token(rest, 0)? {
            "not-configured" | "refused-before-policy" => 1,
            "refused-by-policy" => {
                token(rest, 1)?;
                2
            }
            "authorized" => {
                let texts = (1..=5)
                    .chain([7])
                    .all(|i| matches!(rest.get(i), Some(Value::Text(_))));
                if !texts || !matches!(rest.get(6), Some(Value::Token(_) | Value::Text(_))) {
                    return Err("the authorized group is malformed".into());
                }
                8
            }
            other => return Err(format!("authz {other}")),
        };
        let admission = token(rest, authz)?;
        match rest.len() - authz {
            1 => Ok(()),
            2 if admission == "refused" => token(rest, authz + 1).map(|_| ()),
            n => Err(format!("{n} admission field(s) after {admission}")),
        }
    }

    fn vectors() -> Vec<Vec<u8>> {
        vec![
            golden_accepted(),
            golden_digest_rejected(),
            golden_policy_refused_at_admission(),
            golden_signed(),
            golden_response_rejected_elsewhere(),
        ]
    }

    #[test]
    fn the_reference_reader_round_trips_every_vector() {
        for vector in vectors() {
            let decoded = read(&vector).unwrap_or_else(|e| panic!("{e}: {vector:02x?}"));
            assert_eq!((decoded.run, decoded.seq), ([0x11; 16], 7));
        }
        let signed = read(&golden_signed()).expect("reads");
        assert_eq!(signed.scope, Scope::Exchange([0x11; 16], 3));
        assert_eq!(
            signed.values,
            [
                Value::Token("mcp-re.response.signed".into()),
                Value::Token("Signed".into()),
                Value::Absent,
                Value::Text("actor-a".into()),
                Value::Number(200),
                Value::Number(10),
            ]
        );
    }

    fn with(mut bytes: Vec<u8>, at: usize, value: u8) -> Vec<u8> {
        bytes[at] = value;
        bytes
    }

    fn with_seq(bytes: Vec<u8>, seq: i64) -> Vec<u8> {
        [&bytes[..17], &seq.to_be_bytes(), &bytes[25..]].concat()
    }

    #[test]
    fn the_reference_reader_refuses_non_canonical_forms() {
        for vector in vectors() {
            for cut in 0..vector.len() {
                assert!(
                    read(&vector[..cut]).is_err(),
                    "a truncation at {cut} was read"
                );
            }
            assert!(
                read(&[&vector[..], &[0x00]].concat()).is_err(),
                "a trailing byte"
            );
            assert!(read(&with(vector.clone(), 0, 0x02)).is_err(), "version 2");
            assert!(
                read(&with_seq(vector.clone(), -1)).is_err(),
                "a negative seq"
            );
            assert!(
                read(&with_seq(vector.clone(), i64::MAX)).is_err(),
                "seq == i64::MAX"
            );
        }
        let golden = golden_accepted();
        // The first field's class byte, after header, scope and count.
        assert!(read(&with(golden.clone(), 28, 0x04)).is_err(), "class 4");
        let actor = golden
            .windows(7)
            .position(|w| w == b"actor-a")
            .expect("the actor is in the vector");
        assert!(
            read(&with(golden.clone(), actor, 0xff)).is_err(),
            "invalid UTF-8"
        );
        let count = 26;
        assert!(
            read(&with(golden.clone(), count + 1, 0x09)).is_err(),
            "count + 1"
        );
        assert!(
            read(&with(golden.clone(), count + 1, 0x07)).is_err(),
            "count - 1"
        );
        assert!(
            read(&encoded(&accepted(), 7, &exchange())).is_err(),
            "Exchange on accepted"
        );
        assert!(
            read(&encoded(&signed(), 7, &EventScope::Origin)).is_err(),
            "Origin on signed"
        );
        assert!(
            read(&encoded(&signed(), 3, &exchange())).is_err(),
            "a coordinate that is not earlier than its event"
        );
    }

    // ---- the v1 schema table --------------------------------------------------------------

    const T: u8 = CLASS_TOKEN;
    const N: u8 = CLASS_NUMBER;
    const X: u8 = CLASS_TEXT;
    const A: u8 = CLASS_ABSENT;

    /// One position of the schema: the field's name and the classes v1 admits there.
    type Slot = (&'static str, &'static [u8]);

    /// Every field, by position, and the classes v1 admits there.
    const EXCHANGE_WIDE: &[Slot] = &[
        ("event", &[T]),
        ("decision", &[T]),
        ("reason", &[T, A]),
        ("actor", &[X, A]),
        ("status", &[N]),
        ("at", &[N]),
    ];
    const AUTHZ_ARMS: &[(&str, &[Slot])] = &[
        ("not-configured", &[("authz", &[T])]),
        ("refused-before-policy", &[("authz", &[T])]),
        (
            "refused-by-policy",
            &[("authz", &[T]), ("authz_policy_reason", &[T])],
        ),
        (
            "authorized",
            &[
                ("authz", &[T]),
                ("authz_authority", &[X]),
                ("authz_version", &[X]),
                ("authz_decision_id", &[X]),
                ("authz_decision_evidence", &[X]),
                ("authz_operation", &[X]),
                ("authz_target", &[T, X]),
                ("authz_evidence", &[X]),
            ],
        ),
    ];
    const ADMISSION: &[Slot] = &[("admission", &[T])];
    const ADMISSION_REFUSED: &[Slot] = &[("admission", &[T]), ("admission_refusal", &[T])];

    fn class(value: &AuditValue<'_>) -> u8 {
        match value {
            AuditValue::Absent => A,
            AuditValue::Token(_) => T,
            AuditValue::Number(_) => N,
            AuditValue::Text(_) => X,
        }
    }

    /// The v1 field sequence `record` must have, from the table.
    fn schema_of(record: &AuditRecord) -> Vec<Slot> {
        let mut schema = EXCHANGE_WIDE.to_vec();
        if record.subject.authorization().is_none() {
            return schema;
        }
        let fields = record.audit_fields();
        let AuditValue::Token(authz) = &fields[6].value else {
            panic!("a request's seventh field is its authz token");
        };
        let arm = AUTHZ_ARMS
            .iter()
            .find(|(name, _)| name == authz)
            .unwrap_or_else(|| panic!("authz arm {authz} is not in the v1 table"));
        schema.extend_from_slice(arm.1);
        schema.extend_from_slice(match record.subject.admission_refusal() {
            Some(_) => ADMISSION_REFUSED,
            None => ADMISSION,
        });
        schema
    }

    struct Grants;

    impl crate::authorization::AuthorizationEvaluator for Grants {
        fn evaluate(
            &self,
            _: &crate::authorization::AuthorizationRequest,
        ) -> Result<crate::authorization::AuthorizedDecision, PolicyError> {
            Ok(crate::authorization::AuthorizedDecision::new(
                crate::authorization::GrantAttribution::new("acme", "1", "d-1"),
                crate::authorization::DecisionEvidenceIdentity::from_verified_binding(
                    "sha-256", "fixture",
                ),
            ))
        }
    }

    /// A request the real authority authorized, so the authorized arm is enumerated from its
    /// owner rather than restated here.
    fn authorized_posture() -> AuthorizationPosture {
        let signed = crate::authorization::action_harness::verified_over_as(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#,
            "did:example:agent-1",
            "key-a",
        );
        crate::authorization::authorize(Some(&Grants), &signed.verified, &signed.body, None)
            .expect("the evaluator grants")
    }

    /// Every record this proxy can produce has exactly the v1 field sequence. A change to any
    /// arm — a field added, dropped, moved or reclassified — is a new canonical version.
    #[test]
    fn every_enumerable_record_matches_the_v1_schema_table() {
        let admissions = [
            AdmissionFacet::NotReached,
            AdmissionFacet::NotConfigured,
            AdmissionFacet::LiveConfirmed,
            AdmissionFacet::Degraded,
            AdmissionFacet::Refused,
        ];
        let authorizations = [
            AuthorizationFacet::NotConfigured,
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(
                PolicyError::AuthorizationScopeDenied,
            )),
        ];
        let postures = [
            AuthorizationPosture::NoPolicyConfigured,
            authorized_posture(),
        ];
        let mut subjects = vec![
            AuditSubject::response_signed(),
            AuditSubject::response_rejected(Some(&McpReError::DigestMismatch)),
            AuditSubject::response_rejected(None),
        ];
        for admission in admissions {
            for posture in &postures {
                subjects.push(AuditSubject::request_accepted(posture, admission));
            }
            for authorization in &authorizations {
                subjects.push(AuditSubject::request_rejected(
                    Some(&McpReError::DigestMismatch),
                    authorization.clone(),
                    admission,
                ));
                subjects.push(AuditSubject::request_rejected(
                    None,
                    authorization.clone(),
                    admission,
                ));
                subjects.push(AuditSubject::request_refused_at_admission(
                    None,
                    authorization.clone(),
                    AdmissionRefusalClass::NoRecord,
                ));
            }
        }
        let mut arms_seen = std::collections::BTreeSet::new();
        for subject in subjects {
            for actor_id in [None, Some("actor-a".to_owned())] {
                let record = AuditRecord {
                    subject: subject.clone(),
                    actor_id,
                    status: 200,
                    at_unix: 1,
                };
                let actual: Vec<(&str, u8)> = record
                    .audit_fields()
                    .iter()
                    .map(|f| (f.name, class(&f.value)))
                    .collect();
                let schema = schema_of(&record);
                let matches = actual.len() == schema.len()
                    && actual
                        .iter()
                        .zip(&schema)
                        .all(|((name, c), (want, classes))| name == want && classes.contains(c));
                assert!(
                    matches,
                    "the field sequence of {record:?} is not the v1 schema — a change to it \
                     is a new canonical version: bump CANONICAL_VERSION and keep the v1 \
                     vectors.\nactual: {actual:?}\nv1:     {schema:?}"
                );
                if let Some(AuditValue::Token(authz)) =
                    record.audit_fields().get(6).map(|f| f.value.clone())
                {
                    arms_seen.insert(authz);
                }
            }
        }
        assert_eq!(
            arms_seen.len(),
            AUTHZ_ARMS.len(),
            "every authz arm of the table is exercised: {arms_seen:?}"
        );
    }
}
