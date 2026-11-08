// SPDX-License-Identifier: Apache-2.0
//! The exported entry points that come in pairs, each pair written once.
//!
//! The software-custody and device-custody variants of a signing call take the same
//! parameter list and differ only in who produces the signature; `verifyResponse` and
//! `verifyAccepted202` take the same parameter list and differ only in the verdict they
//! project. A template holds the parameter list and the marshalling of it into the binding
//! core's arguments once, and each entry point states only what it does with them, so the
//! two members of a pair cannot drift apart. The expansion is an ordinary `#[napi]`
//! function with the signature below, so the TypeScript API is exactly what this text spells.

/// A request-signing entry point: `$custody` is the first parameter (the seed, or the sign
/// callback) and `$sign` turns the marshalled arguments into the result.
macro_rules! request_entry {
    (
        $(#[$doc:meta])*
        fn $name:ident($custody:ident: $custody_ty:ty, $args:ident) $sign:block
    ) => {
        $(#[$doc])*
        #[napi]
        #[allow(clippy::too_many_arguments)]
        pub fn $name(
            $custody: $custody_ty,
            key_id: String,
            id_json: String,
            method: String,
            params_json: String,
            target_uri: String,
            audience_id: String,
            route: Option<String>,
            dpop_token: String,
            nonce: String,
            created: f64,
            expires: f64,
            cont_prev_alg: Option<String>,
            cont_prev_value: Option<String>,
            cont_irr_alg: Option<String>,
            cont_irr_value: Option<String>,
            cont_request_state: Option<String>,
            bindings_json: Option<String>,
        ) -> Result<SignedRequestJs, Refusal> {
            let continuation = ContinuationArgs {
                prev_alg: cont_prev_alg,
                prev_value: cont_prev_value,
                irr_alg: cont_irr_alg,
                irr_value: cont_irr_value,
                request_state: cont_request_state,
            };
            let $args = Signing {
                key_id,
                method,
                params_json,
                target_uri,
                audience_id,
                route,
                dpop_token,
                nonce,
                window: Window { created, expires },
                bindings_json,
            }
            .args(request_call(id_json, continuation))?;
            $sign
        }
    };
}

/// A notification-signing entry point, shaped as [`request_entry`] without an id or
/// continuation.
macro_rules! notification_entry {
    (
        $(#[$doc:meta])*
        fn $name:ident($custody:ident: $custody_ty:ty, $args:ident) $sign:block
    ) => {
        $(#[$doc])*
        #[napi]
        #[allow(clippy::too_many_arguments)]
        pub fn $name(
            $custody: $custody_ty,
            key_id: String,
            method: String,
            params_json: String,
            target_uri: String,
            audience_id: String,
            route: Option<String>,
            dpop_token: String,
            nonce: String,
            created: f64,
            expires: f64,
            bindings_json: Option<String>,
        ) -> Result<SignedRequestJs, Refusal> {
            let $args = Signing {
                key_id,
                method,
                params_json,
                target_uri,
                audience_id,
                route,
                dpop_token,
                nonce,
                window: Window { created, expires },
                bindings_json,
            }
            .args(Call::Notification)?;
            $sign
        }
    };
}

/// A verification entry point: `$verify` turns the marshalled arguments into the result.
macro_rules! verify_entry {
    (
        $(#[$doc:meta])*
        fn $name:ident($args:ident) -> $result:ty $verify:block
    ) => {
        $(#[$doc])*
        #[napi]
        #[allow(clippy::too_many_arguments)]
        pub fn $name(
            status: u16,
            resp_headers: Vec<HttpHeader>,
            resp_body: Buffer,
            req_method: String,
            req_target_uri: String,
            req_headers: Vec<HttpHeader>,
            req_body: Buffer,
            issuer_key_id: String,
            issuer_pubkey_b64url: String,
            issuer_role: String,
            issuer_trust_domain: String,
            issuer_subject: String,
            verifier_audiences: Vec<String>,
            expected_audience_hash: String,
            accepted_epochs: Vec<String>,
            max_clock_skew: f64,
            revoked_identifiers: Vec<String>,
            now: f64,
            issuer_retired_until: Option<f64>,
        ) -> Result<$result, Refusal> {
            let $args = Verification {
                answer: Answer {
                    status,
                    headers: resp_headers,
                    body: resp_body.to_vec(),
                },
                transmitted: Transmitted {
                    method: req_method,
                    target_uri: req_target_uri,
                    headers: req_headers,
                    body: req_body.to_vec(),
                },
                issuer: Issuer {
                    key_id: issuer_key_id,
                    pubkey_b64url: issuer_pubkey_b64url,
                    role: issuer_role,
                    trust_domain: issuer_trust_domain,
                    subject: issuer_subject,
                    retired_until: issuer_retired_until,
                },
                trust: Trust {
                    verifier_audiences,
                    expected_audience_hash,
                    accepted_epochs,
                    max_clock_skew,
                    revoked_identifiers,
                    now,
                },
            }
            .args()?;
            $verify
        }
    };
}
