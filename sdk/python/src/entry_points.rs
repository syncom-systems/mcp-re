// SPDX-License-Identifier: Apache-2.0
//! The exported entry points that come in pairs, each pair written once.
//!
//! The software-custody and device-custody variants of a signing call take the same
//! keyword list and differ only in who produces the signature; `verify_response` and
//! `verify_accepted_202` take the same keyword list and differ only in the verdict they
//! project. A template holds the keyword list and the marshalling of it into the binding
//! core's arguments once, and each entry point states only what it does with them, so the
//! two members of a pair cannot drift apart. The expansion is an ordinary `#[pyfunction]`
//! with the signature below, so the Python API is exactly what this text spells.

/// A request-signing entry point: `$custody` is the first positional (the seed, or the
/// sign callback) and `$sign` turns the marshalled arguments into the result.
macro_rules! request_entry {
    (
        $(#[$doc:meta])*
        fn $name:ident($py:ident, $custody:ident: $custody_ty:ty, $args:ident) $sign:block
    ) => {
        $(#[$doc])*
        #[pyfunction]
        #[allow(clippy::too_many_arguments)]
        #[pyo3(signature = (
            $custody, key_id, id_json, method, params_json, target_uri, audience_id, route,
            dpop_token, nonce, created, expires,
            cont_prev_alg=None, cont_prev_value=None, cont_irr_alg=None, cont_irr_value=None,
            cont_request_state=None, bindings_json=None,
        ))]
        fn $name(
            $py: Python<'_>,
            $custody: $custody_ty,
            key_id: &str,
            id_json: &str,
            method: &str,
            params_json: &str,
            target_uri: &str,
            audience_id: &str,
            route: Option<String>,
            dpop_token: &str,
            nonce: &str,
            created: i64,
            expires: i64,
            cont_prev_alg: Option<String>,
            cont_prev_value: Option<String>,
            cont_irr_alg: Option<String>,
            cont_irr_value: Option<String>,
            cont_request_state: Option<String>,
            bindings_json: Option<String>,
        ) -> PyResult<PySignedRequest> {
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
            .args(request_call(id_json, continuation));
            $sign
        }
    };
}

/// A notification-signing entry point, shaped as [`request_entry`] without an id or
/// continuation.
macro_rules! notification_entry {
    (
        $(#[$doc:meta])*
        fn $name:ident($py:ident, $custody:ident: $custody_ty:ty, $args:ident) $sign:block
    ) => {
        $(#[$doc])*
        #[pyfunction]
        #[allow(clippy::too_many_arguments)]
        #[pyo3(signature = (
            $custody, key_id, method, params_json, target_uri, audience_id, route,
            dpop_token, nonce, created, expires, bindings_json=None,
        ))]
        fn $name(
            $py: Python<'_>,
            $custody: $custody_ty,
            key_id: &str,
            method: &str,
            params_json: &str,
            target_uri: &str,
            audience_id: &str,
            route: Option<String>,
            dpop_token: &str,
            nonce: &str,
            created: i64,
            expires: i64,
            bindings_json: Option<String>,
        ) -> PyResult<PySignedRequest> {
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
            .args(Call::Notification);
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
        #[pyfunction]
        #[allow(clippy::too_many_arguments)]
        #[pyo3(signature = (
            status, resp_headers, resp_body, req_method, req_target_uri, req_headers, req_body,
            issuer_key_id, issuer_pubkey_b64url, issuer_role, issuer_trust_domain, issuer_subject,
            verifier_audiences, expected_audience_hash, accepted_epochs, max_clock_skew,
            revoked_identifiers, now, issuer_retired_until = None,
        ))]
        fn $name(
            status: u16,
            resp_headers: Vec<(String, String)>,
            resp_body: &[u8],
            req_method: &str,
            req_target_uri: &str,
            req_headers: Vec<(String, String)>,
            req_body: &[u8],
            issuer_key_id: &str,
            issuer_pubkey_b64url: &str,
            issuer_role: &str,
            issuer_trust_domain: &str,
            issuer_subject: &str,
            verifier_audiences: Vec<String>,
            expected_audience_hash: &str,
            accepted_epochs: Vec<String>,
            max_clock_skew: i64,
            revoked_identifiers: Vec<String>,
            now: i64,
            issuer_retired_until: Option<i64>,
        ) -> PyResult<$result> {
            let $args = Verification {
                answer: Answer {
                    status,
                    headers: resp_headers,
                    body: resp_body,
                },
                transmitted: Transmitted {
                    method: req_method,
                    target_uri: req_target_uri,
                    headers: req_headers,
                    body: req_body,
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
            .args();
            $verify
        }
    };
}
