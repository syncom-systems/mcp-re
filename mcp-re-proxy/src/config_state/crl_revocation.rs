// SPDX-License-Identifier: Apache-2.0
//! The `CrlRevocation` machine — offline client-certificate revocation. Unit
//! `proxy.transport_binding_and_crl_state`.
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `None` | — | a reload cadence | — |
//! | `Static` | at least one CRL path | — | — |
//! | `Reloading` | at least one CRL path, a cadence | — | cadence `> 0` |
//!
//! A zero cadence is not a disabled reloader but an unbounded one: the worker's sleep
//! returns immediately, so it re-reads every CRL, rebuilds the rustls verifier and swaps
//! the serving snapshot in a tight loop, burning a core with no diagnostic.

use crate::deployment_request::DeploymentRequest;

/// Which client-CRL posture a configuration requests.
///
/// The representation is private to this module and [`classify_and_validate_crl`] is the only
/// producer, and it produces no state for a request it refuses. A CRL-bearing state carries the files that put it in that state, and the
/// reloading state carries the cadence that distinguishes it from the static one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlRevocationState {
    /// The CRL files. Empty is exactly what "no CRLs" means, so the posture and the set
    /// cannot disagree.
    paths: Vec<String>,
    /// Seconds between re-reads, where the operator asked for them. Above zero, and absent
    /// where `paths` is empty: the producer returns no state otherwise.
    cadence_secs: Option<u64>,
}

impl CrlRevocationState {
    /// The files to read, empty where the posture reads none.
    ///
    /// For materialization, which loads the same bytes under both CRL-bearing postures.
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Seconds between re-reads, or `None` when the CRLs are read once at startup.
    pub fn reload_cadence_secs(&self) -> Option<u64> {
        self.cadence_secs
    }

    /// Whether any CRL is consulted at all.
    ///
    /// Revocation rests on the client-certificate lifetime ceiling alone when it is not —
    /// a posture rather than an absence, see [`crate::tls_plane::fleet_crl_bound`].
    pub fn is_enforced(&self) -> bool {
        !self.paths.is_empty()
    }

    /// What the TLS plane must establish for client revocation, as this owner states it.
    ///
    /// The projection replaces a match on the representation performed in planning.
    pub fn client_revocation_plan(&self) -> ClientRevocationPlan {
        ClientRevocationPlan {
            paths: self.paths.clone(),
            cadence_secs: self.cadence_secs,
        }
    }
}

/// What the TLS plane establishes for client revocation.
///
/// Produced only by [`CrlRevocationState::client_revocation_plan`]. The files and the
/// cadence are private and set together, so no consumer can plan a re-read cadence over a
/// set of files the deployment did not configure — the combination CF-04 refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRevocationPlan {
    paths: Vec<String>,
    cadence_secs: Option<u64>,
}

impl ClientRevocationPlan {
    /// The files to read, empty where the posture reads none.
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Seconds between re-reads, or `None` when the CRLs are read once at startup.
    ///
    /// `Some` is the reloading posture: a revocation published after startup takes effect
    /// within the cadence, on established connections as well as at the handshake. `None`
    /// with files is the static posture, bounded by the CRL's own `nextUpdate` or a
    /// restart. `None` with no files is no CRL at all.
    pub fn reload_cadence_secs(&self) -> Option<u64> {
        self.cadence_secs
    }

    /// Whether any CRL is consulted at all.
    pub fn is_enforced(&self) -> bool {
        !self.paths.is_empty()
    }
}

/// Recognise the CRL-revocation state. Total: the two fields name one.
fn classify_crl(config: &DeploymentRequest) -> CrlRevocationState {
    let lists = &config.peer_revocation.lists;
    CrlRevocationState {
        paths: lists.paths.clone(),
        cadence_secs: lists.is_configured().then_some(lists.reload_secs).flatten(),
    }
}

/// Classify the CRL-revocation state and check its columns.
pub fn classify_and_validate_crl(
    config: &DeploymentRequest,
) -> (Option<CrlRevocationState>, Vec<String>) {
    let state = classify_crl(config);
    let mut violations = Vec::new();
    // Structure of the list itself, before anything that reads a member. Classification
    // asks whether the list is empty, which a list holding `""` or only whitespace is not — so a deployment
    // could reach `Static`/`Reloading`, announce that offline revocation is enforced, and
    // hold one path that names no file. Placed ahead of the cadence clauses because those
    // are about a different field: a member that names nothing is a defect in the control
    // the cadence would be re-reading.
    if state.paths().iter().any(|path| path.trim().is_empty()) {
        violations.push(
            "--client-crl contains an empty path: every listed CRL must name a file, or the \
             deployment reports offline revocation as enforced while one of its lists \
             revokes nothing"
                .to_string(),
        );
    }
    if config.peer_revocation.lists.reload_secs == Some(0) {
        violations.push(
            "--client-crl-reload-secs 0 makes the CRL reloader spin: the cadence is the sleep \
             between re-reads, so zero re-reads every CRL and rebuilds the TLS verifier \
             continuously. Set a positive cadence, or omit the flag to load the CRLs once"
                .to_string(),
        );
    }
    // Forbidden on `None`: a cadence names how often to re-read a set that is empty, so its
    // presence states a control the deployment does not have.
    if !state.is_enforced() && config.peer_revocation.lists.reload_secs.is_some() {
        violations.push(
            "--client-crl-reload-secs has no effect without --client-crl: there is no \
             revocation list to re-read, so no revocation is enforced on either cadence"
                .to_string(),
        );
    }
    (violations.is_empty().then_some(state), violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    /// A state this machine must recognise, and how to request it.
    type Form = ((Vec<String>, Option<u64>), fn(&mut DeploymentRequest));

    fn crl(
        mutate: impl FnOnce(&mut DeploymentRequest),
    ) -> (Option<CrlRevocationState>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate_crl(&config)
    }

    #[test]
    fn every_legal_crl_state_form_is_classified_and_accepted() {
        let cases: Vec<Form> = vec![
            ((Vec::new(), None), |_| {}),
            (
                (vec!["/crl.pem".to_string()], None),
                |c: &mut DeploymentRequest| {
                    c.peer_revocation.lists.paths = vec!["/crl.pem".to_string()];
                },
            ),
            (
                (vec!["/crl.pem".to_string()], Some(300)),
                |c: &mut DeploymentRequest| {
                    c.peer_revocation.lists.paths = vec!["/crl.pem".to_string()];
                    c.peer_revocation.lists.reload_secs = Some(300);
                },
            ),
        ];
        for ((paths, cadence), mutate) in cases {
            let (state, violations) = crl(mutate);
            let state = state.expect("a legal CRL form names a state");
            assert_eq!(state.paths(), paths.as_slice());
            assert_eq!(state.reload_cadence_secs(), cadence);
            assert_eq!(state.is_enforced(), !paths.is_empty());
            assert!(
                violations.is_empty(),
                "{paths:?}/{cadence:?} refused: {violations:?}"
            );
        }
    }

    /// G5. A list holding `""` is not an empty list, so it classified as a configured
    /// control while naming no file.
    ///
    /// The parser rejects an empty comma segment, but `client_crl_paths` is a public field:
    /// this mutates the REQUEST, so no parser participates. The positive half is
    /// `every_legal_crl_state_form_is_classified_and_accepted`, which drives the same guard
    /// with a real path and asserts nothing is reported.
    #[test]
    fn a_crl_list_holding_an_empty_path_is_refused() {
        for paths in [
            vec![String::new()],
            vec!["/crl.pem".to_string(), String::new()],
            vec!["   ".to_string()],
            vec!["/crl.pem".to_string(), " ".to_string()],
        ] {
            let (state, violations) = crl(|c| c.peer_revocation.lists.paths = paths.clone());
            assert!(
                state.is_none(),
                "{paths:?}: a refused list must name no state"
            );
            assert!(
                violations.iter().any(|v| v.contains("empty path")),
                "{paths:?}: not refused — {violations:?}"
            );
        }
    }

    #[test]
    fn a_zero_cadence_is_an_unbounded_reloader_not_a_disabled_one() {
        let (state, violations) = crl(|c| {
            c.peer_revocation.lists.paths = vec!["/crl.pem".to_string()];
            c.peer_revocation.lists.reload_secs = Some(0);
        });
        assert!(state.is_none(), "a zero cadence must name no state");
        assert!(
            violations.iter().any(|v| v.contains("spin")),
            "{violations:?}"
        );
    }

    #[test]
    fn a_cadence_with_no_list_to_re_read_is_refused() {
        let (state, violations) = crl(|c| c.peer_revocation.lists.reload_secs = Some(300));
        assert!(state.is_none(), "a cadence over no list must name no state");
        assert!(
            violations
                .iter()
                .any(|v| v.contains("has no effect without --client-crl")),
            "{violations:?}"
        );
    }
}
