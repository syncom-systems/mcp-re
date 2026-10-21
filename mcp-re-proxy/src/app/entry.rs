// SPDX-License-Identifier: Apache-2.0
//! How a deployment arrives at the composition root, and what every exit discharges.
//!
//! Three doors, one room. The argv path arrives validated, a request built in code is
//! validated here, and an embedder that compiled a commitment provider registers it through
//! [`run_with`]. Each reaches the private `run_validated` only through [`run_with`], which is
//! where the requested audit policy meets the providers the build registered — purely, before
//! any effect (ADR-MCPRE-070 §2, §11).

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::audit_commitment::{AuditPlan, AuditProviders, BUDGET_CEILING};
use crate::config_state::validation::ValidatedDeployment;
use crate::deployment_request::DeploymentRequest;

/// Serve a validated deployment on the per-core async fleet until `shutdown` is flipped
/// (SIGTERM/SIGINT in the binary; a test flag in tests). The argv path arrives with the proof
/// [`crate::cli::parse_args`] produced, so it validates once.
///
/// The open-source binary registers no commitment provider, so a deployment that requires
/// one is refused here at startup — never served as best-effort.
pub fn run(deployment: ValidatedDeployment, shutdown: Arc<AtomicBool>) -> Result<(), String> {
    run_with(deployment, AuditProviders::none(), shutdown)
}

/// [`run`] for a build that registers commitment `providers` (#1206).
///
/// The deployment's `--audit-commitment` is resolved against `providers` before anything is
/// materialized: `required` with no provider, or with the test-only reference authority
/// unacknowledged, refuses here. A registered provider under best-effort is named and unused.
/// After teardown, a required run states what its commitment path did.
pub fn run_with(
    deployment: ValidatedDeployment,
    providers: AuditProviders,
    shutdown: Arc<AtomicBool>,
) -> Result<(), String> {
    let plan = match AuditPlan::resolve(deployment.state().audit(), &providers, BUDGET_CEILING) {
        Ok(plan) => plan,
        Err(refusal) => return drained(Err(refusal.to_string())),
    };
    let accounting = plan.accounting();
    let outcome = drained(super::run_validated(&deployment, plan, shutdown));
    if let Some(accounting) = accounting {
        eprintln!("{}", accounting.shutdown_line());
    }
    outcome
}

/// [`run`] for a request built in code, which met no parser and so no guard: it is
/// validated here, and nothing past this point sees an unchecked request.
pub fn run_request(config: DeploymentRequest, shutdown: Arc<AtomicBool>) -> Result<(), String> {
    match ValidatedDeployment::try_from(config) {
        Ok(deployment) => run(deployment, shutdown),
        Err(refusal) => drained(Err(refusal)),
    }
}

/// `outcome`, once the audit writer's teardown obligation is discharged. Every exit passes
/// here — a clean drain, a failed serve, a refused startup — because a sink installed past
/// this seam still leaves records in the same global queue.
fn drained(outcome: Result<(), String>) -> Result<(), String> {
    crate::audit_sink::drain::at_shutdown();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S4 at the entry: the open-source binary's `run` registers no provider, so a required
    /// deployment is refused before anything is materialized, naming the flag.
    #[test]
    fn the_default_entry_refuses_a_required_deployment_before_any_effect() {
        let mut config = crate::config_state::test_support::legal_config();
        config.audit.delivery = crate::deployment_request::AuditDeliveryKind::Required;
        let refused = run_request(config, Arc::new(AtomicBool::new(true)))
            .expect_err("no provider is registered");
        assert!(refused.contains("--audit-commitment required"), "{refused}");
        assert!(
            refused.contains("registers no commitment provider"),
            "{refused}"
        );
    }
}
