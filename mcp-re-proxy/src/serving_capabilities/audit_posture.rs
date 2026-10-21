// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPS-035 and ADR-MCPRE-070 §2 — the audit posture: where the per-request record is
//! observed, and whether its commitment is required.
//!
//! | plan | outcome |
//! |---|---|
//! | best-effort, `--audit-sink none` | OFF, nothing installed |
//! | best-effort, `--audit-sink stderr` | ON, the stderr observer; a registered provider is named and NOT used |
//! | required, and the provider establishes | ON, the stderr observer and the established provider |
//! | required, and it cannot | startup REFUSES — never best-effort, never OFF (S4) |
//!
//! Two phases. [`audit_commitment`] establishes the provider before any plane materializes,
//! so a refusal leaves nothing running; [`audit_posture`] opens the observer and assembles
//! the posture at the seam's own position in the transcript, exactly where the best-effort
//! observer was always opened. The artifact is one [`AuditPosture`], so the REQUIRED line
//! cannot travel with a posture that holds no established provider, and the BEST-EFFORT line
//! cannot travel with one that does.

use std::sync::Arc;
use std::time::Duration;

use crate::audit_commitment::{
    run_accounting_cadence, AuditPlan, AuditPosture, CommitmentBound, EstablishedAudit,
    EstablishedProvider, ProviderId, ACCOUNTING_INTERVAL,
};
use crate::config_state::AuditState;

use super::Established;

/// How long the request path waits for each required commitment (G1, G2).
pub(crate) const REQUIRED_COMMITMENT_BOUND: Duration = Duration::from_secs(2);

/// The best-effort ON line. Its meaning is the v0.18.1 one.
const STDERR_BEST_EFFORT: &str = "security audit record = STDERR, delivery = BEST-EFFORT \
     (ADR-MCPS-035; ADR-MCPRE-070 §2): a numbered line per accepted / rejected / signed \
     decision, carrying the verifier-resolved actor and the frozen mcp-re.* wire code, \
     numbered within a run named on every line. Best-effort by design: a full queue drops \
     lines rather than delaying a request, a gap in a run's seq marks each drop, and the drop \
     count is reported.";

/// The OFF line for the attribution record.
const AUDIT_OFF: &str = "security audit record = OFF (--audit-sink none), delivery = \
     BEST-EFFORT: no per-request record is emitted, so this deployment has no attribution \
     surface for a later incident. Pass --audit-sink stderr to enable it.";

/// Establish the commitment half of the posture `plan` resolved — BEFORE any plane
/// materializes, so a required posture whose provider cannot be established refuses startup
/// with nothing yet running.
///
/// A best-effort plan touches no runtime and opens nothing. A required plan establishes its
/// provider on the control runtime and starts the accounting cadence there.
pub(crate) fn audit_commitment(
    plan: AuditPlan,
    control: &crate::control_runtime::ControlRuntimeProvision,
) -> Result<EstablishedAudit, String> {
    let plan = match plan.without_commitment() {
        Ok(best_effort) => return Ok(best_effort),
        Err(required) => required,
    };
    let handle = control.handle()?;
    let established = handle
        .block_on(plan.establish())
        .map_err(|refusal| refusal.to_string())?;
    if let EstablishedAudit::Required(provider) = &established {
        let bound = required_bound()?;
        handle.spawn(run_accounting_cadence(
            Arc::clone(provider),
            bound,
            ACCOUNTING_INTERVAL,
        ));
    }
    Ok(established)
}

fn required_bound() -> Result<CommitmentBound, String> {
    CommitmentBound::new(REQUIRED_COMMITMENT_BOUND)
        .ok_or_else(|| "--audit-commitment required: the commitment bound is not legal".into())
}

/// The audit posture over the observer `state` names, with the commitment `established`.
/// Declared at the security-audit seam's position; the observer is opened here, as it
/// always was.
pub(crate) fn audit_posture(
    state: AuditState,
    established: EstablishedAudit,
) -> Result<Established<AuditPosture>, String> {
    let provider = match established {
        EstablishedAudit::BestEffort { unused } => return best_effort(state, unused.as_ref()),
        EstablishedAudit::Required(provider) => provider,
    };
    let bound = required_bound()?;
    let line = required_line(&provider, bound);
    Ok(Established::on(
        AuditPosture::required(stderr_observer()?, provider, bound),
        line,
    ))
}

/// The stderr observer, or the refusal for a run that cannot be named.
fn stderr_observer() -> Result<crate::audit_sink::MaybeAuditSink, String> {
    let sink = crate::audit_sink::StderrAuditSink::open().ok_or(
        "--audit-sink stderr: the OS CSPRNG did not yield the audit stream's run identity, so \
         its records could not be told from another run's",
    )?;
    Ok(Some(Arc::new(sink)))
}

fn best_effort(
    state: AuditState,
    unused: Option<&ProviderId>,
) -> Result<Established<AuditPosture>, String> {
    let unused = unused
        .map(|id| {
            format!(
                " A commitment provider {id} is registered in this build and NOT used: pass \
                 --audit-commitment required to select it."
            )
        })
        .unwrap_or_default();
    if !state.observes_on_stderr() {
        return Ok(Established::off(format!("{AUDIT_OFF}{unused}")));
    }
    Ok(Established::on(
        AuditPosture::best_effort(stderr_observer()?),
        format!("{STDERR_BEST_EFFORT}{unused}"),
    ))
}

/// The REQUIRED line: what is required, of whom, at which DECLARED tier, and what the
/// observer's stream now looks like.
fn required_line(provider: &EstablishedProvider, bound: CommitmentBound) -> String {
    let tier = provider.tier();
    format!(
        "security audit record = STDERR, delivery = REQUIRED via provider {id}, tier {tier} \
         ({vocabulary}) as DECLARED by the provider ({guarantee}): no dispatch without a \
         committed intent and no success without a committed outcome; a commitment that \
         fails, outlasts {bound}ms or finds all {budget} in-flight commitments taken refuses \
         the request (503 before dispatch). Persistence is the provider's declaration and an \
         external evidence obligation (ADR-MCPRE-070 D3), not verified here. An \
         mcp-re.audit.accounting record is committed every {every}s; its counts are a lower \
         bound. The stderr observer stays best-effort, and under this posture its seq has \
         gaps that are not drops: an execution intent consumes a seq and is never observed \
         (D1), and neither is an outcome that could not be committed or whose retention \
         failed after it was (G2, W5b).",
        id = provider.accounting().provider(),
        tier = tier.wire_name(),
        vocabulary = crate::audit_commitment::TIER_VOCABULARY,
        guarantee = tier.guarantee(),
        bound = bound.get().as_millis(),
        budget = provider.accounting().budget().ceiling(),
        every = ACCOUNTING_INTERVAL.as_secs(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_commitment::{AuditProviders, ReferenceCommitment, BUDGET_CEILING};
    use crate::control_runtime::ControlRuntimeProvision;
    use crate::startup_posture::SeamState;

    fn posture(
        state: AuditState,
        providers: &AuditProviders,
    ) -> Result<(Option<AuditPosture>, SeamState), String> {
        let plan =
            AuditPlan::resolve(state, providers, BUDGET_CEILING).map_err(|r| r.to_string())?;
        let established = audit_commitment(plan, &ControlRuntimeProvision::idle())?;
        audit_posture(state, established).map(Established::into_parts)
    }

    fn line(state: &SeamState) -> String {
        match state {
            SeamState::On(line) | SeamState::Off(line) => line.clone(),
        }
    }

    /// The STDERR posture installs the stderr observer and the OFF posture installs none;
    /// both keep their v0.18.1 meaning and add only the delivery they always had.
    #[test]
    fn best_effort_keeps_its_meaning_and_installs_what_its_line_says() {
        let (on, on_state) = posture(AuditState::Stderr, &AuditProviders::none()).expect("on");
        let on = on.expect("ON installs a posture");
        assert!(on.observer().is_some() && on.provider().is_none());
        assert!(matches!(on_state, SeamState::On(_)));
        assert!(line(&on_state).contains("delivery = BEST-EFFORT"));
        assert!(line(&on_state).contains("a gap in a run's seq marks each drop"));

        let (off, off_state) = posture(AuditState::None, &AuditProviders::none()).expect("off");
        assert!(off.is_none());
        assert!(matches!(off_state, SeamState::Off(_)));
        assert!(
            line(&off_state).contains("record = OFF (--audit-sink none), delivery = BEST-EFFORT")
        );
        assert!(
            AUDIT_OFF.contains("Pass --audit-sink stderr"),
            "the OFF line says what to do"
        );
    }

    /// A registered provider under best-effort is named and NOT used.
    #[test]
    fn an_unused_provider_is_named_and_not_promoted() {
        let reference = ReferenceCommitment::surviving_process_loss([]);
        let providers = AuditProviders::with_reference_for_test(&reference);
        let (posture, state) = posture(AuditState::Stderr, &providers).expect("on");
        assert!(posture.expect("installed").provider().is_none());
        assert!(
            line(&state).contains("provider reference is registered in this build and NOT used")
        );
        assert_eq!(reference.requests(), 0);
    }

    /// ON under REQUIRED carries the established provider, and the line states the declared
    /// tier, its vocabulary, the provider, the accounting record and the seq gaps.
    #[test]
    fn the_required_posture_carries_its_established_provider_and_says_so() {
        let reference = ReferenceCommitment::surviving_process_loss([]);
        let providers = AuditProviders::with_reference_for_test(&reference);
        let (posture, state) = posture(AuditState::Required, &providers).expect("established");
        assert!(posture.expect("installed").provider().is_some());
        let line = line(&state);
        for needle in [
            "delivery = REQUIRED via provider reference",
            "tier SURVIVES_PROXY_PROCESS_LOSS (audit-durability/v1) as DECLARED",
            "not verified here",
            "mcp-re.audit.accounting",
            "gaps that are not drops",
        ] {
            assert!(line.contains(needle), "{needle:?} missing from {line}");
        }
    }

    /// S4: a required posture that cannot be established refuses; it never yields an OFF or
    /// a best-effort posture.
    #[test]
    fn a_required_posture_that_cannot_be_established_refuses() {
        let refused = posture(AuditState::Required, &AuditProviders::none())
            .err()
            .expect("refused");
        assert!(refused.contains("--audit-commitment required"), "{refused}");
        let volatile = ReferenceCommitment::process_volatile();
        let refused = posture(
            AuditState::Required,
            &AuditProviders::with_reference_for_test(&volatile),
        )
        .err()
        .expect("refused");
        assert!(refused.contains("PROCESS_VOLATILE"), "{refused}");
    }
}
