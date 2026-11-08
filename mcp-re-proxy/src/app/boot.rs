//! What startup learns before it acts, and the value every later stage runs against.
//!
//! [`preflight`] needs nothing running: it reads the host clock once, admits the key files
//! and opens the key source, so the refusals that need no plane are raised with nothing
//! installed. [`Startup::begin`] is the first effect this process performs — it opens the
//! [`MaterializingRuntime`], which owns every teardown-bearing resource from the moment it is
//! installed.
//!
//! [`Startup`] holds the runtime LAST on purpose. A failure at any later stage drops the
//! value, and the runtime reclaims what was installed in the order it owns, instead of
//! whatever order locals happen to be declared in. The proxy is never a field: it is a local
//! of the caller, declared after `Startup`, so it is dropped before the planes it signs with.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::async_fleet::ResolvedTopology;
use crate::capability_materialization::{
    admit_key_files, build_key_source, EstablishedChannelCredential, MaterializedSigningRoles,
};
use crate::clock::StartupReading;
use crate::config_state::validation::ValidatedDeployment;
use crate::config_state::InFlightLimitBasis;
use crate::materializing_runtime::MaterializingRuntime;
use crate::serving_capabilities::Established;
use crate::startup_plan::{ChannelEstablishmentPlan, SigningPlan, TrustPlan};
use crate::startup_posture::{PostureLog, Seam};
use crate::tls_plane::CrlReference;

/// What the pre-effect readings produced: the clock reading every boot-time consumer
/// shares, the CRL freshness reference derived from it, and the opened key source with the
/// channel credential its witness established.
pub(super) struct Preflight {
    pub(super) reading: StartupReading,
    pub(super) crl_reference: CrlReference,
    pub(super) roots: MaterializedSigningRoles,
    pub(super) channel_credential: EstablishedChannelCredential,
}

/// Read the clock and open the key source.
///
/// The hard custody guards (memory or weak replay, an over-ceiling or disabled certificate
/// lifetime, an lb assertion, node-local replay under `--fleet`) are all refused at parse
/// time by `config_state::validation::unsafe_config_violations`, so the proxy never reaches
/// here with them. A group- or world-readable key file is a hard error raised by the
/// custody owner's admission, which this function only invokes.
///
/// The response-signing key is NOT extracted: the witness is handed to the signing plane as
/// the response signer, which signs by delegation, so a non-exporting HSM/KMS source never
/// surrenders its private key (ADR-MCPS-014). The channel credential is the witness's own
/// product, with the requested custody already compared against the custody it establishes.
pub(super) fn preflight(config: &ValidatedDeployment) -> Result<Preflight, String> {
    let (reading, crl_reference) = read_clock(config)?;
    let values = config.config();
    let admitted_key_files = admit_key_files(
        config.state().custody(),
        config.state().channel_credential_custody(),
        config.state().key_file_access(),
    )?;
    let roots = build_key_source(
        admitted_key_files,
        &values.channel_credential.credential_chain,
        &values.peer_trust_anchors,
    )
    .map_err(|e| e.to_string())?;
    let channel_credential = roots.channel_credential().map_err(|e| e.to_string())?;
    Ok(Preflight {
        reading,
        crl_reference,
        roots,
        channel_credential,
    })
}

/// Clock-fault diagnosis (audit #94 F5). The host clock is read ONCE, and every startup
/// consumer of the boot instant receives that reading. A faulted reading that only feeds
/// per-request freshness fails closed, so it warns; where it would be the reference time
/// for the boot-time stale-CRL refusal, `CrlReference::of` refuses, and the TLS plane
/// cannot be materialized without the reference it produces.
fn read_clock(config: &ValidatedDeployment) -> Result<(StartupReading, CrlReference), String> {
    let reading = StartupReading::read();
    let crl_reference = CrlReference::of(&reading, config.state().crl_revocation())?;
    if reading.is_faulted() {
        eprintln!(
            "mcp-re-proxy: WARNING: the system clock reads at/near the Unix epoch ({} < {}s); this \
             almost certainly means the host clock is unset or broken. Freshness checks will \
             FAIL CLOSED (every request denied) until the clock is corrected — fix the host clock \
             (NTP/RTC) rather than treating the resulting denials as a load problem.",
            reading.unix_seconds(),
            crate::clock::EPOCH_CLOCK_FAULT_THRESHOLD_SECS,
        );
    }
    Ok((reading, crl_reference))
}

/// The three plans layer A produced, each pure and already classified (ADR-MCPRE-056 §8).
///
/// The response authority is read once and paired into the trust plan and the signing plan
/// by their one producer (ADR-MCPRE-052; CF-09): trust must not enroll the root issuer kid
/// as a request signer and flushes its cache on an epoch advance, while signing mints
/// under both.
pub(super) struct Plans {
    pub(super) trust: TrustPlan,
    pub(super) signing: SigningPlan,
    pub(super) tls: ChannelEstablishmentPlan,
}

/// The admission limit the boundary resolved and the shard shape this host gives the
/// request, resolved ONCE: the inner plane and the fleet both size from these two values.
#[derive(Clone, Copy)]
pub(super) struct Sizing {
    pub(super) in_flight_limit: InFlightLimitBasis,
    pub(super) topology: ResolvedTopology,
}

/// The validated deployment, its plans, the posture ledger and the partly-built runtime.
pub(super) struct Startup<'a> {
    pub(super) config: &'a ValidatedDeployment,
    pub(super) shutdown: Arc<AtomicBool>,
    pub(super) plans: Plans,
    pub(super) sizing: Sizing,
    /// ADR-MCPRE-056 §5.4: from the first capability on, every optional capability states
    /// its posture in BOTH directions here, and `assert_complete` refuses to start — in
    /// every build profile — if any seam is left silent.
    pub(super) posture: PostureLog,
    pub(super) building: MaterializingRuntime,
}

impl<'a> Startup<'a> {
    /// Plan, then begin materializing.
    ///
    /// Everything before `begin` is pure and `begin` is the first effect: it records
    /// validation, planning and the start of materialization from the proof it is handed
    /// (ADR-MCPRE-057 §3, §9), so the composition root asserts nothing on its own word.
    pub(super) fn begin(
        config: &'a ValidatedDeployment,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        let (trust, signing) = crate::startup_plan::response_authority_plans(config);
        let tls = ChannelEstablishmentPlan::from_validated(config);
        let sizing = Sizing {
            in_flight_limit: config.state().in_flight_limit(),
            topology: ResolvedTopology::resolve(config.state().shard_topology()),
        };
        let building = MaterializingRuntime::begin(config)?;
        Ok(Self {
            config,
            shutdown,
            plans: Plans {
                trust,
                signing,
                tls,
            },
            sizing,
            posture: PostureLog::new(),
            building,
        })
    }
}

/// Install one optional capability and state its posture, from the ONE [`Established`]
/// value: the artifact is attached exactly when the posture says ON, and the seam named in
/// the call is the one stated. `scripts/seam_posture_gate.py` counts the call as that
/// seam's declaration.
pub(super) fn install_capability<P, T>(
    posture: &mut PostureLog,
    seam: Seam,
    target: P,
    established: Established<T>,
    attach: impl FnOnce(P, T) -> P,
) -> P {
    let (artifact, state) = established.into_parts();
    posture.declare(seam, state);
    match artifact {
        Some(artifact) => attach(target, artifact),
        None => target,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `assert_complete` reports as still unstated: the seam under test is not in it.
    fn stated_missing(posture: &PostureLog) -> String {
        posture
            .assert_complete()
            .expect_err("other seams are unstated")
    }

    #[test]
    fn an_on_capability_is_attached_and_its_seam_stated() {
        let mut posture = PostureLog::new();
        let out = install_capability(
            &mut posture,
            Seam::AdmissionCurrency,
            Vec::<u8>::new(),
            Established::on(7u8, "on"),
            |mut v, a| {
                v.push(a);
                v
            },
        );
        assert_eq!(out, vec![7]);
        assert!(!stated_missing(&posture).contains("AdmissionCurrency"));
    }

    #[test]
    fn an_off_capability_attaches_nothing_and_still_states_its_seam() {
        let mut posture = PostureLog::new();
        let out = install_capability(
            &mut posture,
            Seam::EvidenceRetention,
            Vec::<u8>::new(),
            Established::<u8>::off("off"),
            |_, _| unreachable!("an OFF capability has no artifact to attach"),
        );
        assert!(out.is_empty());
        assert!(!stated_missing(&posture).contains("EvidenceRetention"));
    }
}
