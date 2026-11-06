// SPDX-License-Identifier: Apache-2.0
//! The commitment-provider seam, driven from OUTSIDE the crate: a provider an embedder
//! compiled, implementing only the public contract.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use mcp_re_proxy::{
    AuditProviders, CommitFuture, CommitRequest, CommitmentAuthority, DurabilityTier,
    EstablishFailure, EstablishFuture, ProviderFailure, ProviderId,
};

use super::*;

/// A provider that DECLARES the qualifying tier and answers its probe as told. It keeps
/// a secret of its own, which must never reach a diagnostic.
struct FakeProvider {
    tier: DurabilityTier,
    probe: Result<(), EstablishFailure>,
    secret: &'static str,
    probes: AtomicUsize,
    tier_reads: AtomicUsize,
}

impl FakeProvider {
    fn new(tier: DurabilityTier, probe: Result<(), EstablishFailure>) -> Arc<Self> {
        Arc::new(FakeProvider {
            tier,
            probe,
            secret: "redis://journal:SECRET-xyz@10.0.0.9:6379",
            probes: AtomicUsize::new(0),
            tier_reads: AtomicUsize::new(0),
        })
    }
}

impl CommitmentAuthority for FakeProvider {
    fn provider_id(&self) -> ProviderId {
        ProviderId::new("fake-journal").expect("a legal name")
    }

    fn declared_tier(&self) -> DurabilityTier {
        self.tier_reads.fetch_add(1, Ordering::SeqCst);
        self.tier
    }

    fn establish(&self) -> EstablishFuture<'_> {
        self.probes.fetch_add(1, Ordering::SeqCst);
        let (answer, _locator) = (self.probe, self.secret);
        Box::pin(async move { answer })
    }

    fn commit<'a>(&'a self, _request: CommitRequest<'a>) -> CommitFuture<'a> {
        Box::pin(async { Err(ProviderFailure::Unavailable) })
    }
}

fn run_with(extra: &[&str], provider: Arc<FakeProvider>) -> String {
    let m = serving_fixtures::write_material();
    let deployment = mcp_re_proxy::cli::parse_args(&with(&m, extra)).expect("parses");
    let registered: Arc<dyn CommitmentAuthority> = provider;
    mcp_re_proxy::app::run_with(
        deployment,
        AuditProviders::with_commitment(registered),
        Arc::new(AtomicBool::new(true)),
    )
    .expect_err("these fixtures never reach the serve loop")
}

/// The stop every hermetic config here reaches once the audit posture is established.
fn replay_refusal() -> &'static str {
    if cfg!(feature = "redis_replay") {
        "connect redis"
    } else {
        "redis_replay"
    }
}

/// A fake-qualified provider whose probe fails is refused at startup, naming only the
/// provider and the class — and never its own text.
#[test]
fn a_fake_qualified_provider_that_fails_establishment_is_refused() {
    let provider = FakeProvider::new(
        DurabilityTier::SurvivesProxyProcessLoss,
        Err(EstablishFailure::Unreachable),
    );
    let refused = run_with(&["--audit-commitment", "required"], provider.clone());
    assert!(
        refused.contains("provider fake-journal could not be established: UNREACHABLE"),
        "{refused}"
    );
    assert!(!refused.contains("SECRET"), "{refused}");
    assert!(
        !refused.contains(replay_refusal()),
        "refused before replay: {refused}"
    );
    assert_eq!(provider.probes.load(Ordering::SeqCst), 1);
}

/// A provider declaring a volatile tier is refused before it is asked anything (D3).
#[test]
fn a_volatile_provider_is_refused_without_being_probed() {
    let provider = FakeProvider::new(DurabilityTier::ProcessVolatile, Ok(()));
    let refused = run_with(&["--audit-commitment", "required"], provider.clone());
    assert!(refused.contains("PROCESS_VOLATILE"), "{refused}");
    assert_eq!(provider.probes.load(Ordering::SeqCst), 0);
}

/// A qualified provider that answers is established inside the real startup, reading
/// its tier once, and startup goes on to its next stop.
#[test]
fn a_qualified_provider_is_established_inside_the_real_startup() {
    let provider = FakeProvider::new(DurabilityTier::SurvivesProxyProcessLoss, Ok(()));
    let refused = run_with(&["--audit-commitment", "required"], provider.clone());
    assert!(refused.contains(replay_refusal()), "{refused}");
    assert_eq!(provider.probes.load(Ordering::SeqCst), 1);
    assert_eq!(provider.tier_reads.load(Ordering::SeqCst), 1);
}

/// Registering a provider selects nothing: under best-effort it is never asked.
#[test]
fn a_registered_provider_is_not_promoted_under_best_effort() {
    let provider = FakeProvider::new(DurabilityTier::SurvivesProxyProcessLoss, Ok(()));
    let refused = run_with(&[], provider.clone());
    assert!(refused.contains(replay_refusal()), "{refused}");
    assert_eq!(provider.probes.load(Ordering::SeqCst), 0);
    assert_eq!(provider.tier_reads.load(Ordering::SeqCst), 0);
}
