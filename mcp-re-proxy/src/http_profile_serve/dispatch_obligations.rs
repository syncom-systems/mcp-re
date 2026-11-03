// SPDX-License-Identifier: Apache-2.0
//! The two obligations a dispatch carries across the threshold, taken in ADR-MCPRE-070 D7's
//! order: the retention obligation ACCEPTED, the execution intent COMMITTED (G1), the crossing
//! RECORDED.
//!
//! After the reserve, so a refused reservation commits no intent. Before the crossing, so no
//! `.pending` marker exists for an exchange whose intent was never committed. A refusal at any
//! step drops what the earlier steps returned, and the reservation rescinds itself on drop, so
//! nothing is left behind.
//!
//! One function, so the order is stated once and its tests drive it over a real store and a
//! scripted authority without a serving proxy.

use mcp_re_http_profile::HttpRequest;

use crate::audit_commitment::AuditPosture;
use crate::audit_record::{ExchangeCoordinate, ExecutionIntent};
use crate::exchange_state::Established;
use crate::refusal::Refusal;
use crate::request_stages::{IntentDisposition, RetentionDisposition};

use super::retention::Retention;

/// Reserve retention for `request`, commit `intent` for the exchange `coordinate` names, then
/// record the crossing.
pub(super) async fn take(
    retention: &Retention,
    audit: &AuditPosture,
    request: &HttpRequest,
    coordinate: Option<ExchangeCoordinate>,
    intent: ExecutionIntent<'_>,
) -> Result<(Established<RetentionDisposition>, IntentDisposition), Refusal> {
    let accepted = retention.reserve(request).await?;
    let intent = audit.intent(coordinate, intent).await?;
    let crossing = retention.commit(accepted).await?;
    Ok((crossing, intent))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::audit_commitment::reference::{ReferenceAuthority, Step};
    use crate::audit_commitment::{
        CommitmentBound, DurabilityTier, EstablishedProvider, RejectReason,
    };
    use crate::transparency::EvidenceRetention;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("mcp-re-d7-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            Scratch(path)
        }

        fn markers(&self, extension: &str) -> usize {
            fn walk(dir: &Path, extension: &str) -> usize {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    return 0;
                };
                entries
                    .flatten()
                    .map(|entry| {
                        let path = entry.path();
                        if path.is_dir() {
                            walk(&path, extension)
                        } else {
                            usize::from(path.extension().is_some_and(|e| e == extension))
                        }
                    })
                    .sum()
            }
            walk(&self.0, extension)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn request() -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            target_uri: "https://example.test/mcp".into(),
            headers: vec![],
            body: b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}".to_vec(),
        }
    }

    fn required(steps: impl IntoIterator<Item = Step>) -> (Arc<ReferenceAuthority>, AuditPosture) {
        let authority = Arc::new(
            ReferenceAuthority::new(DurabilityTier::SurvivesProxyProcessLoss).scripted(steps),
        );
        let posture = AuditPosture::required(
            None,
            EstablishedProvider::eligible_for_test(authority.clone()),
            CommitmentBound::new(Duration::from_millis(200)).expect("a legal bound"),
        );
        (authority, posture)
    }

    fn accepted() -> Option<ExchangeCoordinate> {
        crate::audit_record::record_to(
            &None,
            None,
            crate::audit_record::AuditSubject::request_accepted(
                &crate::authorization::AuthorizationPosture::NoPolicyConfigured,
                crate::admission_enforcer::AdmissionFacet::NotConfigured,
            ),
            None,
            200,
            1,
        )
    }

    async fn taken(
        retention: &Retention,
        audit: &AuditPosture,
    ) -> Result<(Established<RetentionDisposition>, IntentDisposition), Refusal> {
        take(
            retention,
            audit,
            &request(),
            accepted(),
            ExecutionIntent::new("actor-a", 1),
        )
        .await
    }

    /// RESERVE BEFORE INTENT: a reservation the store refuses asks the authority nothing, so
    /// no intent exists for an exchange the deployment could not take responsibility for.
    #[tokio::test]
    async fn a_refused_reservation_commits_no_intent() {
        let scratch = Scratch::new("reserve");
        let mut store = EvidenceRetention::open(&scratch.0).expect("open");
        store.retire_writer_for_test();
        let retention = Retention::to(Arc::new(store));
        let (authority, audit) = required([Step::Commit]);
        assert!(taken(&retention, &audit).await.is_err());
        assert_eq!(authority.requests(), 0, "no intent was asked for");
    }

    /// INTENT BEFORE CROSSING: an intent the authority refuses leaves no `.pending` marker,
    /// and its reservation is rescinded.
    #[tokio::test]
    async fn a_refused_intent_records_no_crossing() {
        let scratch = Scratch::new("intent");
        let retention = Retention::to(Arc::new(EvidenceRetention::open(&scratch.0).expect("open")));
        let (authority, audit) = required([Step::Reject(RejectReason::Refused)]);
        assert!(taken(&retention, &audit).await.is_err());
        assert_eq!(authority.requests(), 1);
        assert_eq!(scratch.markers("pending"), 0, "no crossing was recorded");
        let mut waited = Duration::ZERO;
        while scratch.markers("reserved") > 0 && waited < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
            waited += Duration::from_millis(20);
        }
        assert_eq!(
            scratch.markers("reserved"),
            0,
            "the reservation was rescinded"
        );
    }

    /// All three steps: the crossing is recorded and the intent committed, once each.
    #[tokio::test]
    async fn the_crossing_is_recorded_once_the_intent_is_committed() {
        let scratch = Scratch::new("all");
        let retention = Retention::to(Arc::new(EvidenceRetention::open(&scratch.0).expect("open")));
        let (authority, audit) = required([Step::Commit]);
        let (crossing, intent) = taken(&retention, &audit).await.expect("both taken");
        assert!(matches!(intent, IntentDisposition::Committed(_)));
        assert_eq!(authority.journaled().len(), 1);
        assert_eq!(scratch.markers("pending"), 1, "the crossing is durable");
        let mut progress = crate::exchange_state::ExchangeProgress::new();
        assert!(matches!(
            progress.establish(crossing),
            RetentionDisposition::Committed { .. }
        ));
    }
}
