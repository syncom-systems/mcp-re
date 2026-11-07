//! What an AWS KMS refusal of the session credential costs, and what it discards.
//!
//! A cached session credential can stop being honoured by KMS before the expiry it was cached
//! under, and nothing else evicts it. This module owns the one answer: KMS refusing the
//! credential as expired or unrecognized discards exactly the credential that was presented
//! and re-signs ONCE with a fresh one. `AccessDeniedException`, throttling and every other
//! name discard nothing and cost one call, because a fresh credential cannot fix them and
//! evicting on them is a per-handshake STS exchange drivable by a peer. A refusal a fresh
//! credential does not fix suspends the retry for [`CREDENTIAL_REFUSAL_RETRY_COOLDOWN`].

use crate::aws_sigv4::AwsCredentials;
use crate::aws_sts::AwsCredentialSource;
use crate::key_source::KeyError;
use crate::remote_signer_call::RemoteSignerFailure;
use crate::remote_signer_call::NETWORK_TIMEOUT;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

/// The `__type` names with which KMS says it will not read the credential itself.
const SESSION_CREDENTIAL_REFUSALS: &[&str] =
    &["ExpiredTokenException", "UnrecognizedClientException"];

/// How long a refusal that a FRESH credential did not fix suspends the retry.
const CREDENTIAL_REFUSAL_RETRY_COOLDOWN: Duration = NETWORK_TIMEOUT;

/// Did KMS refuse the session credential itself? Reads only the `__type` of the body: the
/// suffix after the last `#` and before any `:`.
fn refused_the_session_credential(failure: &RemoteSignerFailure) -> bool {
    let Some(body) = failure.body() else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let Some(kind) = parsed.get("__type").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let name = kind.rsplit('#').next().unwrap_or(kind);
    let name = name.split(':').next().unwrap_or(name);
    SESSION_CREDENTIAL_REFUSALS.contains(&name)
}

/// The failure reported when the replacement credential could not be acquired, carrying the
/// refusal that made one necessary.
fn reacquisition_failed(
    error: &KeyError,
    refused: RemoteSignerFailure,
    operation: &str,
) -> RemoteSignerFailure {
    RemoteSignerFailure::rendered(KeyError::NotFound(format!(
        "credential re-acquisition failed: {error}; after {}",
        refused.into_key_error("aws-kms", operation)
    )))
}

/// One signing call's view of the credential it presented: where a fresh one comes from, which
/// access key id went out, which KMS operation it was for, and the instant the call is judged
/// at.
pub(super) struct Presentation<'a> {
    source: &'a dyn AwsCredentialSource,
    presented: Option<String>,
    operation: &'a str,
    now: Instant,
}

impl<'a> Presentation<'a> {
    pub(super) fn new(
        source: &'a dyn AwsCredentialSource,
        presented: Option<String>,
        operation: &'a str,
    ) -> Self {
        Self::at(Instant::now(), source, presented, operation)
    }

    fn at(
        now: Instant,
        source: &'a dyn AwsCredentialSource,
        presented: Option<String>,
        operation: &'a str,
    ) -> Self {
        Self {
            source,
            presented,
            operation,
            now,
        }
    }
}

/// The refused-credential retry and its suspension.
pub(super) struct RefusalRecovery {
    /// When the last refusal that a fresh credential did not fix was observed. `None` in the
    /// steady state. Held as a start rather than an end so no `Instant` arithmetic can overflow.
    suspended_since: Mutex<Option<Instant>>,
}

impl RefusalRecovery {
    pub(super) fn new() -> Self {
        Self {
            suspended_since: Mutex::new(None),
        }
    }

    /// Return `first`, or when KMS refused the credential `call` presented, discard it and call
    /// `resend` once with a fresh one.
    pub(super) fn recover(
        &self,
        call: Presentation<'_>,
        first: Result<Vec<u8>, RemoteSignerFailure>,
        resend: impl FnOnce(AwsCredentials) -> Result<Vec<u8>, RemoteSignerFailure>,
    ) -> Result<Vec<u8>, RemoteSignerFailure> {
        let refused = match first {
            Ok(body) => return Ok(body),
            Err(error) => error,
        };
        let Some(presented) = call.presented.as_deref() else {
            return Err(refused);
        };
        if !self.retry_is_warranted(&refused, &call, presented) {
            return Err(refused);
        }
        let fresh = match call.source.credentials() {
            Ok(fresh) => fresh,
            Err(error) => {
                self.suspend(call.now);
                return Err(reacquisition_failed(&error, refused, call.operation));
            }
        };
        let resent = resend(fresh);
        self.record_outcome(&resent, call.now);
        resent
    }

    /// The refusal names the credential, the retry is not suspended, and the source still held
    /// the refused credential, so discarding it did something. Evaluated in that order: the
    /// source is asked to discard only once the first two hold.
    fn retry_is_warranted(
        &self,
        refused: &RemoteSignerFailure,
        call: &Presentation<'_>,
        presented: &str,
    ) -> bool {
        refused_the_session_credential(refused)
            && !self.suspended_at(call.now)
            && call.source.invalidate(presented)
    }

    /// A fresh credential that works ends any suspension; one KMS refuses too starts it.
    fn record_outcome(&self, resent: &Result<Vec<u8>, RemoteSignerFailure>, now: Instant) {
        match resent {
            Ok(_) => *self.since() = None,
            Err(error) if refused_the_session_credential(error) => self.suspend(now),
            Err(_) => {}
        }
    }

    fn since(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        self.suspended_since
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Is the retry suspended at `now`? Clears a lapsed suspension.
    fn suspended_at(&self, now: Instant) -> bool {
        let mut since = self.since();
        match *since {
            Some(start)
                if now.saturating_duration_since(start) < CREDENTIAL_REFUSAL_RETRY_COOLDOWN =>
            {
                true
            }
            Some(_) => {
                *since = None;
                false
            }
            None => false,
        }
    }

    /// Never shortens: a straggler holding an older `now` leaves a later start in place.
    fn suspend(&self, now: Instant) {
        let mut since = self.since();
        *since = Some(since.map_or(now, |current| current.max(now)));
    }
}

impl super::UreqKmsClient {
    /// Refresh before signing; a failed refresh keeps the last-good credentials and is reported
    /// once per failing episode. Poison is recovered: the guarded value is a whole-value swap.
    /// Returns the access key id installed.
    pub(super) fn refresh(&self) -> Option<String> {
        match self.credential_source.credentials() {
            Ok(refreshed) => {
                let presented = refreshed.access_key_id.clone();
                let mut signer = self.signer.write().unwrap_or_else(|p| p.into_inner());
                signer.set_credentials(refreshed);
                self.refresh_failing.store(false, Ordering::Relaxed);
                Some(presented)
            }
            Err(e) if !self.refresh_failing.swap(true, Ordering::Relaxed) => {
                eprintln!("mcp-re-proxy: aws-kms credential refresh failed; signing continues on the last-good credentials: {e}");
                None
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    #[derive(Default)]
    struct CountingSource {
        credentials: AtomicUsize,
        invalidations: AtomicUsize,
        replaced: bool,
        fails: bool,
    }

    impl AwsCredentialSource for CountingSource {
        fn credentials(&self) -> Result<AwsCredentials, KeyError> {
            self.credentials.fetch_add(1, Ordering::SeqCst);
            if self.fails {
                return Err(KeyError::NotFound("sts down".to_string()));
            }
            Ok(AwsCredentials {
                access_key_id: "AKIDFRESH".to_string(),
                secret_access_key: zeroize::Zeroizing::new("secret".to_string()),
                session_token: None,
            })
        }
        fn invalidate(&self, _refused: &str) -> bool {
            self.invalidations.fetch_add(1, Ordering::SeqCst);
            !self.replaced
        }
        fn describe(&self) -> String {
            "counting".to_string()
        }
    }

    fn refusal(kind: &str) -> RemoteSignerFailure {
        RemoteSignerFailure::status_body(400, format!("{{\"__type\":\"{kind}\"}}"))
    }

    /// A recovery, its counting source, and how many times the resend ran.
    struct Rig {
        recovery: RefusalRecovery,
        source: CountingSource,
        resent: AtomicUsize,
    }

    impl Rig {
        fn new() -> Self {
            Self::with_source(CountingSource::default())
        }

        fn with_source(source: CountingSource) -> Self {
            Self {
                recovery: RefusalRecovery::new(),
                source,
                resent: AtomicUsize::new(0),
            }
        }

        /// Recover `first` at `now`, the resend succeeding when it runs.
        fn recover(
            &self,
            now: Instant,
            first: RemoteSignerFailure,
        ) -> Result<Vec<u8>, RemoteSignerFailure> {
            self.recover_with(now, first, Ok(b"{}".to_vec()))
        }

        /// Recover a refused credential whose replacement KMS refuses as well.
        fn recover_refused_again(&self, now: Instant) -> Result<Vec<u8>, RemoteSignerFailure> {
            self.recover_with(
                now,
                refusal("ExpiredTokenException"),
                Err(refusal("ExpiredTokenException")),
            )
        }

        fn recover_with(
            &self,
            now: Instant,
            first: RemoteSignerFailure,
            answer: Result<Vec<u8>, RemoteSignerFailure>,
        ) -> Result<Vec<u8>, RemoteSignerFailure> {
            let call = Presentation::at(now, &self.source, Some("AKIDOLD".to_string()), "Sign");
            self.recovery.recover(call, Err(first), |_| {
                self.resent.fetch_add(1, Ordering::SeqCst);
                answer
            })
        }

        fn invalidations(&self) -> usize {
            self.source.invalidations.load(Ordering::SeqCst)
        }

        fn fresh_credentials(&self) -> usize {
            self.source.credentials.load(Ordering::SeqCst)
        }

        fn resends(&self) -> usize {
            self.resent.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn only_an_expired_or_unrecognized_session_credential_is_a_refusal_of_the_credential() {
        for named in [
            "ExpiredTokenException",
            "UnrecognizedClientException",
            "com.amazonaws.kms#ExpiredTokenException",
        ] {
            assert!(refused_the_session_credential(&refusal(named)), "{named}");
        }
        for other in [
            "AccessDeniedException",
            "ThrottlingException",
            "InvalidSignatureException",
        ] {
            assert!(!refused_the_session_credential(&refusal(other)), "{other}");
        }
        for body in ["{}", "not json"] {
            let failure = RemoteSignerFailure::status_body(400, body.to_string());
            assert!(!refused_the_session_credential(&failure), "{body}");
        }
        assert!(!refused_the_session_credential(
            &RemoteSignerFailure::transport("down".to_string())
        ));
    }

    #[test]
    fn a_refused_session_credential_is_discarded_and_the_call_retried_once() {
        let rig = Rig::new();
        let out = rig.recover(Instant::now(), refusal("ExpiredTokenException"));
        assert!(out.is_ok());
        assert_eq!(rig.invalidations(), 1);
        assert_eq!(rig.fresh_credentials(), 1);
        assert_eq!(rig.resends(), 1);
    }

    #[test]
    fn an_access_denied_refusal_discards_nothing_and_costs_one_call() {
        let rig = Rig::new();
        let out = rig.recover(Instant::now(), refusal("AccessDeniedException"));
        assert!(out.is_err());
        assert_eq!(rig.invalidations(), 0);
        assert_eq!(rig.fresh_credentials(), 0);
        assert_eq!(rig.resends(), 0);
    }

    #[test]
    fn a_refusal_about_a_credential_already_replaced_costs_no_second_call() {
        let rig = Rig::with_source(CountingSource {
            replaced: true,
            ..CountingSource::default()
        });
        let out = rig.recover(Instant::now(), refusal("ExpiredTokenException"));
        assert!(out.is_err());
        assert_eq!(rig.invalidations(), 1);
        assert_eq!(rig.resends(), 0);
    }

    #[test]
    fn a_refusal_a_fresh_credential_does_not_fix_suspends_the_retry_for_the_cool_off() {
        let rig = Rig::new();
        let now = Instant::now();
        assert!(rig.recover_refused_again(now).is_err());
        assert_eq!(rig.resends(), 1);
        assert!(rig.recover_refused_again(now).is_err());
        assert_eq!(rig.invalidations(), 1, "suspended: no invalidate");
        assert_eq!(rig.resends(), 1, "suspended: no resend");
        assert!(rig
            .recover_refused_again(now + CREDENTIAL_REFUSAL_RETRY_COOLDOWN)
            .is_err());
        assert_eq!(rig.resends(), 2, "the cool-off lapsed");
    }
}
