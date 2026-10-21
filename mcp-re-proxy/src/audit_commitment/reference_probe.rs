// SPDX-License-Identifier: Apache-2.0
//! How the reference authority answers its startup probe. Test-only flavors, like the
//! authority.

#[cfg(test)]
use super::EstablishFailure;
use super::EstablishFuture;

/// How the reference authority answers its startup probe.
#[derive(Debug, Clone)]
pub(crate) enum EstablishStep {
    /// Establish.
    Succeed,
    /// Refuse with this class.
    #[cfg(test)]
    Fail(EstablishFailure),
    /// Refuse, with an error text of the provider's own that must never be printed.
    #[cfg(test)]
    FailSaying(&'static str),
    /// Never answer.
    #[cfg(test)]
    Hang,
    /// Panic while the answer is polled.
    #[cfg(test)]
    PanicInPoll,
    /// Panic before any answer exists.
    #[cfg(test)]
    PanicBeforeFuture,
}

impl EstablishStep {
    /// The probe's answer.
    pub(super) fn answer(self) -> EstablishFuture<'static> {
        match self {
            EstablishStep::Succeed => Box::pin(std::future::ready(Ok(()))),
            #[cfg(test)]
            EstablishStep::Fail(class) => Box::pin(std::future::ready(Err(class))),
            // The text is the provider's own and stays with it: the answer is a class.
            #[cfg(test)]
            EstablishStep::FailSaying(_text) => {
                Box::pin(std::future::ready(Err(EstablishFailure::Misconfigured)))
            }
            #[cfg(test)]
            EstablishStep::Hang => Box::pin(std::future::pending()),
            #[cfg(test)]
            EstablishStep::PanicInPoll => Box::pin(async { panic!("reference probe fault") }),
            #[cfg(test)]
            EstablishStep::PanicBeforeFuture => panic!("reference probe fault before its future"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn each_step_answers_as_named() {
        assert_eq!(EstablishStep::Succeed.answer().await, Ok(()));
        assert_eq!(
            EstablishStep::Fail(EstablishFailure::Unauthorized)
                .answer()
                .await,
            Err(EstablishFailure::Unauthorized)
        );
        assert_eq!(
            EstablishStep::FailSaying("SECRET").answer().await,
            Err(EstablishFailure::Misconfigured)
        );
    }
}
