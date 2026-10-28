// SPDX-License-Identifier: Apache-2.0
//! WHICH name a retention marker carries at each stage, and how a name is read back.
//!
//! One rule, in one owner. A marker is named by the object path of its exchange's request
//! digest plus a stage extension; the extension keeps it out of the content-addressed
//! namespace, which is read back by bare digest and can therefore never resolve to one of
//! these. Writing a marker and enumerating markers both go through this type, so the name a
//! reservation writes is the name a reconciliation reads.

use std::path::PathBuf;

use mcp_re_http_profile::scitt::EvidenceDigest;

/// The stage a retention marker records. Closed: no marker is named, or enumerated, at a
/// stage the obligation does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MarkerStage {
    /// The exchange has not committed to dispatching: `<request-digest>.reserved`.
    ///
    /// A separate NAME from [`MarkerStage::Committed`] is the whole repair. One artefact was
    /// asked to mean two contradictory things — *responsibility is accepted, nothing has run*
    /// at `reserve`, and *this call crossed the execution threshold and its outcome was never
    /// retained* at reconciliation — so no byte on disk distinguished a refused call from one
    /// whose backend may have acted. Two names, and the commitment is the rename between them.
    Reserved,
    /// The exchange has committed to dispatching: `<request-digest>.pending`.
    ///
    /// The one an auditor reads as *this exact request crossed the execution threshold and its
    /// outcome was never retained*. Distinct from [`MarkerStage::Reserved`] because those are
    /// different facts, and a reconciliation that could not tell them apart counted refused
    /// calls as calls that may have run.
    Committed,
}

impl MarkerStage {
    fn extension(self) -> &'static str {
        match self {
            MarkerStage::Reserved => "reserved",
            MarkerStage::Committed => "pending",
        }
    }

    /// The marker at this stage for the object at `object`.
    pub(super) fn path_for(self, object: PathBuf) -> PathBuf {
        let mut name = object.into_os_string();
        name.push(".");
        name.push(self.extension());
        PathBuf::from(name)
    }

    /// The digest token a marker file name carries at this stage, if it is one.
    pub(super) fn digest_in(self, file_name: &str) -> Option<String> {
        let token = file_name
            .strip_suffix(self.extension())?
            .strip_suffix('.')?;
        let digest = EvidenceDigest::from_token(token).ok()?;
        Some(digest.as_str().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> EvidenceDigest {
        EvidenceDigest::of(b"one exchange")
    }

    #[test]
    fn each_stage_reads_back_the_digest_it_names() {
        for stage in [MarkerStage::Reserved, MarkerStage::Committed] {
            let path = stage.path_for(PathBuf::from("root").join(digest().as_str()));
            let name = path.file_name().and_then(|n| n.to_str()).expect("a name");
            assert_eq!(stage.digest_in(name), Some(digest().as_str().to_owned()));
        }
    }

    #[test]
    fn the_two_stages_never_read_each_others_markers() {
        let reserved = MarkerStage::Reserved.path_for(PathBuf::from(digest().as_str()));
        let name = reserved.to_str().expect("a name");
        assert_eq!(MarkerStage::Committed.digest_in(name), None);
    }

    #[test]
    fn a_name_that_is_not_a_digest_token_reads_back_nothing() {
        for name in [".pending", "not-a-digest.pending", "pending"] {
            assert_eq!(MarkerStage::Committed.digest_in(name), None, "{name}");
        }
    }
}
