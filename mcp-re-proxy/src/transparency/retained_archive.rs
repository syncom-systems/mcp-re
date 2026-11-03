// SPDX-License-Identifier: Apache-2.0
//! WHICH retained hops an archive holds.
//!
//! One fact, and it is not the one [`super::durability`] owns. That one says at what
//! INSTANT a deployment became answerable for an exchange — a claim only the process that
//! serves the exchange can make, and one that costs write authority to make. This one says
//! what is in the directory now, which costs nothing but the ability to read it.
//!
//! # Why the two are separate owners (MCPRE-179)
//!
//! They were not, and the consequence was concrete: [`super::EvidenceRetention`] had one
//! constructor, it PROVES the directory writable by writing a probe object, and it starts
//! the writer thread the serving path hands jobs to. So the auditor — which only ever
//! reads — could not run against a read-only mount or a filesystem snapshot, held write
//! access to the evidence it was attesting, and started a thread that never received a job.
//!
//! None of that followed from anything about auditing. It followed from there being one
//! constructor, which is the shape ADR-MCPRE-061 §8 question 2 exists to find: *the archive
//! holds these bytes* and *this deployment may become answerable for more of them* are
//! independently describable, and the second one's consumer needs none of the first's
//! authority.
//!
//! So [`super::attest_chain`] takes this projection. An auditor opens one directly and never
//! constructs a retention authority at all; `EvidenceRetention` holds one over the root it
//! created, and asks it for the names it writes.
//!
//! # What it adds to the object archive underneath
//!
//! Two things. The record SCHEMA: the bytes come back re-addressed by
//! [`crate::retained_evidence::FsRetainedArchive`] — the check that a name determines its
//! bytes lives there and is not repeated here — and this owner turns them into a
//! [`RetainedHop`], or refuses. A chain with a gap is refused rather than reconstructed
//! from what happens to be present. And the MARKERS: which exchanges crossed the execution
//! threshold without a retained hop, and which reservations were left behind, named by
//! [`super::marker_stage::MarkerStage`] — the same rule the write side names them by.

use mcp_re_http_profile::chain::RetainedHop;
use mcp_re_http_profile::scitt::EvidenceDigest;

use crate::retained_evidence::FsRetainedArchive;

use super::marker_stage::MarkerStage;
use super::retained_record::RetainedHopRecord;
use super::RetentionError;

/// A read view of a retained-evidence archive, in hops rather than bytes.
pub struct RetainedArchive {
    objects: FsRetainedArchive,
}

impl RetainedArchive {
    /// Open an existing archive for READING ONLY.
    ///
    /// It takes no write authority, creates nothing and starts no thread, so it works
    /// against a read-only mount or a snapshot — the ordinary way an archive is handed to
    /// somebody meant to audit it and not to add to it.
    pub fn open_read_only(dir: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        Ok(RetainedArchive {
            objects: FsRetainedArchive::open_read_only(dir)?,
        })
    }

    /// The read view over an archive the retention authority has already opened for
    /// writing.
    ///
    /// `pub(super)`: the only legitimate producer of a projection over a root that was not
    /// separately checked is the owner that just created and proved it.
    pub(super) fn over(objects: FsRetainedArchive) -> Self {
        RetainedArchive { objects }
    }

    /// The content-addressed path for `digest`, refusing a name that is not a base64url
    /// token.
    ///
    /// The WRITE path needs the final name of an object it is about to stage, and it asks
    /// here rather than deriving it again: one rule about which names are legal, in the
    /// owner that reads them back.
    pub(super) fn object_path(
        &self,
        digest: &EvidenceDigest,
    ) -> Result<std::path::PathBuf, RetentionError> {
        self.objects
            .object_path(digest)
            .map_err(|_| RetentionError::Malformed("evidence digest is not a token"))
    }

    /// The path of the marker at `stage` for the exchange whose request digest is `digest`.
    ///
    /// Refused unless the digest is a token, because the name is the object path plus the
    /// stage extension; asked here for the same reason as [`object_path`](Self::object_path).
    pub(super) fn marker_path(
        &self,
        digest: &EvidenceDigest,
        stage: MarkerStage,
    ) -> Result<std::path::PathBuf, RetentionError> {
        Ok(stage.path_for(self.object_path(digest)?))
    }

    /// The digest tokens of every COMMITTED marker currently on disk.
    ///
    /// The reconciliation read, and it reads one stage only. A committed-stage marker
    /// records an exchange that crossed the execution threshold and whose outcome was
    /// never retained, and a fact recorded where nothing can enumerate it is not a record
    /// an auditor can act on: this is how the audit lane asks which calls crossed without
    /// landing a hop. It is a fact about the directory, so it is read here, with no write
    /// authority, and works on a read-only mount or a snapshot.
    ///
    /// Reserved-stage markers are deliberately NOT here. They record obligations accepted
    /// by exchanges that never committed, so counting them would be counting refused calls
    /// as calls that may have run — the collapse the stage split exists to remove. They
    /// have their own enumerator, [`stale_reservations`](Self::stale_reservations), and it
    /// answers a different question.
    pub fn pending_reservations(&self) -> Result<Vec<String>, RetentionError> {
        self.markers_at(MarkerStage::Committed)
    }

    /// The digest tokens of every RESERVED marker currently on disk.
    ///
    /// Cleanup debt, and nothing else. Each one is an obligation that was accepted by an
    /// exchange which then did not commit, and whose rescind did not land — a queue that
    /// was full when the reservation dropped, or a process that died between the two.
    ///
    /// An auditor must not read this as indeterminacy. That is the whole reason the stage
    /// has its own name on disk: a residue that says *nothing ran* is answerable by
    /// deleting it, and one that says *something may have* is not.
    pub fn stale_reservations(&self) -> Result<Vec<String>, RetentionError> {
        self.markers_at(MarkerStage::Reserved)
    }

    /// The digest tokens of every marker at one stage.
    fn markers_at(&self, stage: MarkerStage) -> Result<Vec<String>, RetentionError> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(self.objects.root()).map_err(RetentionError::Store)? {
            let entry = entry.map_err(RetentionError::Store)?;
            let name = entry.file_name();
            found.extend(name.to_str().and_then(|name| stage.digest_in(name)));
        }
        found.sort();
        Ok(found)
    }

    /// Read back one retained exchange.
    ///
    /// `Ok(None)` means the archive does not hold it — an auditor, not the archive,
    /// decides whether a missing hop is fatal for the reconstruction being attempted.
    pub fn load(&self, digest: &EvidenceDigest) -> Result<Option<RetainedHop>, RetentionError> {
        let Some(bytes) = self.objects.get(digest).map_err(RetentionError::Store)? else {
            return Ok(None);
        };
        let record: RetainedHopRecord = serde_json::from_slice(&bytes)
            .map_err(|_| RetentionError::Malformed("retained hop does not parse"))?;
        record.into_hop().map(Some)
    }

    /// Read back an ordered chain, refusing rather than reconstructing from a gap.
    ///
    /// A missing hop is fatal HERE because the caller asked for a specific ordered
    /// chain: silently reconstructing from the hops that happen to be present would
    /// produce a `Complete` label for a record with a hole in it, which is the quiet
    /// truncation the chain seam exists to prevent.
    pub fn load_chain(
        &self,
        digests: &[EvidenceDigest],
    ) -> Result<Vec<RetainedHop>, RetentionError> {
        digests
            .iter()
            .map(|digest| {
                self.load(digest)?
                    .ok_or(RetentionError::Malformed("retained chain is missing a hop"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory nobody may write to is still an archive. This is the whole point of the
    /// split: the auditor's constructor must not need the authority the serving one proves.
    #[test]
    #[cfg(unix)]
    fn a_read_only_archive_opens_where_the_retention_authority_refuses() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "mcp-re-retained-archive-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&root).expect("create");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).expect("chmod");

        let read_only = RetainedArchive::open_read_only(&root);
        let serving = super::super::EvidenceRetention::open(&root);

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let _ = std::fs::remove_dir_all(&root);

        assert!(read_only.is_ok(), "reading needs no write authority");
        assert!(
            serving.is_err(),
            "the serving constructor must still prove the archive writable at startup"
        );
    }

    /// Enumeration reads a name only when it is a stage extension over a digest token, and
    /// it reads with no more than a read-only archive.
    #[test]
    fn an_enumerated_marker_is_a_well_formed_token() {
        let root = std::env::temp_dir().join(format!(
            "mcp-re-retained-archive-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&root).expect("create");
        std::fs::write(root.join(".pending"), b"").expect("write");
        std::fs::write(root.join("not-a-digest.pending"), b"").expect("write");

        let found = RetainedArchive::open_read_only(&root)
            .expect("open")
            .pending_reservations();
        let _ = std::fs::remove_dir_all(&root);

        assert!(found.expect("list").is_empty());
    }

    /// A missing hop is absent, not an error — the caller decides.
    #[test]
    fn a_missing_hop_is_absent_rather_than_an_error() {
        let root = std::env::temp_dir().join(format!(
            "mcp-re-retained-archive-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&root).expect("create");
        let archive = RetainedArchive::open_read_only(&root).expect("open");
        let never = EvidenceDigest::of(b"never retained");
        assert!(archive.load(&never).expect("load").is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A digest whose object is not a retained record is refused, not reconstructed from.
    #[test]
    fn an_object_that_is_not_a_retained_record_is_refused() {
        let root = std::env::temp_dir().join(format!(
            "mcp-re-retained-archive-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&root).expect("create");
        let bytes = b"not a retained hop record".as_slice();
        let digest = EvidenceDigest::of(bytes);
        std::fs::write(root.join(digest.as_str()), bytes).expect("write");

        let archive = RetainedArchive::open_read_only(&root).expect("open");
        let loaded = archive.load(&digest);
        let _ = std::fs::remove_dir_all(&root);

        assert!(matches!(loaded, Err(RetentionError::Malformed(_))));
    }
}
