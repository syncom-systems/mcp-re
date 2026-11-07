// SPDX-License-Identifier: Apache-2.0
//! An evidence-retention root that can be made to fail after it has proved itself writable.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use mcp_re_proxy::transparency::EvidenceRetention;

/// A retention store that accepts being opened and then cannot write.
///
/// Read-only after `open` has already proved it writable, which is the shape of the real
/// failure this covers: a volume that goes away under a running proxy, not a
/// misconfiguration caught at startup.
pub(super) struct WedgedRetentionDir(PathBuf);

impl WedgedRetentionDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mcp-re-mrt-retention-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the retention root");
        WedgedRetentionDir(path)
    }

    pub(super) fn path(&self) -> &std::path::Path {
        &self.0
    }

    /// From here on the root is unwritable.
    pub(super) fn wedge(&self) {
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o500))
            .expect("make the retention root unwritable");
    }
}

impl Drop for WedgedRetentionDir {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A retention store opened over a fresh root named `name` while it is still writable, and
/// the root, which the caller may wedge afterwards.
pub(super) fn retention_in(name: &str) -> (WedgedRetentionDir, Arc<EvidenceRetention>) {
    let dir = WedgedRetentionDir::new(name);
    let retention = Arc::new(
        EvidenceRetention::open(dir.path()).expect("retention opens while the root is writable"),
    );
    (dir, retention)
}
