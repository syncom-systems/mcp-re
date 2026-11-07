// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
#![cfg(feature = "redis_replay")]
//! The primary-and-replica topology the WAIT-quorum proof drives: attaching and detaching
//! the replica, and waiting for each change to be visible from both sides.

use std::time::{Duration, Instant};

use super::harness::{raw_conn, RedisUrl};

/// `(host, port)` parsed from a `redis://host:port[/db]` URL — the REPLICAOF target.
fn host_port(url: &RedisUrl) -> (String, u16) {
    let url = url.as_str();
    let s = url.strip_prefix("redis://").unwrap_or(url);
    let s = s.split('/').next().unwrap_or(s);
    let (host, port) = s.rsplit_once(':').expect("redis url is host:port");
    (
        host.to_string(),
        port.parse().expect("redis port is numeric"),
    )
}

/// The `INFO replication` text of `conn`.
fn replication_info(conn: &mut redis::Connection, which: &str) -> String {
    redis::cmd("INFO")
        .arg("replication")
        .query(conn)
        .unwrap_or_else(|e| panic!("INFO replication on {which}: {e}"))
}

/// `connected_slaves:N` from the primary's `INFO replication`, or -1 if absent.
pub(super) fn primary_connected_slaves(primary: &mut redis::Connection) -> i64 {
    replication_info(primary, "primary")
        .lines()
        .find_map(|l| l.trim().strip_prefix("connected_slaves:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(-1)
}

/// True when the replica reports it is a slave with its master link up.
fn replica_link_up(replica: &mut redis::Connection) -> bool {
    let info = replication_info(replica, "replica");
    let role_slave = info.lines().any(|l| l.trim() == "role:slave");
    let link_up = info.lines().any(|l| l.trim() == "master_link_status:up");
    role_slave && link_up
}

/// Poll `cond` until true or a 20s deadline, then panic — never a blind sleep.
fn poll_until<F: FnMut() -> bool>(what: &str, mut cond: F) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("timed out after 20s waiting for: {what}");
}

/// A primary and its replica, reattached when the value is dropped so a failing case
/// leaves the topology as the next case in the lane expects it.
pub(super) struct Topology {
    primary: redis::Connection,
    replica: redis::Connection,
    replica_url: String,
    master: (String, u16),
}

impl Topology {
    pub(super) fn open(primary_url: &RedisUrl, replica_url: &RedisUrl) -> Self {
        Self {
            primary: raw_conn(primary_url),
            replica: raw_conn(replica_url),
            replica_url: replica_url.as_str().to_owned(),
            master: host_port(primary_url),
        }
    }

    fn point_replica_at_master(&mut self, what: &str) {
        let _: () = redis::cmd("REPLICAOF")
            .arg(&self.master.0)
            .arg(self.master.1)
            .query(&mut self.replica)
            .unwrap_or_else(|e| panic!("{what}: {e}"));
    }

    /// Attach the replica and wait until its link is up and the primary sees it.
    pub(super) fn attach(&mut self) {
        self.point_replica_at_master("attach replica to primary");
        self.wait_until_attached("");
    }

    /// Attach the replica again after a detach, and wait until the topology has resynced.
    pub(super) fn reattach(&mut self) {
        self.point_replica_at_master("reattach replica to primary");
        self.wait_until_attached(" after reattach");
    }

    fn wait_until_attached(&mut self, suffix: &str) {
        let (primary, replica) = (&mut self.primary, &mut self.replica);
        poll_until(&format!("replica link up{suffix}"), || {
            replica_link_up(replica)
        });
        poll_until(&format!("primary connected_slaves>=1{suffix}"), || {
            primary_connected_slaves(primary) >= 1
        });
    }

    /// Detach the replica (`REPLICAOF NO ONE`) and wait until the primary sees none.
    pub(super) fn detach(&mut self) {
        let _: () = redis::cmd("REPLICAOF")
            .arg("NO")
            .arg("ONE")
            .query(&mut self.replica)
            .expect("detach replica (REPLICAOF NO ONE)");
        let primary = &mut self.primary;
        poll_until("primary connected_slaves==0", || {
            primary_connected_slaves(primary) == 0
        });
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        let Ok(mut conn) =
            redis::Client::open(self.replica_url.as_str()).and_then(|c| c.get_connection())
        else {
            return;
        };
        let _ = redis::cmd("REPLICAOF")
            .arg(self.master.0.as_str())
            .arg(self.master.1)
            .query::<()>(&mut conn);
    }
}
