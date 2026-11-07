// SPDX-License-Identifier: Apache-2.0
//! The standing tiers a run measures against: the backend that is already up, the
//! executables for the other two, and the fixture material they share.

use super::generators::Fleet;
use super::generators::Load;
use super::generators::Measurement;
use super::material::Material;
use super::proc::cpu_secs;
use super::proc::Proc;
use super::proxy::spawn_proxy;
use super::proxy::ProxySpec;

pub(super) struct Rig {
    pub(super) proxy_cli: String,
    pub(super) gen_exe: String,
    pub(super) material: Material,
    pub(super) redis: String,
    pub(super) backend_addr: String,
    pub(super) backend_pid: u32,
    pub(super) tier: String,
}

impl Rig {
    /// Spawn a proxy with `cores` per-core workers and `headroom` for both its
    /// connection and in-flight ceilings. Returns it with its serving address.
    pub(super) fn spawn_proxy(&self, cores: usize, headroom: usize) -> (Proc, String) {
        let spec = ProxySpec {
            cores,
            redis: &self.redis,
            inner: &self.backend_addr,
            tier: &self.tier,
            headroom,
        };
        spawn_proxy(&self.proxy_cli, &self.material, &spec)
    }

    pub(super) fn generate(&self, target: &str, generators: usize, load: &Load) -> Measurement {
        Fleet {
            exe: &self.gen_exe,
            material: &self.material,
            target,
            load,
        }
        .run(generators)
    }

    pub(super) fn backend_cpu(&self) -> f64 {
        cpu_secs(self.backend_pid)
    }
}
