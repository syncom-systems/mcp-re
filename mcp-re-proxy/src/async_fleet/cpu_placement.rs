// SPDX-License-Identifier: Apache-2.0
//! Which CPU a serving shard is pinned to (#1196).
//!
//! A shard's index is mapped onto the CPUs this process is ALLOWED to run on — the affinity
//! mask it was started with (`taskset`, a cgroup cpuset, a Kubernetes static CPU manager) —
//! not onto every online CPU. Mapping onto `0..online_cpus` pinned shards outside an
//! operator's mask (the call succeeds, so the mask stopped meaning anything) or, under a
//! cpuset, failed to pin and left the shard floating with nothing recorded.
//!
//! The allowed set is read ONCE, before any shard is spawned, so every shard maps onto the
//! same set: a shard reading the mask after an earlier shard pinned itself would read that
//! shard's single CPU on a platform where the mask is inherited per thread.
//!
//! Pinning is a tail-latency optimization, never a correctness property: every failure is
//! ignored, and a set that cannot be read falls back to the online CPUs.

/// The CPUs serving shards are placed on, in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CpuPlacement {
    allowed: Vec<usize>,
}

impl CpuPlacement {
    /// The CPUs this process may run on now: its affinity mask on Linux, falling back to the
    /// online CPUs when the mask cannot be read. Empty off Linux, where nothing is pinned.
    pub(super) fn of_this_process() -> Self {
        CpuPlacement {
            allowed: allowed_cpus(),
        }
    }

    /// The CPU shard `core_index` is pinned to: the `core_index`-th allowed CPU, wrapping when
    /// shards outnumber them. `None` when no CPU is known, and nothing is pinned.
    pub(super) fn cpu_for(&self, core_index: usize) -> Option<usize> {
        let slot = core_index.checked_rem(self.allowed.len())?;
        self.allowed.get(slot).copied()
    }

    /// Pin the calling thread to [`cpu_for`](Self::cpu_for)`(core_index)`. Best-effort.
    pub(super) fn pin_current_thread(&self, core_index: usize) {
        if let Some(cpu) = self.cpu_for(core_index) {
            pin_current_thread_to(cpu);
        }
    }
}

/// The calling thread's affinity mask, as CPU numbers; the online CPUs when it cannot be read.
#[cfg(target_os = "linux")]
fn allowed_cpus() -> Vec<usize> {
    // SAFETY: `set` is a zeroed, fully-owned `cpu_set_t`; `sched_getaffinity(0, ..)` writes
    // the calling thread's mask into it and does not retain the pointer; `CPU_ISSET` reads one
    // bit of it for an index below `CPU_SETSIZE`.
    let allowed: Vec<usize> = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
            return online_cpus();
        }
        let size = usize::try_from(libc::CPU_SETSIZE).unwrap_or(0);
        (0..size)
            .filter(|&cpu| libc::CPU_ISSET(cpu, &set))
            .collect()
    };
    if allowed.is_empty() {
        return online_cpus();
    }
    allowed
}

/// No portable affinity mask: nothing is placed.
#[cfg(not(target_os = "linux"))]
fn allowed_cpus() -> Vec<usize> {
    Vec::new()
}

/// `0..n` for the `n` online CPUs: `sysconf(_SC_NPROCESSORS_ONLN)`, then
/// `available_parallelism`, then 1.
#[cfg(target_os = "linux")]
fn online_cpus() -> Vec<usize> {
    // SAFETY: `sysconf` takes an int name and returns a long; no pointers involved.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let n = usize::try_from(n)
        .ok()
        .filter(|&n| n > 0)
        .or_else(|| std::thread::available_parallelism().ok().map(|x| x.get()))
        .unwrap_or(1);
    (0..n).collect()
}

/// Pin the calling thread to `cpu` (`sched_setaffinity`). The result is ignored.
#[cfg(target_os = "linux")]
fn pin_current_thread_to(cpu: usize) {
    // SAFETY: `cpu_set` is a zeroed, fully-owned `cpu_set_t`; `CPU_SET` sets one bit for a
    // CPU number the kernel reported in this thread's mask; `sched_setaffinity(0, ...)`
    // applies it to the calling thread and does not retain the pointer.
    unsafe {
        let mut cpu_set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut cpu_set);
        let _ = libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &cpu_set as *const libc::cpu_set_t,
        );
    }
}

/// No portable thread-affinity syscall: pinning is a no-op.
#[cfg(not(target_os = "linux"))]
fn pin_current_thread_to(_cpu: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shards map onto the allowed CPUs in order and wrap, so a mask of three CPUs keeps every
    /// shard on those three — the property `core_index % online_cpus` did not have.
    #[test]
    fn shards_map_onto_the_allowed_cpus_in_order_and_wrap() {
        let placement = CpuPlacement {
            allowed: vec![2, 5, 7],
        };
        let placed: Vec<_> = (0..5).map(|i| placement.cpu_for(i)).collect();
        assert_eq!(placed, [Some(2), Some(5), Some(7), Some(2), Some(5)]);
    }

    /// No known CPU places nothing, rather than dividing by zero or pinning CPU 0.
    #[test]
    fn no_known_cpu_places_nothing() {
        let placement = CpuPlacement { allowed: vec![] };
        assert_eq!(placement.cpu_for(0), None);
        placement.pin_current_thread(0);
    }

    /// The placement is read from the actual mask: a thread restricted to one CPU (what
    /// `taskset` does to a process) places every shard on that CPU.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_restricted_mask_keeps_every_shard_inside_it() {
        let all = CpuPlacement::of_this_process();
        let Some(first) = all.cpu_for(0) else {
            panic!("a Linux process has at least one allowed CPU");
        };
        let mask = vec![first];
        let read = std::thread::spawn(move || {
            pin_current_thread_to(first);
            CpuPlacement::of_this_process()
        })
        .join()
        .expect("the probe thread");
        assert_eq!(read, CpuPlacement { allowed: mask });
        assert!((0..8).all(|i| read.cpu_for(i) == Some(first)));
    }
}
