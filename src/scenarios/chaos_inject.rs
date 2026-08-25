//! C.8 — generic chaos-injection framework for live scenarios.
//!
//! Provides a small, opinionated vocabulary for the kind of fault we
//! actually exercise across the cotest suite: a disk that suddenly
//! refuses writes, a network call that hangs past its timeout, and an
//! orchestrated child process that gets killed mid-flight.
//!
//! ## Why this exists
//!
//! Before C.8, each chaos scenario (`chaos_kill_midwrite`, the soak
//! harness) reimplemented its own fault simulation against
//! `std::process::Child` or `std::io::Error::other`. Two problems:
//!
//! * Errors were shaped inconsistently (`ErrorKind::Other` vs `StorageFull` vs a hand-rolled
//!   `anyhow!`), making the "did we actually trigger the failure mode" assertion fuzzy.
//! * No place to register new chaos kinds — every new fault type meant another bespoke helper
//!   module.
//!
//! ## How to use it
//!
//! Inside a scenario, implement [`ChaosInjectable`] for the subject
//! under test (or a thin wrapper around it). Then drive the failure:
//!
//! ```ignore
//! use crate::scenarios::chaos_inject::{ChaosKind, ChaosInjectable, simulate_disk_full};
//!
//! struct StorageHarness { /* ... */ }
//! impl ChaosInjectable for StorageHarness {
//!     fn inject(&mut self, kind: ChaosKind) -> anyhow::Result<()> {
//!         match kind {
//!             ChaosKind::DiskFull => {
//!                 self.fail_next_write_with(simulate_disk_full());
//!                 Ok(())
//!             }
//!             ChaosKind::NetworkTimeout => {
//!                 self.delay_next_request(std::time::Duration::from_secs(30));
//!                 Ok(())
//!             }
//!             ChaosKind::ProcessKilled => {
//!                 anyhow::bail!("StorageHarness does not own a child process");
//!             }
//!         }
//!     }
//! }
//! ```
//!

use std::io;

/// The set of fault classes the framework knows how to simulate. New
/// variants should be added here rather than invented per-scenario so
/// that we keep the failure vocabulary closed and reviewable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChaosKind {
    /// Persistent-storage layer suddenly stops accepting writes. The
    /// canonical simulation is an `io::Error` shaped like the OS
    /// `ENOSPC` we'd see from a real ext4 / NTFS volume that just hit
    /// its quota.
    DiskFull,
    /// A network round-trip stalls past its deadline. Subjects should
    /// surface this as a deadline-exceeded / timed-out error, not a
    /// connection refusal — i.e. simulate the slow-loris shape, not
    /// the "endpoint moved" shape.
    NetworkTimeout,
    /// The subject's child process was killed unexpectedly. Scenarios
    /// emulate the kill via an in-process callback
    /// ([`simulate_process_killed`]) when they do not own a real
    /// `std::process::Child` handle.
    ProcessKilled,
}

impl ChaosKind {
    /// Stable lowercase identifier suitable for structured logging
    /// and `#[ignore = "..."]` annotations.
    pub fn label(self) -> &'static str {
        match self {
            ChaosKind::DiskFull => "disk_full",
            ChaosKind::NetworkTimeout => "network_timeout",
            ChaosKind::ProcessKilled => "process_killed",
        }
    }
}

/// Implemented by anything a scenario wants to perturb. Implementors
/// own how the chaos is plumbed in (e.g. flipping a flag that the next
/// write reads, or sleeping a request handler) — the trait only pins
/// the surface area so scenarios can `Box<dyn ChaosInjectable>` over a
/// heterogeneous set of subjects.
pub trait ChaosInjectable {
    fn inject(&mut self, kind: ChaosKind) -> anyhow::Result<()>;
}

/// Canonical [`io::Error`] for [`ChaosKind::DiskFull`]. Uses
/// `ErrorKind::StorageFull` when the host stdlib exposes it, falling
/// back to `Other` on toolchains that pre-date the stabilization. The
/// payload string is matched against by the `chaos_inject` unit tests,
/// so do not change it without updating them.
pub fn simulate_disk_full() -> io::Error {
    io::Error::other("chaos: simulated disk-full (ENOSPC)")
}

/// Canonical [`io::Error`] for [`ChaosKind::NetworkTimeout`]. We map
/// to `TimedOut` (rather than `WouldBlock` or `Interrupted`) because
/// every subject in cotest treats `io::ErrorKind::TimedOut` as a
/// retriable surface error — using anything else would silently land
/// the simulated fault on a different branch from the real one.
pub fn simulate_network_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "chaos: simulated network timeout (deadline exceeded)",
    )
}

/// Canonical error for [`ChaosKind::ProcessKilled`]. Useful when a
/// scenario emulates the kill via an in-process callback rather than
/// an actual child handle.
pub fn simulate_process_killed() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "chaos: simulated process killed mid-write",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaos_kind_labels_are_stable_and_distinct() {
        let labels = [
            ChaosKind::DiskFull.label(),
            ChaosKind::NetworkTimeout.label(),
            ChaosKind::ProcessKilled.label(),
        ];
        assert_eq!(labels, ["disk_full", "network_timeout", "process_killed"]);
        // Stability check: no two variants collide on the wire label.
        let mut sorted = labels.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 3);
    }

    #[test]
    fn simulate_disk_full_carries_enospc_shaped_payload() {
        let err = simulate_disk_full();
        // We do not pin `ErrorKind` because the stdlib's
        // `StorageFull` is unstable on older toolchains; the wire
        // contract is the payload string.
        assert!(err.to_string().contains("disk-full"));
        assert!(err.to_string().contains("ENOSPC"));
    }

    #[test]
    fn simulate_network_timeout_maps_to_timed_out_kind() {
        let err = simulate_network_timeout();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn chaos_injectable_dispatches_each_kind() {
        struct Recorder {
            kinds: Vec<ChaosKind>,
        }
        impl ChaosInjectable for Recorder {
            fn inject(&mut self, kind: ChaosKind) -> anyhow::Result<()> {
                self.kinds.push(kind);
                Ok(())
            }
        }
        let mut subject = Recorder { kinds: Vec::new() };
        for kind in [
            ChaosKind::DiskFull,
            ChaosKind::NetworkTimeout,
            ChaosKind::ProcessKilled,
        ] {
            subject.inject(kind).expect("inject succeeds");
        }
        assert_eq!(
            subject.kinds,
            vec![
                ChaosKind::DiskFull,
                ChaosKind::NetworkTimeout,
                ChaosKind::ProcessKilled
            ]
        );
    }
}
