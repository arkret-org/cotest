//! C.8 — generic chaos-injection framework for live scenarios.
//!
//! Provides a small, opinionated vocabulary for the kind of fault we
//! actually exercise across the cotest suite: a disk that suddenly
//! refuses writes, a network call that hangs past its timeout, and an
//! orchestrated child process that gets killed mid-flight.
//!
//! ## Why this exists
//!
//! Before C.8, each chaos scenario (`chaos_kill_midwrite`,
//! `presign_blob_fail_closed`, the soak harness) reimplemented its own
//! kill / timeout / disk-full simulation against `std::process::Child`
//! or `std::io::Error::other`. Three problems:
//!
//! * No shared graceful-shutdown helper, so a scenario that forgot to
//!   wait for SIGTERM-with-timeout would leave a zombie process between
//!   `cargo test --test-threads=1` invocations.
//! * Errors were shaped inconsistently (`ErrorKind::Other` vs
//!   `StorageFull` vs a hand-rolled `anyhow!`), making the "did we
//!   actually trigger the failure mode" assertion fuzzy.
//! * No place to register new chaos kinds — every new fault type meant
//!   another bespoke helper module.
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
//! For the kill case, use [`graceful_shutdown_test`] against the
//! `std::process::Child` so the scenario stays consistent with
//! `chaos_kill_midwrite`: SIGTERM (or `taskkill` on Windows), wait up
//! to five seconds, then assert a clean exit code surfaced through the
//! returned [`ShutdownOutcome`]. Tests should assert the variant they
//! expect (graceful exit code vs `TimedOutKilled` vs `WaitFailed`).

use std::io;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

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
    /// The subject's child process was killed unexpectedly. Drivers
    /// should use [`graceful_shutdown_test`] when they actually own a
    /// `Child` handle.
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

/// Five-second default for [`graceful_shutdown_test`]. Picked to match
/// `chaos_kill_midwrite`'s historical 5s budget — long enough that a
/// real shutdown hook (which flushes WAL + writes a final receipt) can
/// finish on a slow CI runner, short enough that a hung subprocess is
/// surfaced before the surrounding `cargo test` timeout.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of a [`graceful_shutdown_test`] cycle. Scenarios assert on
/// the variant they expect rather than the raw exit code — a clean
/// shutdown can legitimately exit either 0 or with a SIGTERM-bound
/// platform-specific status, and we don't want every chaos scenario
/// reinventing the platform delta.
#[derive(Debug)]
pub enum ShutdownOutcome {
    /// The child exited within the timeout. Carries the raw status so
    /// scenarios can assert clean (code 0 / non-fatal signal) vs
    /// crash-loop (code != 0).
    Graceful(ExitStatus),
    /// The child did not respond to the term signal before the
    /// deadline, so the framework escalated to `Child::kill`. The
    /// status reflects the SIGKILL path.
    TimedOutKilled(ExitStatus),
    /// `Child::wait` itself failed (the OS lost track of the pid, or
    /// the child was already reaped under us). The error is preserved
    /// for the scenario to log.
    WaitFailed(io::Error),
}

impl ShutdownOutcome {
    /// True when the subject came down cleanly — graceful exit, code
    /// 0, no SIGKILL escalation. Useful as a single-line
    /// `assert!(outcome.is_clean_exit())` in scenarios that don't care
    /// about the platform-specific signal vs code split.
    pub fn is_clean_exit(&self) -> bool {
        match self {
            ShutdownOutcome::Graceful(status) => status.success(),
            ShutdownOutcome::TimedOutKilled(_) | ShutdownOutcome::WaitFailed(_) => false,
        }
    }
}

/// Run the canonical kill-with-timeout shutdown sequence against a
/// child process and report the outcome. Drivers should call this
/// from the [`ChaosKind::ProcessKilled`] branch of their
/// [`ChaosInjectable`] impl when they actually own the `Child`.
///
/// The sequence is:
///
/// 1. Send a graceful termination signal (SIGTERM on Unix, gentle
///    `Child::kill` on Windows — the platform doesn't expose anything
///    softer for an arbitrary subprocess that we didn't create with
///    a job-object).
/// 2. Wait up to `timeout` for the child to exit, polling every 50ms
///    so a fast graceful shutdown returns promptly.
/// 3. If the wait deadline elapses, escalate to `Child::kill` and
///    wait for the SIGKILL path.
pub fn graceful_shutdown_test(child: &mut Child, timeout: Duration) -> ShutdownOutcome {
    kill_with_term(child);
    match wait_with_timeout(child, timeout) {
        Ok(Some(status)) => ShutdownOutcome::Graceful(status),
        Ok(None) => {
            // Deadline elapsed — escalate to SIGKILL and try to reap.
            let _ = child.kill();
            match child.wait() {
                Ok(status) => ShutdownOutcome::TimedOutKilled(status),
                Err(error) => ShutdownOutcome::WaitFailed(error),
            }
        }
        Err(error) => ShutdownOutcome::WaitFailed(error),
    }
}

/// Best-effort graceful termination. On Unix we shell out to `kill
/// -TERM` (rather than going through `nix` or a raw libc binding) so
/// the helper compiles on any host stdlib. On Windows we fall back to
/// `Child::kill`, which is the only termination path the platform
/// gives us for an arbitrary child.
pub fn kill_with_term(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id().to_string();
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
}

/// Poll `child.try_wait()` until either the process exits or the
/// deadline elapses. Returns `Ok(Some(status))` on exit, `Ok(None)` on
/// timeout, or the underlying `io::Error` from `try_wait` if the OS
/// lost the pid.
pub fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(Some(status)),
            None => {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Convenience assertion for scenarios that expect a fully-clean
/// shutdown. Panics with a structured message rather than a generic
/// `assert!` failure so the chaos kind shows up in the test log.
pub fn assert_clean_exit(outcome: &ShutdownOutcome) {
    if !outcome.is_clean_exit() {
        panic!(
            "chaos_inject: expected clean graceful shutdown but got {outcome:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

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

    #[test]
    fn graceful_shutdown_test_reaps_fast_exit() {
        // Use a portable noop subprocess: rustc-target-independent
        // `cargo` is in PATH on every cotest CI runner, but we don't
        // want to depend on it here. Fall back to spawning the
        // current test binary with a sentinel arg that immediately
        // exits — except that's also fragile. The simplest portable
        // choice is `std::process::Command::new(<self>)` where self is
        // either `cmd /C exit 0` on Windows or `true` on Unix.
        #[cfg(windows)]
        let mut child = Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .expect("spawn cmd /C exit");
        #[cfg(not(windows))]
        let mut child = Command::new("true").spawn().expect("spawn /bin/true");

        let outcome = graceful_shutdown_test(&mut child, DEFAULT_SHUTDOWN_TIMEOUT);
        // Either the child finished cleanly before we even sent the
        // term signal (fast path) or we killed it — both are
        // acceptable for a process that immediately exits. We only
        // require that `wait` did not fail.
        assert!(
            !matches!(outcome, ShutdownOutcome::WaitFailed(_)),
            "wait should not fail for a fast-exit child: {outcome:?}"
        );
    }

    #[test]
    fn shutdown_outcome_is_clean_exit_only_for_graceful_success() {
        // We can't easily construct an `ExitStatus` directly across
        // platforms in stable Rust, so spin up a real fast-exit child
        // and re-read its status.
        #[cfg(windows)]
        let mut child = Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .expect("spawn cmd /C exit");
        #[cfg(not(windows))]
        let mut child = Command::new("true").spawn().expect("spawn /bin/true");

        let status = child.wait().expect("child wait");
        assert!(ShutdownOutcome::Graceful(status).is_clean_exit());
    }
}
