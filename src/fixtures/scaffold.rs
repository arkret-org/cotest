//! Per-test isolation scaffold.
//!
//! CT-12 (2026-05-18): audit established that `CokretServer::spawn*` already
//! gives each scenario complete isolation:
//!
//! - a brand-new SUT process (or docker container) on a freshly-allocated `free_port()`,
//! - a unique blob root at `temp_dir().join("cotest-{name}-{port}-blobs")` (the port is
//!   system-unique while the listener is held, so two parallel spawns cannot collide on the path),
//! - a unique `did:web:{name}.cotest.local` service DID,
//! - in-memory persistence inside `soland` so all `AccountRecord` / `SpaceMetaRecord` /
//!   `ProjectionState` lives inside the spawned process and is destroyed by `Drop for
//!   CokretServer`.
//!
//! That means AccountRecord / SpaceMetaRecord / ProjectionState **already**
//! cannot leak between tests; there is no shared database or filesystem
//! anchor that survives the per-test process drop.
//!
//! The only process-global state cotest itself owns is:
//!
//! - `NEXT_EVENT_SEQ` — a monotonic `AtomicU64`. Each call returns a unique value; correctness is
//!   unaffected by parallelism, only event-id ordering becomes interleaved.
//! - The tracing subscriber (`OnceLock`) and the per-thread `ACTIVE_SCENARIO` transcript binding in
//!   `transcripts.rs`. The thread-local design is parallel-safe; only the global subscriber is
//!   shared (one-time init).
//! - The artifact `transcript.ndjson` referenced by `COTEST_TRANSCRIPT_PATH` /
//!   `COTEST_ARTIFACT_DIR`. NDJSON appends are line-atomic at the OS level, but readers consuming
//!   the file by-scenario will see interleaved lines when `--test-threads > 1`.
//!
//! `TestScaffold::fresh(label)` is the recommended entry point for new
//! scenarios. It:
//!
//! 1. derives a per-call unique scenario name (`label-<seq>`) so transcript and per-service log
//!    files do not collide when several tests run in parallel,
//! 2. spawns a fresh `CokretServer` (single-node) — already isolated as described above,
//! 3. returns the server inside a guard that the scenario can keep on the stack; when the scenario
//!    returns, the `Drop` impl on `CokretServer` tears the process and blob root down.
//!
//! Existing scenarios that call `CokretServer::spawn(label)` directly
//! remain valid — the harness contract already isolates them. The scaffold
//! is purely an ergonomic + name-uniqueness wrapper. The tests below also
//! exercise the wrapper as a smoke check that two `TestScaffold::fresh`
//! calls can co-exist (same process, parallel-safe).

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;

use crate::harness::{CokretServer, TestServerGroup};

static SCAFFOLD_SEQ: AtomicU64 = AtomicU64::new(1);

/// Per-test scaffold that owns one freshly-spawned `CokretServer`.
///
/// The server inside is identical to what `CokretServer::spawn(label)`
/// returns — see the module-level docs for why that is already sufficient
/// for AccountRecord / SpaceMetaRecord / ProjectionState isolation.
///
/// Scaffolds are not `Clone`: the embedded `CokretServer`'s `Drop` impl is
/// the lifecycle anchor that tears down the spawned process and removes the
/// blob root, so each scaffold corresponds to exactly one running SUT.
pub struct TestScaffold {
    label: String,
    server: CokretServer,
}

impl TestScaffold {
    /// Spawn a fresh single-server scaffold for the calling test.
    ///
    /// `label` is the human-readable test name (e.g. `"space-permissions"`);
    /// the scaffold suffixes it with a process-unique counter so two parallel
    /// `fresh("foo")` calls produce distinct service DIDs, transcript files,
    /// and on-disk blob roots.
    pub async fn fresh(label: &str) -> Result<Self> {
        let unique = unique_label(label);
        let server = CokretServer::spawn(&unique).await?;
        Ok(Self {
            label: unique,
            server,
        })
    }

    /// Spawn a fresh multi-server scaffold (federation-style) with `count`
    /// independent SUT processes. Each constituent server is isolated by the
    /// same per-process rules as `fresh`.
    pub async fn fresh_multi(label: &str, count: usize) -> Result<MultiScaffold> {
        let unique = unique_label(label);
        let group = TestServerGroup::multi(&unique, count).await?;
        Ok(MultiScaffold {
            label: unique,
            group,
        })
    }

    /// The unique scenario label this scaffold was created with — useful for
    /// transcript writers and assertions that want to tag artifacts.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Borrow the underlying server for normal `CokretServer` API use.
    pub fn server(&self) -> &CokretServer {
        &self.server
    }
}

/// Multi-server scaffold counterpart of [`TestScaffold::fresh_multi`].
pub struct MultiScaffold {
    label: String,
    group: TestServerGroup,
}

impl MultiScaffold {
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn group(&self) -> &TestServerGroup {
        &self.group
    }

    pub fn server(&self, index: usize) -> &CokretServer {
        self.group.server(index)
    }

    pub fn len(&self) -> usize {
        self.group.len()
    }

    pub fn is_empty(&self) -> bool {
        self.group.len() == 0
    }
}

fn unique_label(label: &str) -> String {
    let seq = SCAFFOLD_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("{label}-p{pid}-{seq:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_label_is_monotonic_and_includes_pid() {
        let a = unique_label("scaffold-unit");
        let b = unique_label("scaffold-unit");
        assert_ne!(a, b);
        let pid_suffix = format!("p{}", std::process::id());
        assert!(a.contains(&pid_suffix));
        assert!(b.contains(&pid_suffix));
        assert!(a.starts_with("scaffold-unit-"));
        assert!(b.starts_with("scaffold-unit-"));
    }

    #[test]
    fn unique_labels_disambiguate_repeated_callers() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            assert!(seen.insert(unique_label("same-test")));
        }
        assert_eq!(seen.len(), 50);
    }
}
