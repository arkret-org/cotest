//! CT-17 — Upgrade testing: N-1 binary writes, upgrade to N, replay.
//!
//! Goal: prove backward-compat reducer + forward migration semantics on
//! event log replay. The implicit contract of an event-sourced system is
//! that any past event written by an older binary MUST replay cleanly
//! against the current reducer, producing a projection state that's
//! either identical to the old projection (no behavioural change) or
//! the migrated equivalent (deterministic forward migration). Any
//! "missing event kind", "schema mismatch", or "projection diverges"
//! on replay is a release-blocker bug.
//!
//! Spec:
//!   - `arkret-spec/spec/v1/zh/state/event-log.md` — event log is the source of truth; projections
//!     are derived and disposable.
//!   - `arkret-spec/spec/v1/zh/conformance/event-schemas.md` — event-kind versioning +
//!     forward-compat reducer rules.
//!   - `arkret-spec/spec/v1/zh/state/snapshot-schema.md` — when a snapshot from N-1 is restored
//!     under N, the snapshot schema must either be exactly compatible OR auto-migrate.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Scenario walk-through (when fully wired):
//!
//!   1. Resolve "previous release" of soland.
//!        - Read `../soland/Cargo.toml` for the current version.
//!        - `git -C ../soland tag --list "v*"` to get released tags.
//!        - Pick the highest tag strictly less than the current version (this is N-1). If no tag
//!          exists, the test must skip with a clear "no previous release tagged" message (the
//!          current repo state today!).
//!   2. Build the N-1 binary in an isolated target dir.
//!        - `git -C ../soland worktree add /tmp/soland-n-1 <tag>` to avoid disturbing the live
//!          tree.
//!        - `cargo build --manifest-path /tmp/soland-n-1/Cargo.toml --bin soland --release
//!          --target-dir /tmp/soland-n-1/target`.
//!        - Cache by tag hash so repeated CT-17 runs don't rebuild.
//!   3. Write fixture data with the N-1 binary against a fresh data dir.
//!        - Spawn N-1 soland, point at a tempdir DB / Pg schema.
//!        - alice creates a Realm, sends N messages, knocks/joins, uploads a blob — exercise enough
//!          event kinds that the replay matrix is non-trivial.
//!        - Capture the projection state via the public API: list of messages, member roster, blob
//!          refs.
//!   4. Cleanly shut down N-1 soland (graceful, no chaos here — this isolates the upgrade variable
//!      from the recovery variable covered by CT-16).
//!   5. Spawn current-build soland against the same data dir / DB.
//!        - On startup, soland MUST replay the log without error.
//!        - `/health` reports `ready` (not `replay_error`).
//!   6. Verify equivalence:
//!        - Re-fetch the same projection state via the public API.
//!        - For each event kind that didn't change schema between N-1 and N: projection must be
//!          byte-identical to the N-1 capture.
//!        - For each event kind that DID change schema (recorded in a migration manifest):
//!          projection must match the documented post-migration shape.
//!        - No events MAY silently disappear from the log; the log row count MUST be unchanged
//!          (migrations append, never delete).
//!   7. Bonus: write one new event under N (e.g. send another message). The new event must persist
//!      + replay cleanly on a subsequent N restart — proving the upgraded state is itself durable,
//!      not just readable.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Status: scaffolded as `#[ignore]`.
//!
//! Prerequisite blockers (the cross-version test is the most
//! infrastructure-heavy scenario in Lane D — these are real, not
//! aspirational):
//!
//!   * **No tagged releases.** `git -C ../soland tag --list` returns empty today. Without at least
//!     one `v*` tag, "N-1" is undefined and the test can't even pick a baseline. Either:
//!       - the soland project starts tagging cuts (semver discipline), OR
//!       - the test is parameterised by an arbitrary commit hash via env
//!         (`COTEST_UPGRADE_BASE_REV=<sha>`), trading "release compat" for "any-two-commits
//!         compat".
//!   * **No cross-version build helper in the cotest harness.** Today `ArkretServer::spawn` builds
//!     the live tree's binary on demand (via `cargo run` under the hood) and doesn't know how to
//!     build a different revision. Need a `BuildSpec { rev, target_dir, features }` helper that:
//!       1. Creates / reuses a `git worktree` under `cotest/.cache/` for the requested rev.
//!       2. Runs `cargo build --release` with a per-rev `--target-dir`.
//!       3. Returns the path to the built binary.
//!     This is ~150 LOC of new harness code; not zero, but bounded.
//!   * **No schema-migration manifest.** Today there is no machine-readable list of "event kind X
//!     changed shape between v0.4.0 and v0.5.0; here's the migrator". Without one, step 6 can only
//!     do a strict byte-equality check, which makes the test fail every time any reducer touches
//!     the projection shape — defeating the point. A `arkret-spec/state/migrations/*.json` manifest
//!     (or a Rust `inventory!`-style registry) would close this.
//!   * **Per-rev data dir / DB schema isolation.** The N-1 binary and the N binary MUST share the
//!     same on-disk state, but two concurrent CT-17 invocations MUST NOT share. Need a `Pg
//!     schema-per-test` or a unique tempdir hand-off, with the N-1 process's lock file released
//!     before the N process starts.
//!   * **N-1 binary network compatibility.** If the test driver uses the current SDK's HTTP client
//!     against the N-1 server, any wire-protocol change between versions will surface as "test
//!     can't even talk to the old server". Mitigation: drive the fixture step via raw HTTP + JSON,
//!     not the SDK; the SDK can come back for the post-upgrade verification step.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Future implementer's checklist (drop the `#[ignore]` once these land):
//!   1. Tag a soland release (any `v*` tag — even `v0.0.1-baseline` satisfies the test, though
//!      semantically meaningful tags are preferred).
//!   2. Add `cotest::scenarios::_helpers::cross_version_build` with worktree management + caching.
//!   3. Add a migration manifest schema + at least an empty manifest under
//!      `arkret-spec/state/migrations/`.
//!   4. Add `spawn_with_postgres` to the harness (shared with CT-16).
//!   5. Replace each `unimplemented!("step N: …")` below with the real call.
//!
//! Track: `_claude_todos.md` row CT-17.

use anyhow::Result;

/// CT-17 scenario probe. See module docs for the full prerequisites.
///
/// The test exercises a real "N-1 → N → replay" pipeline. Until the
/// blocker list above is closed, this scaffold returns immediately so
/// the `#[ignore]`'d test surfaces in `cargo test --list` output without
/// false-positive passes.
pub async fn upgrade_n_minus_one_replay_run() -> Result<()> {
    // Sketch (do not "fix" by deleting the unimplemented! calls — they
    // are the design):
    //
    //   // Step 1: resolve previous release tag
    //   let previous_tag = resolve_previous_release_tag("../soland")?
    //       .ok_or_else(|| anyhow!("no previous release tag — CT-17 \
    //                                requires at least one v* tag"))?;
    //
    //   // Step 2: build the N-1 binary
    //   let n_minus_one = build_at_rev(BuildSpec {
    //       repo: PathBuf::from("../soland"),
    //       rev: previous_tag.clone(),
    //       target_dir: cotest_cache_dir().join(&previous_tag).join("target"),
    //       bin: "soland",
    //       features: &[],
    //   }).await?;
    //
    //   // Step 3: write fixture data under N-1
    //   let data_dir = tempfile::tempdir()?;
    //   let pg_schema = format!("ct17_{}", short_hash(&previous_tag));
    //   provision_pg_schema(&pg_schema).await?;
    //
    //   let server_old = ArkretServer::spawn_explicit_binary(
    //       n_minus_one,
    //       data_dir.path(),
    //       &[("DATABASE_URL", &pg_url_for(&pg_schema))],
    //   ).await?;
    //   let alice = register_account(&server_old, "did:web:alice.example",
    //                                "@alice",
    // "ak:device:01904100-0000-7000-8000-0000000000a1").await?;   let realm_id =
    // create_realm(&server_old, &alice, "Upgrade Realm").await?;   let mut sent = Vec::new();
    //   for i in 0..16 {
    //       sent.push(send_message(&server_old, &alice, &realm_id,
    //                              &format!("hello {i}")).await?);
    //   }
    //   let baseline = capture_projection(&server_old, &alice, &realm_id).await?;
    //
    //   // Step 4: graceful shutdown
    //   server_old.graceful_stop().await?;
    //
    //   // Step 5: spawn current-build soland against the SAME data dir / DB
    //   let server_new = ArkretServer::spawn_with_postgres_existing(
    //       "ct17-upgraded", data_dir.path(),
    //       &pg_url_for(&pg_schema),
    //   ).await?;
    //   assert_eq!(server_new.health().await?["status"], "ready");
    //   assert!(server_new.health().await?["replay_error"].is_null());
    //
    //   // Step 6: equivalence
    //   let upgraded = capture_projection(&server_new, &alice, &realm_id).await?;
    //   let migrations = load_migration_manifest()?;
    //   assert_projections_equivalent(&baseline, &upgraded, &migrations)?;
    //
    //   // Step 7: write a new event under N, restart, prove it replays
    //   let new_msg = send_message(&server_new, &alice, &realm_id,
    //                              "post-upgrade ping").await?;
    //   server_new.graceful_stop().await?;
    //   let server_new2 = ArkretServer::spawn_with_postgres_existing(
    //       "ct17-upgraded-restart", data_dir.path(),
    //       &pg_url_for(&pg_schema),
    //   ).await?;
    //   let messages = list_messages(&server_new2, &alice, &realm_id).await?;
    //   assert!(messages.iter().any(|m| m["event_id"] == new_msg["event_id"]));

    let _ = step_1_resolve_previous_tag;
    let _ = step_2_build_n_minus_one;
    let _ = step_3_write_fixture_with_old_binary;
    let _ = step_5_spawn_new_binary_same_dir;
    let _ = step_6_assert_projections_equivalent;
    let _ = step_7_write_and_restart_under_n;

    unimplemented!(
        "CT-17 upgrade N-1 → N replay — blocked on tagged soland releases, \
         cross-version build helper in cotest harness, schema-migration \
         manifest, and shared persistent-storage harness hook (see module \
         docs + _claude_todos.md CT-17)."
    )
}

fn step_1_resolve_previous_tag() -> ! {
    unimplemented!(
        "step 1: resolve the previous release tag by reading \
         ../soland/Cargo.toml version + `git tag --list v*`; pick highest \
         tag strictly less than current version. If empty, return a clear \
         skip — not a panic — so CI surfaces \"no baseline\" distinct from \
         \"upgrade failed\""
    )
}

fn step_2_build_n_minus_one() -> ! {
    unimplemented!(
        "step 2: git worktree add the tag into cotest/.cache/<tag>/, then \
         `cargo build --bin soland --release --target-dir cotest/.cache/\
         <tag>/target`. Cache by tag so repeated runs reuse the build"
    )
}

fn step_3_write_fixture_with_old_binary() -> ! {
    unimplemented!(
        "step 3: spawn the N-1 binary against a fresh per-test Pg schema, \
         register an actor + Realm, send a representative slice of event \
         kinds (messages / membership / blob refs), capture the projection \
         state via the public read API"
    )
}

fn step_5_spawn_new_binary_same_dir() -> ! {
    unimplemented!(
        "step 5: spawn the current-tree soland against the SAME data dir / \
         Pg schema. Verify /health reports `ready` and no `replay_error` \
         before any read"
    )
}

fn step_6_assert_projections_equivalent() -> ! {
    unimplemented!(
        "step 6: re-capture the projection under N, load the migration \
         manifest, and compare. Unchanged event kinds → byte-equality. \
         Migrated kinds → match the documented post-migration shape. The \
         log row count MUST be unchanged (migrations append, never delete)"
    )
}

fn step_7_write_and_restart_under_n() -> ! {
    unimplemented!(
        "step 7: send one new event under N, restart N (still same data \
         dir), assert the new event replays. This guards against the \
         upgrade succeeding for reads but corrupting future writes"
    )
}
