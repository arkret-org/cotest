//! CT-16 — Chaos: kill server mid-write, restart, verify recovery.
//!
//! Goal: prove that the soland event log + projection store give either
//! (a) full commit (event visible in the projection AND in the durable log
//! AND addressable by its `operation_id`) OR (b) clean reject (no row in
//! the projection, no row in the log, client may safely retry). Anything
//! in between — log row but no projection, projection update but no log
//! row, phantom `operation_id` that the server doesn't recognise on
//! retry — is a bug.
//!
//! Spec: `contrix-spec/spec/v1/zh/conformance/idempotency-keys.md` (the
//! `Idempotency-Key` / `operation_id` contract is what makes "either
//! committed or rejected, no third state" testable); `contrix-spec/spec/v1/zh/
//! state/event-log.md` §append-atomicity.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Scenario walk-through (when fully wired):
//!
//!   1. Spawn soland with **persistent** storage backend.
//!        - Postgres backend preferred (`DATABASE_URL=postgres://...`),
//!          because it gives us a real WAL boundary to crash against.
//!        - Or persistent-file backend if/when soland grows one
//!          (currently `persistence.rs` is in-memory by default and Pg
//!          when `DATABASE_URL` is set — there is no "file" mode today).
//!   2. Register an actor + a space (these are setup; they MUST succeed
//!      cleanly before the chaos step).
//!   3. Pick a deterministic `operation_id` (e.g.
//!      `chaos-midwrite-{uuid}`). Submit
//!      `POST /api/v1/events` for a `cx.message.send` (or any committing
//!      kind) with that `Idempotency-Key`.
//!   4. Mid-flight: between the moment the server has parsed + reduced
//!      the event and the moment the client receives 200, send `SIGKILL`
//!      to the soland process. On Windows this is
//!      `child.kill()` (equivalent to `TerminateProcess`, no graceful
//!      shutdown). The exact landing point matters:
//!        - if the kill lands before the WAL flush: client gets a
//!          connection-reset error, server has no log row → on restart,
//!          retry with same `operation_id` MUST succeed (no phantom);
//!        - if the kill lands after the WAL flush but before the HTTP
//!          response flush: client gets a connection-reset error, server
//!          has a committed log row → on restart, retry with same
//!          `operation_id` MUST return the same committed result
//!          (idempotency replay), and a query for the message MUST find
//!          it;
//!        - anything else is a bug.
//!   5. Restart soland against the same data dir / database.
//!   6. Two probes:
//!        (a) `GET /api/v1/messages?space_id=...&operation_id=...` (or
//!            equivalent log scan) — assert the message either fully
//!            exists OR fully doesn't.
//!        (b) Retry the original POST with the same `operation_id`. If
//!            the first call had committed, this MUST return the same
//!            envelope (replay). If the first call had not committed,
//!            this MUST commit fresh.
//!        Together (a) + (b) catch any partial / phantom state.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Status: scaffolded as `#[ignore]`.
//!
//! Prerequisite blockers (these are what stops the test from running
//! today; each is a concrete piece of soland work):
//!
//!   * **Default-on persistent storage hook in the cotest harness.** Today
//!     `ContrixServer::spawn` doesn't plumb `DATABASE_URL` through to the
//!     child — every test runs in-memory. The chaos test is meaningless
//!     against an in-memory store (restart = clean slate = no recovery to
//!     verify). Need either:
//!       - a harness helper `spawn_with_postgres(test_db_url)` that
//!         provisions an isolated schema per test and tears it down on
//!         drop, OR
//!       - persistent-file mode in soland (not present today), which
//!         would be much cheaper for CI but requires fsync semantics on
//!         the file format.
//!   * **`SOLAND_TEST_CHAOS_DELAY_MS=N` env hook.** The narrow window
//!     between "WAL fsync" and "HTTP response flush" is microseconds
//!     wide on a healthy box; reliably killing in that window from the
//!     outside is racy. Soland needs a test-only env that injects an
//!     N-millisecond sleep at a chosen breakpoint (e.g. right before
//!     `Response::send`, optionally also right before the WAL flush so
//!     we can test the pre-flush race). The current soland codebase
//!     has **no** such hook — `rg "SOLAND_TEST_CHAOS"` is empty.
//!   * **Direct log-after-restart inspector.** Asserting "log either has
//!     this op_id or doesn't" needs a way to ask the log directly, not
//!     via the public POST/GET surface (which would conflate "server
//!     accepted" with "server saw"). Either:
//!       - an admin diagnostic endpoint `GET /api/v1/_internal/log?op_id=...`
//!         (test-mode only, gated by `SOLAND_DIAGNOSTIC_TOKEN`), OR
//!       - direct Pg query helper in the harness that hits the log
//!         table (acceptable but couples the test to Pg schema).
//!   * **Reliable kill-mid-write hook in the harness.** `Child::kill` on
//!     Windows is `TerminateProcess` (no graceful shutdown — that's what
//!     we want for chaos), on Unix it's `SIGKILL`. The harness needs a
//!     `ContrixServer::kill_immediately()` that returns once the OS has
//!     reaped the process, so the restart step is race-free.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Future implementer's checklist (drop the `#[ignore]` once these land):
//!   1. Add `spawn_with_postgres` to `cotest/src/harness.rs`.
//!   2. Add `SOLAND_TEST_CHAOS_DELAY_MS` + breakpoint enum to soland (e.g.
//!      `Pre-WAL` / `Post-WAL-Pre-Response`).
//!   3. Add the diagnostic log query endpoint to soland, gated behind
//!      `SOLAND_DEVELOPMENT_MODE=true` + token.
//!   4. Wire `ContrixServer::kill_immediately()`.
//!   5. Replace each `unimplemented!("step N: …")` below with the real
//!      call.
//!
//! Track: `_claude_todos.md` row CT-16. The blocker list above is the
//! "blocked on [X]" set.

use anyhow::Result;

/// CT-16 scenario probe. See module docs for the full prerequisites.
///
/// This function is intentionally not callable until each phase below is
/// wired. Each `unimplemented!("step N: …")` documents the contract the
/// real implementation must satisfy.
pub async fn chaos_kill_midwrite_run() -> Result<()> {
    // Sketch (do not "fix" by deleting the unimplemented! calls — they
    // are the design):
    //
    //   // Step 1: persistent storage soland
    //   let server = ContrixServer::spawn_with_postgres(
    //       "chaos-midwrite",
    //       &[("SOLAND_TEST_CHAOS_DELAY_MS", "500"),
    //         ("SOLAND_TEST_CHAOS_BREAKPOINT", "post_wal_pre_response")],
    //   ).await?;
    //
    //   // Step 2: actor + space setup
    //   let alice = register_account(&server, "did:web:alice.example",
    //                                "@alice", "dev_alice").await?;
    //   let space_id = create_space(&server, &alice, "Chaos Space").await?;
    //
    //   // Step 3: dispatch the doomed POST (don't await; spawn it)
    //   let op_id = format!("chaos-midwrite-{}", Uuid::new_v4());
    //   let post_fut = tokio::spawn({
    //       let server = server.clone();
    //       let alice = alice.clone();
    //       let op_id = op_id.clone();
    //       async move {
    //           submit_event_with_op_id(
    //               &server, &alice, &space_id,
    //               "cx.message.send",
    //               json!({"text": "doomed"}),
    //               &op_id,
    //           ).await
    //       }
    //   });
    //
    //   // Step 4: wait for the breakpoint sleep to start, then SIGKILL
    //   tokio::time::sleep(Duration::from_millis(200)).await;
    //   server.kill_immediately().await?;
    //   let post_result = post_fut.await; // expected: connection reset
    //   assert!(post_result.is_err(),
    //           "POST should have failed mid-flight, got {:?}", post_result);
    //
    //   // Step 5: restart
    //   let server = ContrixServer::spawn_with_postgres_existing(
    //       "chaos-midwrite", server.data_dir(),
    //   ).await?;
    //
    //   // Step 6a: log inspector
    //   let log_row = server.diagnostic_log_query(&op_id).await?;
    //
    //   // Step 6b: retry with same op_id
    //   let retry = submit_event_with_op_id(
    //       &server, &alice, &space_id,
    //       "cx.message.send",
    //       json!({"text": "doomed"}),
    //       &op_id,
    //   ).await?;
    //
    //   // Assert the two states are consistent.
    //   match log_row {
    //       Some(committed) => {
    //           // Pre-restart commit + post-restart replay must agree.
    //           assert_eq!(retry["event_id"], committed["event_id"]);
    //           assert!(retry["replay"].as_bool() == Some(true) ||
    //                   retry["status"] == "duplicate");
    //           // Projection must visibly contain the message.
    //           let messages = list_messages(&server, &alice, &space_id).await?;
    //           assert!(messages.iter().any(|m| m["operation_id"] == op_id),
    //                   "committed message missing from projection");
    //       }
    //       None => {
    //           // Pre-restart did NOT commit; retry should succeed fresh.
    //           assert_eq!(retry["status"], "ok");
    //           assert!(retry.get("replay").is_none(),
    //                   "retry of uncommitted op should not be marked replay");
    //       }
    //   }

    let _ = step_1_spawn_persistent_soland;
    let _ = step_3_dispatch_doomed_post;
    let _ = step_4_kill_mid_flight;
    let _ = step_5_restart;
    let _ = step_6_assert_consistency;

    unimplemented!(
        "CT-16 chaos kill-mid-write — blocked on persistent-storage harness \
         hook, SOLAND_TEST_CHAOS_DELAY_MS breakpoint, diagnostic log query \
         endpoint, and ContrixServer::kill_immediately (see module docs + \
         _claude_todos.md CT-16)."
    )
}

// The fn pointers below exist solely to make the design visible to grep
// and to keep each phase as a named anchor in the future implementor's
// IDE. They are never called; each one panics with the phase contract.

fn step_1_spawn_persistent_soland() -> ! {
    unimplemented!(
        "step 1: spawn soland with a persistent backend (Postgres preferred) \
         and the SOLAND_TEST_CHAOS_DELAY_MS / SOLAND_TEST_CHAOS_BREAKPOINT \
         env vars set; data_dir / database name MUST be reusable across \
         restarts in step 5"
    )
}

fn step_3_dispatch_doomed_post() -> ! {
    unimplemented!(
        "step 3: POST /api/v1/events with a deterministic Idempotency-Key / \
         operation_id; do NOT await — spawn the future so step 4 can kill \
         the server while the POST is still mid-flight"
    )
}

fn step_4_kill_mid_flight() -> ! {
    unimplemented!(
        "step 4: wait for the chaos-delay window to open, then SIGKILL the \
         soland child (Child::kill on Windows, kill(SIGKILL) on Unix). The \
         POST future MUST resolve to a transport-level error (connection \
         reset / broken pipe), not a 5xx — a 5xx would mean the response \
         did flush and there's no race to test"
    )
}

fn step_5_restart() -> ! {
    unimplemented!(
        "step 5: re-spawn soland against the same data dir / database. \
         Verify the log replay finished (e.g. /health reports `ready` not \
         `replaying`) before issuing the next request"
    )
}

fn step_6_assert_consistency() -> ! {
    unimplemented!(
        "step 6: query the log directly for the operation_id, then retry \
         the POST. Assert exactly one of two consistent outcomes: \
         (a) log has it + retry returns replay envelope + projection \
         contains it, or (b) log doesn't have it + retry commits fresh + \
         projection now contains it. Any other combination is a bug; the \
         test must fail with a clear message naming which invariant broke"
    )
}
