//! CT-18 — Soak: 100 actors × 10k messages.
//!
//! Goal: surface memory leaks, projection-index fragmentation, and query
//! slowdown that only appear under volume. Unit-test scale traffic
//! (~10 events / scenario) cannot catch these; nor can the existing
//! conformance fixtures, which are designed for byte-equivalence not
//! throughput. CT-18 is the only Lane D scenario that intentionally
//! generates 1M+ events.
//!
//! Spec: there is no dedicated soak-test spec; the relevant invariants
//! are operational, not protocol:
//!   - heap growth MUST be sub-linear in event count once the steady state is reached (a small
//!     per-actor and per-space working set is expected, but a linear-in-N leak is a bug);
//!   - p50 / p95 read latency for `GET /api/v1/messages?space_id=...` MUST stay within a constant
//!     factor of the empty-store latency as the log grows (index-backed read, not full scan);
//!   - anchor-store row growth MUST be linear in event count (no pathological write amplification),
//!     but the rate MUST be stable (no super-linear gc-then-rebuild storms).
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Scenario walk-through (when fully wired):
//!
//!   1. Spawn soland with persistent storage (Postgres preferred, for index analysis). Set
//!      `SOLAND_PROFILING=1` if/when soland grows that hook, otherwise rely on external
//!      `/proc/.../status` or `wmic process get` polling.
//!   2. Setup phase (not counted toward soak timing):
//!        - Register 100 actors (`@soak0` … `@soak99`).
//!        - alice creates a "soak" space, invites all 100.
//!        - All 100 accept; membership steady state reached.
//!   3. Soak phase:
//!        - 100 concurrent worker tasks (tokio task per actor).
//!        - Each task sends 10k messages over a compressed timeline (e.g. one message per 10 ms per
//!          actor = 100 s total wall time at full throttle, simulating a peak-hour conversation).
//!        - Total: 1,000,000 events.
//!   4. Sampling (concurrent with step 3, runs at 1 Hz):
//!        - Heap: read `RSS` from `/proc/<pid>/status` on Linux, `wmic process where
//!          ProcessId=<pid> get WorkingSetSize` on Windows, `task_info` via libproc on macOS.
//!        - Latency: every 5 s, fire 10 `GET /api/v1/messages?space_id= <space>&limit=50` requests,
//!          record p50 / p95.
//!        - Anchor store: every 30 s, query `SELECT count(*) FROM anchor_store` (or equivalent).
//!   5. Steady-state window: drop the first 10% of samples (warm-up) and the last 10% (drain). On
//!      the middle 80%:
//!        - heap RSS slope (linear regression) MUST satisfy `slope_bytes_per_event < THRESHOLD`
//!          (e.g. 64 bytes/event, tunable);
//!        - p50 latency slope MUST be near-zero (allow 10% drift);
//!        - p95 latency slope MUST satisfy `slope_ms_per_kevents < THRESHOLD_P95` (e.g. 0.5
//!          ms/k-events);
//!        - anchor-store growth MUST be ≈1 row/event ±5%.
//!   6. Cooldown: drain the worker queue, send 100 final reads, assert they all return without
//!      error and within 2× the steady-state p95.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Status: scaffolded as `#[ignore]`. Opt-in only via `--profile soak`
//! (see `cotest/config/ci-profiles.json` — adding this scenario adds a
//! new profile entry, NOT a default-on test). This is by design:
//! 100s-of-seconds wall-time tests do not belong on every PR.
//!
//! Prerequisite blockers:
//!
//!   * **Persistent storage harness hook.** Same blocker as CT-16 and CT-17: `ContrixServer::spawn`
//!     doesn't plumb `DATABASE_URL` today. Without persistence, the soak data evaporates between
//!     samples and the test measures only the in-memory hashmap, which has fundamentally different
//!     scaling behaviour than the Pg-backed production path.
//!   * **Per-process memory introspection.** Cross-platform RSS reading is fiddly (Linux `/proc`,
//!     Windows WMIC / PERF_NT, macOS `task_info`). Options: (a) inline platform-specific code in
//!     the test (~80 LOC + cfg gates), (b) depend on a crate like `sysinfo` or `memory-stats`, (c)
//!     require soland to expose a `/metrics` endpoint with `process_resident_memory_bytes`
//!     (Prometheus convention) and just scrape it. Option (c) is cleanest but adds a soland
//!     feature; (b) is the pragmatic default for the harness.
//!   * **Latency probe instrumentation.** The test needs reliable timing for the latency probe
//!     (warmup, percentile reservoir, no-allocation hot path). The `hdrhistogram` crate is the
//!     standard choice; not yet a cotest dep.
//!   * **Anchor-store row-count diagnostic.** Need either an admin endpoint that returns it, or a
//!     Pg query helper (acceptable but couples test to Pg schema, same caveat as CT-16).
//!   * **CI capacity.** A 100 s wall-clock test that runs ~100k events / sec needs an isolated
//!     runner — not your shared GitHub Actions micro-VM. Either:
//!       - dedicated self-hosted runner with the `soak` label,
//!       - nightly cron job rather than per-PR,
//!       - or local-only with an explicit `cargo test -- --ignored soak_100x10k`.
//!     This test SHOULD NOT run on every push.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! `--profile soak` is wired into `cotest/scripts/run-cotest.ps1` and
//! the cargo filter is the test fn name below
//! (`soak_100_actors_10k_messages`). Future implementer's checklist:
//!   1. Add `spawn_with_postgres` to the harness (shared with CT-16 / CT-17).
//!   2. Pick a memory-probe strategy (sysinfo crate is the lowest-cost path).
//!   3. Add `hdrhistogram = "7.5"` to cotest dev-dependencies.
//!   4. Add an anchor-store row-count probe (admin endpoint or Pg query helper).
//!   5. Replace each `unimplemented!("step N: …")` below with the real call.
//!   6. Tune the four THRESHOLD_* constants (heap slope, p50 slope, p95 slope, anchor growth) once
//!      you have a clean reference run.
//!
//! Track: `_claude_todos.md` row CT-18.

use anyhow::Result;

/// CT-18 scenario probe. See module docs for the full prerequisites.
///
/// Run only via the `soak` profile:
///
///   ./scripts/run-cotest.ps1 -Profile soak
///   # or directly:
///   cargo test --test soak_test -- --ignored
pub async fn soak_100x10k_run() -> Result<()> {
    // Sketch (do not "fix" by deleting the unimplemented! calls — they
    // are the design):
    //
    //   const N_ACTORS: usize = 100;
    //   const N_MESSAGES_PER_ACTOR: usize = 10_000;
    //   const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
    //   const LATENCY_PROBE_INTERVAL: Duration = Duration::from_secs(5);
    //   const ANCHOR_PROBE_INTERVAL: Duration = Duration::from_secs(30);
    //
    //   // Step 1: persistent soland
    //   let server = ContrixServer::spawn_with_postgres("soak").await?;
    //
    //   // Step 2: setup actors + shared space
    //   let alice = register_account(&server, "did:web:alice.example",
    //                                "@alice", "dev_alice").await?;
    //   let space_id = create_space(&server, &alice, "Soak Space").await?;
    //   let mut actors = Vec::with_capacity(N_ACTORS);
    //   for i in 0..N_ACTORS {
    //       let did = format!("did:web:soak{i}.example");
    //       let a = register_account(&server, &did, &format!("@soak{i}"),
    //                                &format!("dev_soak{i}")).await?;
    //       invite_and_join(&server, &alice, &a, &space_id).await?;
    //       actors.push(a);
    //   }
    //
    //   // Step 4 (started early, runs concurrent with step 3): samplers
    //   let stop = CancellationToken::new();
    //   let heap_samples = Arc::new(Mutex::new(Vec::<HeapSample>::new()));
    //   let latency_samples = Arc::new(Mutex::new(Hdr::new(3).unwrap()));
    //   let anchor_samples = Arc::new(Mutex::new(Vec::<AnchorSample>::new()));
    //
    //   let heap_task = spawn_heap_sampler(server.pid(),
    //                                      SAMPLE_INTERVAL,
    //                                      stop.clone(),
    //                                      heap_samples.clone());
    //   let latency_task = spawn_latency_probe(&server, &alice, &space_id,
    //                                          LATENCY_PROBE_INTERVAL,
    //                                          stop.clone(),
    //                                          latency_samples.clone());
    //   let anchor_task = spawn_anchor_probe(&server,
    //                                        ANCHOR_PROBE_INTERVAL,
    //                                        stop.clone(),
    //                                        anchor_samples.clone());
    //
    //   // Step 3: 100 concurrent senders
    //   let mut senders = JoinSet::new();
    //   for actor in &actors {
    //       let actor = actor.clone();
    //       let server = server.clone();
    //       let space_id = space_id.clone();
    //       senders.spawn(async move {
    //           for j in 0..N_MESSAGES_PER_ACTOR {
    //               send_message(&server, &actor, &space_id,
    //                            &format!("soak {j}")).await?;
    //               tokio::time::sleep(Duration::from_millis(10)).await;
    //           }
    //           Result::<_, anyhow::Error>::Ok(())
    //       });
    //   }
    //   while let Some(res) = senders.join_next().await {
    //       res??;
    //   }
    //
    //   // Step 6: cooldown drain
    //   stop.cancel();
    //   heap_task.await??;
    //   latency_task.await??;
    //   anchor_task.await??;
    //
    //   for actor in &actors {
    //       list_messages(&server, actor, &space_id).await?;
    //   }
    //
    //   // Step 5: steady-state assertions on middle 80%
    //   let heap = trim_middle_80(&heap_samples.lock().unwrap());
    //   let heap_slope = linear_regression_slope(&heap);
    //   assert!(heap_slope.bytes_per_event < THRESHOLD_HEAP_BYTES_PER_EVENT,
    //           "heap leak suspected: {} bytes/event > {}",
    //           heap_slope.bytes_per_event,
    //           THRESHOLD_HEAP_BYTES_PER_EVENT);
    //
    //   let p50 = latency_samples.lock().unwrap().value_at_quantile(0.50);
    //   let p95 = latency_samples.lock().unwrap().value_at_quantile(0.95);
    //   assert!(p95 < THRESHOLD_READ_P95_MS,
    //           "read p95 {}ms > {}ms — projection index regressed?",
    //           p95, THRESHOLD_READ_P95_MS);
    //
    //   let anchor_growth_per_event = anchor_growth_rate(
    //       &anchor_samples.lock().unwrap(),
    //   );
    //   assert!((anchor_growth_per_event - 1.0).abs() < 0.05,
    //           "anchor-store growth {anchor_growth_per_event} rows/event \
    //            outside ±5% of expected 1.0");

    let _ = step_1_spawn_persistent_soland;
    let _ = step_2_setup_actors_and_space;
    let _ = step_3_run_concurrent_senders;
    let _ = step_4_run_samplers;
    let _ = step_5_assert_steady_state;
    let _ = step_6_cooldown_drain;

    unimplemented!(
        "CT-18 soak 100 actors × 10k messages — blocked on persistent- \
         storage harness hook, per-process memory introspection, \
         hdrhistogram dependency, anchor-store row-count probe, and \
         dedicated CI capacity (see module docs + _claude_todos.md CT-18)."
    )
}

fn step_1_spawn_persistent_soland() -> ! {
    unimplemented!(
        "step 1: spawn soland with a persistent backend (Postgres \
         preferred for realistic index behaviour). Capture pid() for the \
         heap sampler"
    )
}

fn step_2_setup_actors_and_space() -> ! {
    unimplemented!(
        "step 2: register 100 actors, create one shared space, invite + \
         join all 100. This setup phase is NOT counted toward soak metrics"
    )
}

fn step_3_run_concurrent_senders() -> ! {
    unimplemented!(
        "step 3: spawn one tokio task per actor; each sends 10k messages \
         pacing one per 10 ms. Total 1M events across ~100 s wall time"
    )
}

fn step_4_run_samplers() -> ! {
    unimplemented!(
        "step 4: concurrent samplers for RSS (1 Hz), read latency (every \
         5 s × 10 probe requests into an hdrhistogram), and anchor-store \
         row count (every 30 s)"
    )
}

fn step_5_assert_steady_state() -> ! {
    unimplemented!(
        "step 5: trim warm-up + drain (first 10% / last 10% of samples); \
         on the middle 80% assert heap slope < THRESHOLD bytes/event, \
         p95 read latency < THRESHOLD ms, anchor growth = 1 row/event \
         ±5%. Threshold constants live at module scope and need a \
         reference-run calibration pass before they're trustable"
    )
}

fn step_6_cooldown_drain() -> ! {
    unimplemented!(
        "step 6: cancel samplers, drain all sender tasks, fire 100 final \
         reads, assert all succeed within 2× steady-state p95. Catches \
         shutdown-time latency cliffs (e.g. gc storms triggered by \
         queue draining)"
    )
}
