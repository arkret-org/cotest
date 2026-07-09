//! CT-5 — `did:webvh` witness offline >24h + emergency recovery.
//!
//! Spec:
//!   - `arkret-spec/spec/v1/zh/identity/identity-did.md` §4.2.1 — `did:webvh` health states
//!     (`healthy`, `degraded_no_witness`, `stale_history`, `write_unavailable`, `untrusted`). 24h
//!     hard cap for `degraded_no_witness`; past it resolver MUST fail closed for new high-risk
//!     writes.
//!   - `arkret-spec/spec/v1/zh/identity/identity-did.md` §8.2 (numbered in the spec under §5+,
//!     key-management threshold path) — emergency recovery when remaining quorum < threshold.
//!   - `arkret-spec/spec/v1/zh/identity/key-management.md` §3.3 — rotation kinds (`scheduled` /
//!     `emergency`) and the requirement that emergency rotations are tagged and audited distinctly.
//!
//! Scenario walk-through (when fully wired):
//!   1. Boot the mock-witness harness (`cotest/e2e/mocks/mock-witness.mjs`) in `healthy` state.
//!   2. Boot `starid` with the mock witness configured as a required witness (witness DID
//!      `did:web:witness.joint-e2e.local`).
//!   3. Resolve a `did:webvh` and assert the resolver reports `health="healthy"` with a fresh
//!      witness signature.
//!   4. Flip witness via `POST /mock/witness/health {state:"down"}`. Per `mock-witness.mjs`,
//!      subsequent `/witness/sign` calls return 503 `witness_unavailable`.
//!   5. Within 24h: resolver SHOULD report `degraded_no_witness` (read ok, write disallowed for new
//!      high-risk DID ops).
//!   6. Simulate stale-by-clock by either (a) advancing test clock if starid supports a
//!      `STARID_CLOCK_NOW` env override, or (b) setting witness state to `down` long enough plus a
//!      starid `--max-witness-evidence-age` flag if available.
//!   7. After 24h window elapsed: resolver MUST enter `stale_history` / `untrusted` and
//!      `unresolvable` for new writes.
//!   8. Recovery: submit an emergency rotation that intentionally skips the prev-key signature
//!      requirement (because prev-key is the one that's gone offline / compromised).
//!      Resolver/registrar MUST tag the resulting DID log entry with `rotation_kind="emergency"`
//!      (key-management §3.3). Read back the DID document and assert the rotation entry carries the
//!      emergency marker.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Status: scaffolded as `#[ignore]`.
//!
//! Prerequisite blockers:
//!   * `mock-witness.mjs` exists (per `cotest/e2e/mocks/mock-witness.mjs`) and supports the `POST
//!     /mock/witness/health {state:"down"}` hook verified above. But the Rust harness has no helper
//!     yet to spawn it standalone — currently it's launched by `scripts/run-joint-e2e.ps1`. Need a
//!     `spawn_mock_witness()` helper analogous to `external_binary::spawn_required` that exec's
//!     `node mock-witness.mjs` with `MOCK_WITNESS_PORT` and returns a `SpawnedExternalProcess`-ish
//!     handle.
//!   * `starid` resolver health-state surfacing: the in-process resolver would need to expose
//!     `degraded_no_witness` / `stale_history` via a diagnostic endpoint (e.g. `GET
//!     /_arkret/root/identity/health/{did}`). Not yet present in `starid/src/`.
//!   * Test-clock injection or short-window override: the 24h hard cap is a real wall-clock window
//!     in production. The test needs either a `STARID_WITNESS_MAX_EVIDENCE_AGE` env that we can set
//!     to a few seconds, or a fake-clock harness. Neither exists today.
//!   * `rotation_kind="emergency"` tagging on the resolver side: the registrar must accept a
//!     `kind=emergency` query/body field on rotation submit and store it on the entry. Not yet
//!     implemented.
//!
//! Track: `_claude_todos.md` row CT-5. Unblock requires the four pieces
//! above; once the mock-witness Rust spawner lands (see CT-15 mock
//! tracking table), this becomes the first scenario to consume it.

use anyhow::Result;

/// CT-5 scenario probe. See module docs for the full prerequisites.
pub async fn webvh_witness_offline_recovery_run() -> Result<()> {
    // When ready, sketch:
    //
    //   let witness = spawn_mock_witness().await?;
    //   // env-inject witness URL into starid before spawn
    //   let starid = spawn_required(&STARID_SPEC_with_witness(&witness.base_url)).await?;
    //   let client = Client::new();
    //
    //   // Step 3: healthy resolve
    //   let h1 = client.get(starid.url("/_arkret/root/identity/health/did:webvh:.../scid"))
    //                  .send().await?.json::<Value>().await?;
    //   assert_eq!(h1["state"], "healthy");
    //
    //   // Step 4: flip witness down
    //   client.post(format!("{}/mock/witness/health", witness.base_url))
    //         .json(&json!({"state":"down"})).send().await?;
    //
    //   // Step 5: degraded_no_witness within window
    //   let h2 = client.get(starid.url("/_arkret/root/identity/health/did:webvh:.../scid"))
    //                  .send().await?.json::<Value>().await?;
    //   assert_eq!(h2["state"], "degraded_no_witness");
    //
    //   // Step 7: stale_history past window (with short max-evidence-age)
    //   tokio::time::sleep(Duration::from_secs(3)).await;
    //   let h3 = client.get(starid.url("/_arkret/root/identity/health/did:webvh:.../scid"))
    //                  .send().await?.json::<Value>().await?;
    //   assert!(matches!(h3["state"].as_str(), Some("stale_history"|"untrusted")));
    //
    //   // High-risk write fails closed
    //   let create = client.post(starid.url("/_starid/webvh/dids"))
    //                      .json(&json!({...})).send().await?;
    //   assert!(create.status().as_u16() >= 500 || create.status() == 423);
    //
    //   // Step 8: emergency recovery
    //   let rot = client.post(starid.url("/_starid/webvh/dids/<scid>/rotate"))
    //                   .json(&json!({"kind":"emergency",
    //                                 "skip_prev_key_sig": true,
    //                                 "new_controller_keys": [...],
    //                                 "recovery_proof": {...}}))
    //                   .send().await?;
    //   assert!(rot.status().is_success());
    //   let doc = client.get(starid.url("/_starid/webvh/dids/<scid>"))
    //                   .send().await?.json::<Value>().await?;
    //   let latest = doc["history"].as_array().unwrap().last().unwrap();
    //   assert_eq!(latest["rotation_kind"], "emergency");

    unimplemented!(
        "CT-5 webvh witness offline + emergency recovery — blocked on \
         mock-witness Rust spawner, starid health-state diagnostic \
         endpoint, max-evidence-age override, and rotation_kind=emergency \
         tagging (see module docs + _claude_todos.md CT-5)."
    )
}
