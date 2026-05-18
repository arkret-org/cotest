//! CT-4 — Knock + member.application + cooldown matrix.
//!
//! Spec: `contrix-spec/spec/v1/zh/models/space-and-place.md`
//!   - §3.3 — `default_join_rule` enum + gate composition
//!   - §3.6.2 — `member.application` schema
//!   - §3.6.3 — `member.application.review` (accept / reject / request_changes)
//!   - §3.6.4 — `member.application.cancel`
//!   - §3.6.5 — accepted-after-review → `cx.invite.create` + `cx.invite.accept`
//!   - §3.8  — membership state machine (knock → invite → join, reject → leave)
//!   - §3.11 — anti-abuse defaults (application_ttl=168h, cooldown=72h,
//!             max_open_applications_per_actor=1)
//!
//! Scenario walk-through (when fully wired):
//!   1. Alice creates a Space with `join_rule="knock"` and `manual_review`
//!      gate (`auto_resolve=false`); short test-only `application_ttl=10s`
//!      and `cooldown_after_reject=2s` so the matrix exercises in seconds.
//!   2. Bob (non-member) submits `cx.member.state{membership=knock}` →
//!      reducer accepts, projects bob into `members_in_state("knock")`.
//!   3. Bob submits `member.application` (in same batch SHOULD be allowed
//!      per §3.6.1); reducer accepts, projects `application_pending`.
//!   4. Reviewer alice submits `member.application.review{decision=reject,
//!      reason_code=other}` → bob's membership transitions back to
//!      `leave` with `cooldown_until` projection.
//!   5. Bob immediately re-submits `member.application` → expect
//!      `failed_precondition` errcode (cooldown active, §3.11).
//!   6. Wait > `cooldown_after_reject` (test-shortened to 2s) → re-submit
//!      knock + application succeeds.
//!   7. `max_open_applications_per_actor` cap: bob with one pending
//!      application submits a second → `failed_precondition`.
//!   8. `application_ttl` expiry: leave an application pending past the
//!      shortened ttl, then sync — application is auto-rejected
//!      (`rejected_reason="ttl_expired"`); does NOT engage cooldown.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Status: scaffolded as `#[ignore]`.
//!
//! Prerequisite blockers (none of the below currently land in soland's
//! dev-mode reducer, despite the bare `knock` membership state being
//! supported per `soland/src/reducer.rs::knock_state_visible_in_members_in_state_query`):
//!
//!   * `cx.space.join_rule` event kind not yet enforced by reducer (Space
//!     create only stores `public: bool`, no enum); no path to set
//!     `join_rule="knock"`.
//!   * `member.application` / `.review` / `.cancel` event kinds not in
//!     the soland event kind registry (`soland/src/routing/events/operations.rs`
//!     dispatcher table).
//!   * `cooldown_after_reject` / `application_ttl` /
//!     `max_open_applications_per_actor` reducer enforcement absent.
//!   * Test-only short-TTL injection: harness has no way to set
//!     `cooldown_after_reject=2s` (would need a soland test-mode env var
//!     or admin override route).
//!
//! Track: `_claude_todos.md` row CT-4. Unblock requires soland join-rule +
//! application machinery; once available, drop the `#[ignore]` and tighten
//! the asserts.

use anyhow::Result;

/// CT-4 scenario probe. See module docs for the full matrix this exercises.
///
/// Until the soland reducer wires up `cx.space.join_rule="knock"`,
/// `member.application`, `member.application.review`, and the cooldown /
/// TTL enforcement (§3.11), this scaffold returns immediately so the
/// `#[ignore]`'d test surfaces in `cargo test --list` output without
/// false-positive passes.
pub async fn knock_cooldown_matrix_run() -> Result<()> {
    // When ready: spawn soland, create space with knock policy, run the
    // 8-step matrix above. Skeleton sketch retained for the implementor:
    //
    //   let server = ContrixServer::spawn("knock-cooldown-matrix").await?;
    //   let alice = register_account(&server, "did:web:alice.example",
    //                                "@alice", "dev_alice").await?;
    //   let bob   = register_account(&server, "did:web:bob.example",
    //                                "@bob",   "dev_bob").await?;
    //
    //   let space_id = create_knock_space(&server, &alice,
    //       "Knock Test", /*application_ttl=*/"10s",
    //       /*cooldown_after_reject=*/"2s", /*max_open=*/1).await?;
    //
    //   // 2. Knock
    //   submit_event(&server, &bob, "did:web:bob.example", &space_id,
    //                "cx.member.state",
    //                json!({"membership":"knock"}), StatusCode::OK).await?;
    //   // 3. Application
    //   let app = submit_event(&server, &bob, "did:web:bob.example", &space_id,
    //                "member.application.v1",
    //                json!({"applicant_did":"did:web:bob.example",
    //                       "knock_ref":"<event id>",
    //                       "policy_version":"<sha256>",
    //                       "answers": []}), StatusCode::OK).await?;
    //   // 4. Reject
    //   submit_event(&server, &alice, "did:web:alice.example", &space_id,
    //                "member.application.review.v1",
    //                json!({"application_ref": app["event_id"],
    //                       "decision":"reject",
    //                       "reason_code":"other",
    //                       "reviewer_capability_proof": {...}}),
    //                StatusCode::OK).await?;
    //   // 5. Cooldown blocks re-application
    //   submit_event(..., StatusCode::CONFLICT).await? // failed_precondition
    //   // 6. Wait > 2s, retry succeeds
    //   tokio::time::sleep(Duration::from_secs(3)).await;
    //   submit_event(..., StatusCode::OK).await?;
    //   // 7. max_open cap
    //   submit_event(..., StatusCode::CONFLICT).await? // failed_precondition
    //   // 8. application_ttl expiry
    //   tokio::time::sleep(Duration::from_secs(11)).await;
    //   let app_state = fetch_application(&server, &alice, &app["event_id"]).await?;
    //   assert_eq!(app_state["status"], "rejected");
    //   assert_eq!(app_state["rejected_reason"], "ttl_expired");

    unimplemented!(
        "CT-4 knock + member.application + cooldown matrix — blocked on \
         soland join_rule=\"knock\" + member.application reducer + \
         cooldown / application_ttl / max_open enforcement (see module \
         docs and _claude_todos.md CT-4)."
    )
}
