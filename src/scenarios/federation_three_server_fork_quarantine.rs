//! CT-1 — Three-server federation fork quarantine.
//!
//! Spec references:
//!   - `cokret-spec/spec/v1/zh/sync/federation.md` §4.5 "Fork Detection / Frontier Exchange":
//!       * federation peers periodically exchange `{space_id, heads[], max_hlc,
//!         witness_receipts[]}` frontier digests.
//!       * "若两端历史包含相同 `event_id` 但不同 hash，接收方 MUST quarantine 并以
//!         `duplicate_conflict` 报告。"
//!       * "可疑 remote 输入 MAY 在 quarantine 队列中暂存，直到签名、 schema、capability、fork
//!         resolution 与 operator policy 全部 通过。"
//!   - `cokret-spec/spec/v1/zh/models/space-and-place.md` (Space cell- family lattice rules —
//!     concurrent cas-register / mv-register Moves on the same `cell_subject` MUST converge via the
//!     lattice merge rule, and conflicting "winning" branches are determined by the
//!     `state_resolution` profile, not by acceptance order).
//!
//! ──────────────────────────────────────────────────────────────────────────
//! ## Scenario walk-through (3 instances: alpha, beta, gamma)
//!
//! 1. Spawn three real soland binaries via the `TestServerGroup::try_multi_external` fast-path
//!    (mirrors the existing 2-server `federation_two_node_e1.rs`, extended to 3). Each instance
//!    gets a distinct `service_did`.
//!
//! 2. Wire pairwise federation peer trust: alpha ↔ beta, alpha ↔ gamma, beta ↔ gamma. For now this
//!    is "they can address each other by URL"; once soland ships outbound HTTP federation
//!    (E2E-FED-1) this step becomes a POST to `/api/v1/federation/peers` on each pair.
//!
//! 3. Alice creates space `S` on alpha. The space is pushed to beta and gamma so all three reach
//!    the same initial frontier.
//!
//! 4. Concurrent conflicting Moves on the **same `cell_subject`**:
//!       * alice from alpha submits a `cx.flow.move` (or `cx.space.title` cas-register Move)
//!         targeting `S/cell:title`.
//!       * bob's anchor request races on beta (independent actor, same cell, conflicting value).
//!       * charlie's on gamma (third independent value).
//!     Each server initially accepts its own Move into its local frontier
//!     because none has yet seen the others. This yields three diverged
//!     heads.
//!
//! 5. Drive forced sync via federation push: each server pushes its anchored leaves to the other
//!    two. On receipt of a Move that shares an `event_id` (or a `cell_subject` causal slot) with a
//!    differently-hashed local Move, soland MUST quarantine the conflicting branch per spec §4.5
//!    and emit `duplicate_conflict` in the rejected[] / quarantine[] response field.
//!
//! 6. After all three have exchanged frontiers, the cell's cas-register reducer + the
//!    state-resolution profile picks **one** canonical winner. The other two values remain
//!    quarantined (visible via the server's quarantine endpoint) until an operator reconciles them.
//!
//! 7. Asserts (when fully wired):
//!       * All three servers report the same `heads[]` for `S` (modulo witness-receipt ordering).
//!       * The minority two branches are present in each server's quarantine queue with
//!         `reason_code=duplicate_conflict` (or the spec-equivalent code in soland's wire
//!         vocabulary).
//!       * No server's `accepted[]` includes more than one of the three conflicting Moves.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! ## Status — `#[ignore]`'d
//!
//! Prerequisite blockers (soland-side):
//!   * **E2E-FED-1**: federation outbound push is currently a stub. Until `broadcast_move_to_peers`
//!     does real `POST /api/v1/federation/push- operations` with RFC 9421 signatures, the three
//!     nodes will not actually exchange their concurrent Moves and the "fork detected" branch is
//!     unreachable.
//!   * **E2E-FED-2**: inbound RFC 9421 signature verification — required for each receiving server
//!     to trust the pushed Moves before quarantining vs. accepting.
//!   * **Fork quarantine surface**: soland does not yet expose a `GET
//!     /api/v1/federation/quarantine` (or `quarantine[]` field on
//!     `/api/v1/federation/push-operations` responses). The §4.5 `duplicate_conflict` taxonomy is
//!     spec-only today.
//!   * **State-resolution profile selection**: 3-way merge of conflicting cas-register Moves needs
//!     the `state_resolution` profile to be deterministic across nodes; current soland only exposes
//!     the lattice merge at single-node level.
//!
//! This file scaffolds the full test body with `unimplemented!()` once
//! the three-node spawn succeeds, so an implementer landing E2E-FED-1
//! and the quarantine endpoint can fill in step by step. The scenario
//! sketch is deliberately verbose: each step records the request body,
//! expected status, and the spec section that authorises the assertion.
//!
//! Track: `_claude_todos.md` row CT-1.

use anyhow::Result;

use crate::harness::TestServerGroup;

/// CT-1 — three-server fork quarantine probe.
///
/// See module docs for the full walk-through and prerequisite blockers.
/// When soland's federation outbound + quarantine surface ships, the
/// stub below becomes a real assertion of three-way frontier
/// convergence.
pub async fn three_server_fork_quarantine_run() -> Result<()> {
    // Step 1: spawn 3 soland instances. Silent-skip if no soland binary
    // is locatable (matches the existing 2-node pattern in
    // `federation_two_node_e1.rs`).
    let Some(group) = TestServerGroup::try_multi_external("ct1-fork-quarantine-3node", 3).await?
    else {
        // Test entry is `#[ignore]`d, so we only reach here under
        // `--ignored` opt-in. A silent Ok lets CI runners without a
        // built soland skip cleanly rather than fail.
        return Ok(());
    };
    assert_eq!(
        group.len(),
        3,
        "three-node group must have exactly 3 servers"
    );

    let _alpha = group.server(0);
    let _beta = group.server(1);
    let _gamma = group.server(2);

    // ── Step 2: wire pairwise federation peer trust ─────────────────────
    //
    // When soland ships the peer-trust admin surface:
    //
    //   for (origin, peer) in [
    //       (alpha, beta), (alpha, gamma),
    //       (beta, alpha), (beta, gamma),
    //       (gamma, alpha), (gamma, beta),
    //   ] {
    //       expect_status(
    //           origin.http()
    //               .post(origin.url("/api/v1/federation/peers"))
    //               .json(&json!({
    //                   "peer_service_did": peer.service_did(),
    //                   "peer_base_url": peer.base_url(),
    //                   "trust_level": "mutual",
    //               })),
    //           StatusCode::OK,
    //       ).await?;
    //   }
    //
    // Today: no such admin surface — peer DIDs are inferred from the
    // push body's `origin` field at federation/anchors POST time.

    // ── Step 3: alice creates space on alpha and seeds beta + gamma ─────
    //
    //   let alice = alpha.register_client(
    //       "did:web:alice.ct1.cotest.local",
    //       "@alice-ct1",
    //       &new_prefixed_uuid7("ck:device:"),
    //   ).await?;
    //   let space_id = alice.create_realm("ct1-fork-quarantine-space").await?;
    //
    //   // Seed the initial frontier on beta + gamma by pushing the
    //   // space-create + first member-add Moves. This relies on
    //   // E2E-FED-1: today this is a no-op stub.
    //   for peer in [beta, gamma] {
    //       expect_json(
    //           peer.http()
    //               .post(peer.url("/api/v1/federation/push-operations"))
    //               .json(&json!({
    //                   "origin": alpha.service_did(),
    //                   "destination": peer.service_did(),
    //                   "realm_id": space_id,
    //                   "operations": <alpha's bootstrap moves>,
    //               })),
    //           StatusCode::OK,
    //       ).await?;
    //   }

    // ── Step 4: three concurrent conflicting Moves on the same cell ─────
    //
    // All three target `S/cell:title` (a cas-register cell) with
    // different values. Each is submitted to a *different* server's
    // /api/v1/events endpoint so each server initially accepts its own
    // value into local frontier.
    //
    //   let alpha_move = alice.submit_event(&space_id, "cx.space.title",
    //                       json!({"value": "alpha-wins"})).await?;
    //   let bob = beta.register_client(
    //       "did:web:bob.ct1.cotest.local", "@bob-ct1",
    //       &new_prefixed_uuid7("ck:device:")).await?;
    //   let beta_move = bob.submit_event(&space_id, "cx.space.title",
    //                       json!({"value": "beta-wins"})).await?;
    //   let charlie = gamma.register_client(
    //       "did:web:charlie.ct1.cotest.local", "@charlie-ct1",
    //       &new_prefixed_uuid7("ck:device:")).await?;
    //   let gamma_move = charlie.submit_event(&space_id, "cx.space.title",
    //                       json!({"value": "gamma-wins"})).await?;
    //
    //   // After this point each server has a different frontier `head`:
    //   //   alpha: hash(alpha_move)
    //   //   beta:  hash(beta_move)
    //   //   gamma: hash(gamma_move)

    // ── Step 5: drive forced sync via federation push ───────────────────
    //
    //   for (origin, peer, move_) in [
    //       (alpha, beta, alpha_move.clone()),
    //       (alpha, gamma, alpha_move.clone()),
    //       (beta, alpha, beta_move.clone()),
    //       (beta, gamma, beta_move.clone()),
    //       (gamma, alpha, gamma_move.clone()),
    //       (gamma, beta, gamma_move.clone()),
    //   ] {
    //       let response = expect_json(
    //           peer.http()
    //               .post(peer.url("/api/v1/federation/push-operations"))
    //               .json(&json!({
    //                   "origin": origin.service_did(),
    //                   "destination": peer.service_did(),
    //                   "realm_id": space_id,
    //                   "operations": [move_],
    //               })),
    //           StatusCode::OK,
    //       ).await?;
    //
    //       // Spec §4.5: differently-hashed Moves on the same
    //       // cell_subject MUST land in `rejected[]` or `quarantine[]`
    //       // with `reason_code=duplicate_conflict`.
    //       let rejected = response["rejected"].as_array().unwrap_or(&vec![]);
    //       let quarantined = response["quarantine"].as_array().unwrap_or(&vec![]);
    //       assert!(
    //           !rejected.is_empty() || !quarantined.is_empty(),
    //           "expected at least one Move to be quarantined or rejected"
    //       );
    //   }

    // ── Step 6: assert convergence ──────────────────────────────────────
    //
    //   // Wait for all three to drain their inbound queues + reducers
    //   // before reading the frontier.
    //   eventually(|| async {
    //       let frontiers = [alpha, beta, gamma].into_iter().map(|s| async move {
    //           expect_json(
    //               s.http().get(s.url(&format!(
    //                   "/api/v1/federation/anchors?space_id={space_id}"
    //               ))),
    //               StatusCode::OK,
    //           ).await
    //       });
    //       let frontiers = futures::future::try_join_all(frontiers).await?;
    //       // All three frontiers MUST agree on a single canonical
    //       // head, modulo witness-receipt ordering.
    //       assert_eq!(frontiers[0]["heads"], frontiers[1]["heads"]);
    //       assert_eq!(frontiers[1]["heads"], frontiers[2]["heads"]);
    //       Ok(())
    //   }, Duration::from_secs(10)).await?;

    // ── Step 7: assert quarantine queue is populated on the losers ──────
    //
    //   // The two "losing" branches (whichever the state-resolution
    //   // profile did not pick) MUST appear in each server's quarantine
    //   // surface with reason_code=duplicate_conflict.
    //   for server in [alpha, beta, gamma] {
    //       let q = expect_json(
    //           server.http().get(server.url(&format!(
    //               "/api/v1/federation/quarantine?space_id={space_id}"
    //           ))),
    //           StatusCode::OK,
    //       ).await?;
    //       let entries = q["entries"].as_array().expect("quarantine entries[]");
    //       assert_eq!(entries.len(), 2, "two losing branches must be quarantined");
    //       for entry in entries {
    //           assert_eq!(entry["reason_code"], "duplicate_conflict");
    //       }
    //   }

    unimplemented!(
        "CT-1 three-server fork quarantine — blocked on soland E2E-FED-1 \
         (outbound real HTTP federation push), E2E-FED-2 (inbound RFC 9421 \
         signature verification), and the §4.5 quarantine surface \
         (`GET /api/v1/federation/quarantine` + `duplicate_conflict` \
         reason_code in push response). See module docs + \
         soland/_todos.md E2E-FED-1/2/3 + spec §4.5."
    )
}
