#![allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
//! Live-stack integration test for CXP-0007 §Membership Cascade;
//! defaults to ignored — set `COTEST_LIVE_STACK=1` to enable (or invoke with
//! `cargo test --test live_circle_realm_member_removal_cascade -- --ignored`).
//!
//! Scenario (Phase B scaffold):
//!   1. Boot soland (+ coauth) via the existing CT-6 `FourServiceStack` bootstrap helper.
//!   2. Create a Realm and two Circles under it (`circle_alpha`, `circle_beta`). Both Circles share
//!      the same Realm.
//!   3. Register actor `X` and add X as a Realm member; also add X to both Circles
//!      (`cx.circle.member.state → active`).
//!   4. Admin issues `cx.realm.cx.member.state → left` for actor X. Assert: a) X's Realm membership
//!      flips to `left` in soland's projection, b) X's membership in BOTH `circle_alpha` AND
//!      `circle_beta` is auto-flipped to `left` (CXP-0007 strict-subset cascade: any Circle
//!      membership is invalid when the actor leaves the parent Realm, so the reducer MUST emit
//!      synthetic `cx.circle.member.state → left` events), c) each Circle's MLS group emits a
//!      *remove proposal* + commit pair: verify the Circle's `mls_group_ref` epoch advanced (the
//!      projection exposes the epoch number on `Circle.mls_group_ref` or via a sibling field once
//!      P5 finalises), d) a sync request from an actor that IS still in the Circle no longer sees X
//!      in the Circle's `cx.circle.members` projection.
//!
//! Gating mirrors the existing `#[ignore]` live tests; the bootstrap is
//! soft-skipped via a descriptive `bail!` when the stack cannot start.

use anyhow::{Result, anyhow, bail};
use contrix_core::{
    Circle, CircleColorToken, CircleDisplay, CircleGlyph, CircleId, CircleScopeError, CircleSymbol,
    Did, RealmId,
};
use cotest::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, try_bootstrap};
use serde_json::json;
use serial_test::serial;

/// Gating: live soland + coauth stack — default-ignored, set
/// `COTEST_LIVE_STACK=1` (or pass `--ignored`) once the P5 stack is up.
/// Issue: CXP-0007 (Realm-member-removal → Circle cascade)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CXP-0007 Realm-member-removal → Circle cascade — live soland (+coauth) stack; default-ignored, opt in with --ignored once P5 stack is up or COTEST_LIVE_STACK=1"]
#[serial]
async fn realm_member_left_cascades_to_every_circle_membership() -> Result<()> {
    // ── 0. SDK-level invariant: strict subset breaks the moment a Circle
    //       still references a non-Realm member; cascade exists precisely
    //       to keep this invariant whole. Confirm the SDK helper flags
    //       the violation we expect the reducer to prevent post-cascade.
    let alice: Did = "did:web:alice.cxp0007.example"
        .parse()
        .map_err(|e| anyhow!("alice did: {e}"))?;
    let x: Did = "did:web:x.cxp0007.example"
        .parse()
        .map_err(|e| anyhow!("x did: {e}"))?;
    let realm_members = vec![alice.clone()]; // X has already 'left'.
    let circle_members = vec![alice.clone(), x.clone()];
    match Circle::assert_members_strict_subset(&circle_members, &realm_members) {
        Err(CircleScopeError::MemberNotInRealm { circle_member }) => {
            if circle_member.as_str() != x.as_str() {
                bail!(
                    "expected MemberNotInRealm(x); got MemberNotInRealm({})",
                    circle_member.as_str()
                );
            }
        }
        other => {
            bail!("SDK invariant slipped: post-cascade strict-subset MUST reject X; got {other:?}")
        }
    }

    // ── 1. Bootstrap the live stack ────────────────────────────────────
    let stack = try_bootstrap(FourServiceConfig::new("cxp0007-member-cascade")).await?;
    if stack.coauth.is_none() {
        bail!(
            "live cascade scenario requires coauth (membership state writes); coauth \
             bootstrap returned None — set COAUTH_BIN + docker, then re-run with --ignored"
        );
    }
    stack
        .assert_healthy()
        .await
        .map_err(|e| anyhow!("stack health check failed: {e}"))?;

    // ── 2. Register admin + alice (stays) + bob (Circle-only proxy) + X.
    let admin = stack
        .soland
        .register_client("did:web:admin.cxp0007.example", "@admin", "dev_admin")
        .await?;
    let _alice_client = stack
        .soland
        .register_client("did:web:alice.cxp0007.example", "@alice", "dev_alice")
        .await?;
    let _bob_client = stack
        .soland
        .register_client("did:web:bob.cxp0007.example", "@bob", "dev_bob")
        .await?;
    let _x_client = stack
        .soland
        .register_client("did:web:x.cxp0007.example", "@xeno", "dev_x")
        .await?;

    let realm_id = RealmId::new("ck:realm:0196419b-0000-7000-8000-cxp0007memb01".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))?;
    let alpha_id = CircleId::new("ck:circle:0196419b-0000-7000-8000-cxp0007alpha".to_owned())
        .map_err(|e| anyhow!("alpha id: {e}"))?;
    let beta_id = CircleId::new("ck:circle:0196419b-0000-7000-8000-cxp0007beta0".to_owned())
        .map_err(|e| anyhow!("beta id: {e}"))?;

    // Build SDK Circle structs so the wire payload's schema id, display,
    // and default state are all spec-compliant before we POST.
    let display = |short_name: &str, glyph| CircleDisplay {
        short_name: short_name.to_owned(),
        color_token: CircleColorToken::Indigo,
        symbol: CircleSymbol::Glyph { glyph },
    };
    let admin_did: Did = "did:web:admin.cxp0007.example"
        .parse()
        .map_err(|e| anyhow!("admin did: {e}"))?;
    let _alpha = Circle::new(
        alpha_id.clone(),
        realm_id.clone(),
        "Alpha",
        display("Alpha", CircleGlyph::Star),
        admin_did.clone(),
    );
    let _beta = Circle::new(
        beta_id.clone(),
        realm_id.clone(),
        "Beta",
        display("Beta", CircleGlyph::Moon),
        admin_did.clone(),
    );

    // ── 3. Drive the live wire: create Realm + 2 Circles, add X to both,
    //       then `realm.cx.member.state → left` for X. The expected
    //       endpoints are:
    //         POST /api/v1/realms                            (cx.realm.create)
    //         POST /api/v1/realms/<rid>/circles              (cx.circle.create) x2
    //         POST /api/v1/realms/<rid>/members              for alice + X (active)
    //         POST /api/v1/circles/<cid>/members             for X (active)  x2
    //         POST /api/v1/realms/<rid>/members/<x>/state    body {"state":"left"}
    //
    //       Assertions to wire in once the endpoints land:
    //         a) GET /api/v1/realms/<rid>/members/<x>  → 200 with state=left
    //         b) GET /api/v1/circles/<alpha>/members/<x> → state=left (cascade)
    //         c) GET /api/v1/circles/<beta>/members/<x>  → state=left (cascade)
    //         d) GET /api/v1/circles/<alpha>             → mls_group_ref epoch ↑
    //         e) GET /api/v1/circles/<beta>              → mls_group_ref epoch ↑
    //         f) other-member sync stream contains the synthetic
    //            `cx.circle.member.state` event with state=left for X
    //            (eventually() with 10s timeout, 250ms cadence).
    let _ = admin
        .post("/api/v1/realms")
        .json(&json!({
            "schema": "cx.schema.realm.v1",
            "id": realm_id.as_str(),
            "title": "Member Cascade Realm",
        }))
        .send()
        .await
        .map_err(|e| anyhow!("realm create probe failed: {e}"))?;

    bail!(
        "TODO(P5/CXP-0007): live-stack wiring for Realm-member-left → Circle cascade \
         is scaffolded; finalise once soland exposes the `cx.realm.cx.member.state` \
         and `cx.circle.member.state` projections + MLS epoch field. Expected \
         assertions: (a) X.realm.state=left, (b/c) X.circle.alpha.state=left + \
         X.circle.beta.state=left within 5s, (d/e) MLS epoch advanced exactly once \
         per Circle, (f) other members see synthetic `cx.circle.member.state→left` \
         event on the sync stream."
    );
}
