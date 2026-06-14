#![allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
//! Live-stack integration test for CKP-0007 §Membership Cascade;
//! defaults to ignored — set `COTEST_LIVE_STACK=1` to enable (or invoke with
//! `cargo test --test live_circle_realm_member_removal_cascade -- --ignored`).
//!
//! Scenario (Phase B scaffold):
//!   1. Boot soland (+ coauth) via the existing CT-6 `FourServiceStack` bootstrap helper.
//!   2. Create a Realm and two Circles under it (`circle_alpha`, `circle_beta`). Both Circles share
//!      the same Realm.
//!   3. Register actor `X` and add X as a Realm member; also add X to both Circles
//!      (`ck.circle.member.state → active`).
//!   4. Admin issues `ck.realm.ck.member.state → left` for actor X. Assert: a) X's Realm membership
//!      flips to `left` in soland's projection, b) X's membership in BOTH `circle_alpha` AND
//!      `circle_beta` is auto-flipped to `left` (CKP-0007 strict-subset cascade: any Circle
//!      membership is invalid when the actor leaves the parent Realm, so the reducer MUST emit
//!      synthetic `ck.circle.member.state → left` events), c) each Circle's MLS group emits a
//!      *remove proposal* + commit pair: verify the Circle's `mls_group_ref` epoch advanced (the
//!      projection exposes the epoch number on `Circle.mls_group_ref` or via a sibling field once
//!      P5 finalises), d) a sync request from an actor that IS still in the Circle no longer sees X
//!      in the Circle's `ck.circle.members` projection.
//!
//! Gating mirrors the existing `#[ignore]` live tests; the bootstrap is
//! soft-skipped via a descriptive `bail!` when the stack cannot start.

use anyhow::{Result, anyhow, bail};
use cokret_core::{
    Circle, CircleColorToken, CircleDisplay, CircleGlyph, CircleId, CircleScopeError, CircleSymbol,
    Did, RealmId,
};
use cotest::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, try_bootstrap};
use serde_json::json;
use serial_test::serial;

/// Gating: live soland + coauth stack — default-ignored, set
/// `COTEST_LIVE_STACK=1` (or pass `--ignored`) once the P5 stack is up.
/// Issue: CKP-0007 (Realm-member-removal → Circle cascade)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CKP-0007 Realm-member-removal → Circle cascade — live soland (+coauth) stack; default-ignored, opt in with --ignored once P5 stack is up or COTEST_LIVE_STACK=1"]
#[serial]
async fn realm_member_left_cascades_to_every_circle_membership() -> Result<()> {
    // ── 0. SDK-level invariant: strict subset breaks the moment a Circle
    //       still references a non-Realm member; cascade exists precisely
    //       to keep this invariant whole. Confirm the SDK helper flags
    //       the violation we expect the reducer to prevent post-cascade.
    let alice: Did = "did:web:alice.ckp0007.example"
        .parse()
        .map_err(|e| anyhow!("alice did: {e}"))?;
    let x: Did = "did:web:x.ckp0007.example"
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
    let stack = try_bootstrap(FourServiceConfig::new("ckp0007-member-cascade")).await?;
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
        .register_client(
            "did:web:admin.ckp0007.example",
            "@admin",
            "ck:device:01904100-0000-7000-8000-00000000ad01",
        )
        .await?;
    let _alice_client = stack
        .soland
        .register_client(
            "did:web:alice.ckp0007.example",
            "@alice",
            "ck:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let _bob_client = stack
        .soland
        .register_client(
            "did:web:bob.ckp0007.example",
            "@bob",
            "ck:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let _x_client = stack
        .soland
        .register_client(
            "did:web:x.ckp0007.example",
            "@xeno",
            "ck:device:01904100-0000-7000-8000-0000000000e4",
        )
        .await?;

    let realm_id = RealmId::new("ck:realm:0196419b-0000-7000-8000-ckp0007memb01".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))?;
    let alpha_id = CircleId::new("ck:circle:0196419b-0000-7000-8000-ckp0007alpha".to_owned())
        .map_err(|e| anyhow!("alpha id: {e}"))?;
    let beta_id = CircleId::new("ck:circle:0196419b-0000-7000-8000-ckp0007beta0".to_owned())
        .map_err(|e| anyhow!("beta id: {e}"))?;

    // Build SDK Circle structs so the wire payload's schema id, display,
    // and default state are all spec-compliant before we POST.
    let display = |short_name: &str, glyph| CircleDisplay {
        short_name: short_name.to_owned(),
        color_token: CircleColorToken::Indigo,
        symbol: CircleSymbol::Glyph { glyph },
    };
    let admin_did: Did = "did:web:admin.ckp0007.example"
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
    //       then `realm.ck.member.state → left` for X. The expected
    //       endpoints are:
    //         POST /_cokret/self/realms                            (ck.realm.create)
    //         POST /_cokret/self/realms/<rid>/circles              (ck.circle.create) x2
    //         POST /_cokret/self/realms/<rid>/members              for alice + X (active)
    //         POST /_cokret/self/circles/<cid>/members             for X (active)  x2
    //         POST /_cokret/self/realms/<rid>/members/<x>/state    body {"state":"left"}
    //
    //       Assertions to wire in once the endpoints land:
    //         a) GET /_cokret/self/realms/<rid>/members/<x>  → 200 with state=left
    //         b) GET /_cokret/self/circles/<alpha>/members/<x> → state=left (cascade)
    //         c) GET /_cokret/self/circles/<beta>/members/<x>  → state=left (cascade)
    //         d) GET /_cokret/self/circles/<alpha>             → mls_group_ref epoch ↑
    //         e) GET /_cokret/self/circles/<beta>              → mls_group_ref epoch ↑
    //         f) other-member sync stream contains the synthetic
    //            `ck.circle.member.state` event with state=left for X
    //            (eventually() with 10s timeout, 250ms cadence).
    let _ = admin
        .post("/_cokret/self/realms")
        .json(&json!({
            "schema": "ck.schema.realm.v1",
            "id": realm_id.as_str(),
            "title": "Member Cascade Realm",
        }))
        .send()
        .await
        .map_err(|e| anyhow!("realm create probe failed: {e}"))?;

    bail!(
        "TODO(P5/CKP-0007): live-stack wiring for Realm-member-left → Circle cascade \
         is scaffolded; finalise once soland exposes the `ck.realm.ck.member.state` \
         and `ck.circle.member.state` projections + MLS epoch field. Expected \
         assertions: (a) X.realm.state=left, (b/c) X.circle.alpha.state=left + \
         X.circle.beta.state=left within 5s, (d/e) MLS epoch advanced exactly once \
         per Circle, (f) other members see synthetic `ck.circle.member.state→left` \
         event on the sync stream."
    );
}
