#![allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
//! Live-stack integration test for CKP-0007 §Capability Two-Tier AND;
//! defaults to ignored — set `COTEST_LIVE_STACK=1` to enable (or invoke with
//! `cargo test --test live_circle_capability_two_tier_and -- --ignored`).
//!
//! CKP-0007 evaluates a Circle write as
//!
//!     allowed = grant_present(cap) AND (scope == null OR actor ∈ Circle.members)
//!
//! both halves MUST hold. Either-half-missing MUST be rejected with
//! `permission_denied` / sub-reason `capability_missing` (no grant) or
//! `actor_not_in_circle` (no membership) — never silently allowed.
//!
//! Scenario (Phase B scaffold):
//!   1. Boot soland + coauth (coauth issues the cap grant).
//!   2. Create a Realm + Circle. Actor Y is a Realm member but NOT a Circle member.
//!   3. Grant Y `ck.circle.manage` via coauth's session-grant surface.
//!   4. Y attempts `ck.circle.update` (e.g. patch the title) → MUST be rejected
//!      (`permission_denied` / membership half failed) despite the grant being present.
//!   5. Add Y to the Circle (`ck.circle.member.state → active`); retry the update → MUST succeed
//!      (both halves satisfied).
//!   6. Revoke Y's `ck.circle.manage` grant while Y is still a Circle member; retry the update →
//!      MUST be rejected (`permission_denied` / grant half failed).
//!   7. Cross-check: `ck.circle.audit` (a strictly read-only cap) follows the same two-tier
//!      evaluation — a member without the cap MUST be rejected; a non-member with the cap MUST be
//!      rejected too.
//!
//! Gating mirrors the other `live_circle_*` tests: `#[ignore]` + soft
//! `bail!` when the stack cannot be bootstrapped.

use anyhow::{Result, anyhow, bail};
use arkret_core::{
    CAP_ACTION_CIRCLE_AUDIT, CAP_ACTION_CIRCLE_MANAGE, Circle, CircleColorToken, CircleDisplay,
    CircleGlyph, CircleId, CircleSymbol, Did, RealmId,
};
use cotest::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, try_bootstrap};
use serde_json::json;
use serial_test::serial;

/// Gating: live soland + coauth stack — default-ignored, set
/// `COTEST_LIVE_STACK=1` (or `--ignored`) once P5 stack is up.
/// Issue: CKP-0007 (Circle capability two-tier AND)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CKP-0007 Circle capability two-tier AND — live soland + coauth stack; default-ignored, opt in with --ignored once P5 stack is up or COTEST_LIVE_STACK=1"]
#[serial]
async fn circle_write_requires_both_capability_grant_and_membership() -> Result<()> {
    // ── 0. SDK-level invariants: the cap actions we exercise live in
    //       the canonical CKP-0007 allow-list. A spelling drift here
    //       would mask the live wire assertion.
    if CAP_ACTION_CIRCLE_MANAGE != "ck.circle.manage" {
        bail!(
            "CAP_ACTION_CIRCLE_MANAGE drifted: `{CAP_ACTION_CIRCLE_MANAGE}`; \
             coauth's grant surface keys on this string"
        );
    }
    if CAP_ACTION_CIRCLE_AUDIT != "ck.circle.audit" {
        bail!(
            "CAP_ACTION_CIRCLE_AUDIT drifted: `{CAP_ACTION_CIRCLE_AUDIT}`; \
             coauth's grant surface keys on this string"
        );
    }

    // ── 1. Bootstrap soland + coauth (coauth is hard-required for cap grants).
    let stack = try_bootstrap(FourServiceConfig::new("ckp0007-cap-and")).await?;
    if stack.coauth.is_none() {
        bail!(
            "live capability AND scenario requires coauth (session-grant issuer); \
             coauth bootstrap returned None — set COAUTH_BIN + docker, then re-run \
             with --ignored"
        );
    }
    stack
        .assert_healthy()
        .await
        .map_err(|e| anyhow!("stack health check failed: {e}"))?;

    // ── 2. Register admin + actor Y. Admin holds `ck.circle.create` /
    //       `ck.circle.member.manage` by default in development mode; Y
    //       starts with zero grants.
    let admin = stack
        .soland
        .register_client(
            "did:web:admin.ckp0007.example",
            "@admin",
            "ak:device:01904100-0000-7000-8000-00000000ad01",
        )
        .await?;
    let actor_y = stack
        .soland
        .register_client(
            "did:web:y.ckp0007.example",
            "@y",
            "ak:device:01904100-0000-7000-8000-0000000000e3",
        )
        .await?;
    let _ = actor_y.actor.as_str();

    let admin_did: Did = "did:web:admin.ckp0007.example"
        .parse()
        .map_err(|e| anyhow!("admin did: {e}"))?;
    let realm_id = RealmId::new("ak:realm:0196419b-0000-7000-8000-ckp0007cap001".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))?;
    let circle_id = CircleId::new("ak:circle:0196419b-0000-7000-8000-ckp0007cap002".to_owned())
        .map_err(|e| anyhow!("circle id: {e}"))?;
    let display = CircleDisplay {
        short_name: "Cap".to_owned(),
        color_token: CircleColorToken::Violet,
        symbol: CircleSymbol::Glyph {
            glyph: CircleGlyph::Shield,
        },
    };
    let _circle = Circle::new(
        circle_id.clone(),
        realm_id.clone(),
        "Capability AND",
        display,
        admin_did,
    );

    // ── 3. Drive the live wire (P5 unblock). Expected endpoints:
    //         POST  /_arkret/self/realms                              (admin)
    //         POST  /_arkret/self/realms/<rid>/circles                (admin)
    //         POST  /_arkret/self/realms/<rid>/members                add Y (Realm member)
    //         POST  /coauth/_arkret/gate/account/session-grants               grant Y
    // ck.circle.manage         POST  /_arkret/self/circles/<cid>                       (Y;
    // expect 403)         POST  /_arkret/self/circles/<cid>/members               add Y to
    // Circle (admin)         POST  /_arkret/self/circles/<cid>                       (Y; expect
    // 200)         DELETE /coauth/_arkret/gate/account/session-grants/<grant>      revoke
    // (admin/system)         POST  /_arkret/self/circles/<cid>                       (Y; expect
    // 403)
    //
    //       Assertions:
    //         (i)   first update: 403 with reason
    //               `permission_denied` + sub-reason `actor_not_in_circle`,
    //         (ii)  second update: 200 + projection reflects the patch,
    //         (iii) third update (post-revoke): 403 with reason
    //               `permission_denied` + sub-reason `capability_missing`,
    //         (iv)  ck.circle.audit cross-check: Y without cap (still
    //               Circle member) MUST be rejected; Y with cap but
    //               removed from Circle MUST be rejected.
    let _ = admin
        .post("/_arkret/self/realms")
        .json(&json!({
            "schema": "ck.schema.realm.v1",
            "id": realm_id.as_str(),
            "title": "Cap AND Realm",
        }))
        .send()
        .await
        .map_err(|e| anyhow!("realm create probe failed: {e}"))?;

    bail!(
        "TODO(P5/CKP-0007): live-stack wiring for the two-tier capability \
         (grant ∧ membership) evaluation is scaffolded; finalise once soland \
         publishes the `ck.circle.update` REST surface and coauth's \
         session-grant issue/revoke endpoints are reachable from cotest. \
         Expected assertions: \
         (i) cap-present + non-member → 403 `actor_not_in_circle`, \
         (ii) cap-present + member → 200 + projection reflects update, \
         (iii) cap-absent + member → 403 `capability_missing`, \
         (iv) ck.circle.audit cross-check follows the same AND rule."
    );
}
