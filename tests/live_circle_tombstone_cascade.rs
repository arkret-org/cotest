#![allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
//! Live-stack integration test for CXP-0007 §Tombstone / Cascade Lifecycle;
//! defaults to ignored — set `COTEST_LIVE_STACK=1` to enable (or invoke with
//! `cargo test --test live_circle_tombstone_cascade -- --ignored`).
//!
//! Scenario (Phase B scaffold):
//!   1. Boot soland (+ coauth) via the existing CT-6 `FourServiceStack` bootstrap helper.
//!   2. Create a Realm and a Circle inside that Realm.
//!   3. Add two members to the Circle (strict subset of the Realm).
//!   4. Create N child Flows whose `scope_circle_id` references the Circle.
//!   5. Issue `cx.circle.tombstone` against the Circle. Assert: a) `Circle.state == Tombstoned` in
//!      the projection, b) any further write into the Circle is rejected with `failed_precondition`
//!      / sub-reason `circle_not_active`, c) child Flow projections surface as unavailable through
//!      the sync API (`history_visibility` clamped, deliverability flag cleared) per CXP-0007
//!      cascade rules, d) Circle members see the Circle in their client-side list as `tombstoned`
//!      (not silently disappeared).
//!   6. Repeat the exercise one level up: tombstone the parent Realm with a *fresh* Realm + Circle
//!      and assert every Circle in that Realm is cascade-tombstoned (CXP-0007: Realm tombstone
//!      implies Circle tombstone for every Circle whose `realm_id` matches).
//!
//! Gating mirrors `tests/soland_teabay_directory_sync.rs` / `full_stack_e2e.rs`:
//! the test is `#[ignore]` AND silently `bail!`s with a descriptive message
//! when the four-service stack cannot be bootstrapped (missing docker /
//! sibling binaries / `DATABASE_URL`).

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use cokret_core::error::REASON_CIRCLE_NOT_ACTIVE;
use cokret_core::{
    Circle, CircleColorToken, CircleDisplay, CircleGlyph, CircleId, CircleState, CircleSymbol, Did,
    RealmId,
};
use cotest::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, try_bootstrap};
use serde_json::{Value, json};
use serial_test::serial;

/// Gating: live soland + coauth stack — default-ignored, set
/// `COTEST_LIVE_STACK=1` (or `--ignored`) once P5 stack is up.
/// Issue: CXP-0007 (Circle tombstone cascade)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CXP-0007 Circle tombstone cascade — live soland (+coauth) stack; default-ignored, opt in with --ignored once P5 stack is up or COTEST_LIVE_STACK=1"]
#[serial]
async fn circle_tombstone_cascades_to_flows_and_realm_tombstone_cascades_to_circles() -> Result<()>
{
    // ── 0. SDK-level invariants always run (mirror `full_stack_e2e`) ────
    // Ensure the wire reason code the live leg pins against is registered
    // in the SDK; a typo here would mask the live assertion.
    if REASON_CIRCLE_NOT_ACTIVE != "circle_not_active" {
        bail!(
            "SDK reason code drifted: REASON_CIRCLE_NOT_ACTIVE = `{}`",
            REASON_CIRCLE_NOT_ACTIVE
        );
    }

    // ── 1. Bootstrap the live stack (soft-skip when prereqs absent) ─────
    let stack = try_bootstrap(FourServiceConfig::new("cxp0007-tombstone")).await?;
    if stack.coauth.is_none() {
        bail!(
            "live tombstone cascade scenario requires coauth (membership state writes); \
             coauth bootstrap returned None — set COAUTH_BIN + docker, then re-run with --ignored"
        );
    }
    stack
        .assert_healthy()
        .await
        .map_err(|e| anyhow!("stack health check failed: {e}"))?;

    // ── 2. Register actors and create a Realm + Circle ──────────────────
    // soland's principal admin signer is responsible for `cx.realm.create`
    // in development mode; alice + bob are the future Circle members.
    let admin = stack
        .soland
        .register_client("did:web:admin.cxp0007.example", "@admin", "dev_admin")
        .await?;
    let alice = stack
        .soland
        .register_client("did:web:alice.cxp0007.example", "@alice", "dev_alice")
        .await?;
    let bob = stack
        .soland
        .register_client("did:web:bob.cxp0007.example", "@bob", "dev_bob")
        .await?;

    let realm_id = RealmId::new("ck:realm:0196419b-0000-7000-8000-cxp0007tomb01".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))?;
    let circle_id = CircleId::new("ck:circle:0196419b-0000-7000-8000-cxp0007tomb02".to_owned())
        .map_err(|e| anyhow!("circle id: {e}"))?;
    let actor_admin: Did = "did:web:admin.cxp0007.example"
        .parse()
        .map_err(|e| anyhow!("admin did: {e}"))?;

    // Build the canonical Circle struct the reducer expects. The SDK invariants
    // (strict subset, schema id, default state) are asserted here so the live
    // POST payload is always wire-compliant.
    let display = CircleDisplay {
        short_name: "Tomb".to_owned(),
        color_token: CircleColorToken::Slate,
        symbol: CircleSymbol::Glyph {
            glyph: CircleGlyph::Lock,
        },
    };
    let circle = Circle::new(
        circle_id.clone(),
        realm_id.clone(),
        "Tombstone Cascade",
        display,
        actor_admin.clone(),
    );
    if circle.state != CircleState::Active {
        bail!("Circle::new MUST default to Active; got {:?}", circle.state);
    }

    // ── 3. Drive the live wire: create Realm + Circle + Flows ───────────
    //
    // The remaining wire steps require soland's CXP-0007 surface:
    //   - POST /api/v1/realms                       (cx.realm.create)
    //   - POST /api/v1/realms/<id>/circles          (cx.circle.create)
    //   - POST /api/v1/circles/<id>/members         (cx.circle.member.state→active)
    //   - POST /api/v1/spaces/<rid>/flows           with scope_circle_id
    //   - POST /api/v1/circles/<id>/tombstone       (cx.circle.tombstone)
    //   - POST /api/v1/realms/<id>/tombstone        (cx.realm.tombstone)
    //
    // P5 finalises these endpoints; once they're stable replace the bail
    // below with the wire dance and the assertions documented in the doc
    // comment (steps 5a–d + Realm cascade).
    let _ = (alice.actor.as_str(), bob.actor.as_str());
    let _ = admin
        .post("/api/v1/realms")
        .json(&json!({
            "schema": "cx.schema.realm.v1",
            "id": realm_id.as_str(),
            "title": "Tombstone Cascade Realm",
        }))
        .send()
        .await
        .map_err(|e| anyhow!("realm create probe failed: {e}"))?;

    bail!(
        "TODO(P5/CXP-0007): live-stack wiring for Circle tombstone cascade is \
         scaffolded; finalise once soland exposes `cx.realm.tombstone` and \
         `cx.circle.tombstone` over the public REST surface. Expected assertions \
         (see doc comment): \
         (a) circle state→tombstoned visible in projection within {settle_ms}ms, \
         (b) follow-up writes rejected with reason `{reason}`, \
         (c) child Flow projections marked unavailable, \
         (d) member client list shows tombstoned entry, \
         (e) Realm tombstone cascades to every Circle whose realm_id matches.",
        settle_ms = Duration::from_secs(5).as_millis(),
        reason = REASON_CIRCLE_NOT_ACTIVE,
    );
}

/// Helper used once the live wire is finalised: poll the supplied `url`
/// every `interval` until `predicate` returns `Ok(true)` or the timeout
/// elapses. Kept here (rather than imported from harness) so the test
/// file is self-contained while still using the same poll cadence as
/// `eventually` in `cotest::harness`.
#[allow(dead_code)]
async fn poll_until(
    label: &str,
    timeout: Duration,
    interval: Duration,
    mut predicate: impl FnMut() -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<bool>> + Send>,
    >,
) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if predicate().await? {
            return Ok(());
        }
        tokio::time::sleep(interval).await;
    }
    Err(anyhow!("`{label}` did not settle within {timeout:?}"))
}

/// Sanity helper for parsing a JSON projection body into a Circle struct.
/// Asserted to round-trip cleanly so a soland regression that drops a
/// required field surfaces here.
#[allow(dead_code)]
fn parse_circle_projection(body: &Value) -> Result<Circle> {
    serde_json::from_value(body.clone()).map_err(|e| anyhow!("parse Circle projection: {e}"))
}
