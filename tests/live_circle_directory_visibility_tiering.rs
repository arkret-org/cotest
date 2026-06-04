#![allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
//! Live-stack integration test for CKP-0007 §Directory Visibility Tiering;
//! defaults to ignored — set `COTEST_LIVE_STACK=1` to enable (or invoke with
//! `cargo test --test live_circle_directory_visibility_tiering -- --ignored`).
//!
//! `Circle.directory_visibility` is a two-value enum (CKP-0007):
//!   - `Members`        — only Circle members see the Circle in any directory output; non-members
//!     must NOT receive a redacted-present entry (anti-enumeration).
//!   - `RealmMembers`   — any active Realm member sees an *opaque commitment* (no `title` /
//!     `display` / member count); only Circle members see the full metadata.
//! The spec does NOT define a third value; the SDK default is `Members`
//! (most-restrictive).
//!
//! Scenario (Phase B scaffold):
//!   1. Boot soland + teabay (teabay is hard-required for the projection assertion).
//!   2. Create a Realm. Create three Circles with `directory_visibility` set to `Members`,
//!      `RealmMembers`, and the SDK default (= `Members`). All three live in the same Realm.
//!   3. Identities used to probe teabay's directory:
//!        - `outsider`        — NOT a Realm member,
//!        - `realm_only`      — Realm member, NOT in any Circle,
//!        - `circle_member`   — Realm member AND in all three Circles.
//!   4. Probe teabay's `GET /_cokret/find/directory/circles?realm_id=<rid>` (or equivalent listing
//!      endpoint) and assert: a) `outsider`     — empty result for all three Circles (the Realm
//!      membership is itself the entry gate; non-Realm-members see nothing), b) `realm_only`   —
//!      sees ONLY the `RealmMembers` Circle, and its projection contains the opaque commitment
//!      fields ONLY (no `title`, `display`, `member_count`, `mls_group_ref`); the two `Members`
//!      Circles are absent (anti-enumeration — NOT redacted-present), c) `circle_member`— sees ALL
//!      three Circles with the full metadata projection (title, display, member_count, summary if
//!      set).
//!
//! Gating mirrors the other `live_circle_*` tests: `#[ignore]` + soft
//! `bail!` when the stack cannot be bootstrapped.

use anyhow::{Result, anyhow, bail};
use cokret_core::{
    Circle, CircleColorToken, CircleDirectoryVisibility, CircleDisplay, CircleGlyph, CircleId,
    CircleSymbol, Did, RealmId,
};
use cotest::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, try_bootstrap};
use serde_json::json;
use serial_test::serial;

/// Gating: live soland + teabay stack — default-ignored, set
/// `COTEST_LIVE_STACK=1` (or `--ignored`) once P5 stack is up.
/// Issue: CKP-0007 (Circle directory_visibility tiering)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CKP-0007 Circle directory_visibility tiering — live soland + teabay stack; default-ignored, opt in with --ignored once P5 stack is up or COTEST_LIVE_STACK=1"]
#[serial]
async fn circle_directory_visibility_tiers_project_correctly() -> Result<()> {
    // ── 0. SDK-level invariant: the enum has the two expected variants
    //       and the default constructor picks `Members`. Both are wire-
    //       observable; a drift here would silently mask the live
    //       assertion.
    let admin_did: Did = "did:web:admin.ckp0007.example"
        .parse()
        .map_err(|e| anyhow!("admin did: {e}"))?;
    let display = CircleDisplay {
        short_name: "Vis".to_owned(),
        color_token: CircleColorToken::Cyan,
        symbol: CircleSymbol::Glyph {
            glyph: CircleGlyph::Globe,
        },
    };
    let realm_id = RealmId::new("ck:realm:0196419b-0000-7000-8000-ckp0007vis000".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))?;
    let cid_members = CircleId::new("ck:circle:0196419b-0000-7000-8000-ckp0007vis001".to_owned())
        .map_err(|e| anyhow!("cid_members: {e}"))?;
    let cid_realm = CircleId::new("ck:circle:0196419b-0000-7000-8000-ckp0007vis002".to_owned())
        .map_err(|e| anyhow!("cid_realm: {e}"))?;
    let cid_default = CircleId::new("ck:circle:0196419b-0000-7000-8000-ckp0007vis003".to_owned())
        .map_err(|e| anyhow!("cid_default: {e}"))?;

    let circle_members = {
        let mut c = Circle::new(
            cid_members.clone(),
            realm_id.clone(),
            "Members-Only",
            display.clone(),
            admin_did.clone(),
        );
        c.directory_visibility = CircleDirectoryVisibility::Members;
        c
    };
    let circle_realm = {
        let mut c = Circle::new(
            cid_realm.clone(),
            realm_id.clone(),
            "Realm-Visible",
            display.clone(),
            admin_did.clone(),
        );
        c.directory_visibility = CircleDirectoryVisibility::RealmMembers;
        c
    };
    let circle_default = Circle::new(
        cid_default.clone(),
        realm_id.clone(),
        "Default-Visible",
        display.clone(),
        admin_did.clone(),
    );
    if circle_default.directory_visibility != CircleDirectoryVisibility::Members {
        bail!(
            "Circle::new MUST default directory_visibility to Members; got {:?}",
            circle_default.directory_visibility
        );
    }
    if circle_members.directory_visibility != CircleDirectoryVisibility::Members {
        bail!("explicit Members override lost");
    }
    if circle_realm.directory_visibility != CircleDirectoryVisibility::RealmMembers {
        bail!("explicit RealmMembers override lost");
    }

    // ── 1. Bootstrap soland + teabay. Teabay is hard-required.
    let stack = try_bootstrap(FourServiceConfig::new("ckp0007-dir-tier")).await?;
    if stack.teabay.is_none() {
        bail!(
            "live directory tiering scenario requires teabay (directory projection); \
             teabay bootstrap returned None — ensure TEABAY_BIN + DATABASE_URL are \
             present, then re-run with --ignored"
        );
    }
    stack
        .assert_healthy()
        .await
        .map_err(|e| anyhow!("stack health check failed: {e}"))?;

    // ── 2. Register admin + three probe identities.
    let admin = stack
        .soland
        .register_client("did:web:admin.ckp0007.example", "@admin", "dev_admin")
        .await?;
    let outsider = stack
        .soland
        .register_client(
            "did:web:outsider.ckp0007.example",
            "@outsider",
            "dev_outsider",
        )
        .await?;
    let realm_only = stack
        .soland
        .register_client(
            "did:web:realm-only.ckp0007.example",
            "@realm-only",
            "dev_realm_only",
        )
        .await?;
    let circle_member = stack
        .soland
        .register_client("did:web:incircle.ckp0007.example", "@incircle", "dev_in")
        .await?;
    let _ = (
        outsider.actor.as_str(),
        realm_only.actor.as_str(),
        circle_member.actor.as_str(),
    );

    // ── 3. Drive the live wire (P5 unblock). Expected endpoints:
    //         POST /_cokret/self/realms                          (admin)
    //         POST /_cokret/self/realms/<rid>/circles            x3 (admin)
    //         POST /_cokret/self/realms/<rid>/members            add realm-only + circle-member
    //         POST /_cokret/self/circles/<cid>/members           add circle-member to all 3
    //         (teabay) GET /_cokret/find/directory/circles?realm_id=<rid>
    //                                                     query as each probe identity
    //
    //       Assertions on the teabay projection (after the soland→teabay
    //       ingest latency budget — same 30s `eventually` cadence as
    //       `soland_teabay_directory_sync.rs`):
    //         (a) outsider:
    //             - empty list (NO entries for any of the three Circles),
    //             - no 4xx (just empty), to avoid an oracle for Realm existence (anti-enumeration
    //               on the Realm gate),
    //         (b) realm_only:
    //             - list length == 1, the entry's `id` matches `cid_realm`,
    //             - the entry MUST NOT contain `title`, `display`, `member_count`, `mls_group_ref`,
    //               `summary`, or any other identity-leaking field — only `id`, `realm_id`, and the
    //               opaque-commitment fields (`commitment` / `directory_visibility=realm_members`),
    //             - cid_members and cid_default MUST NOT appear in the response at all (NOT as
    //               redacted-present entries),
    //         (c) circle_member:
    //             - list length == 3, every entry contains the full metadata projection (`title`,
    //               `display`, `member_count`, `directory_visibility`, etc.).
    let _ = admin
        .post("/_cokret/self/realms")
        .json(&json!({
            "schema": "ck.schema.realm.v1",
            "id": realm_id.as_str(),
            "title": "Visibility Tier Realm",
        }))
        .send()
        .await
        .map_err(|e| anyhow!("realm create probe failed: {e}"))?;

    bail!(
        "TODO(P5/CKP-0007): live-stack wiring for Circle directory_visibility \
         tiering is scaffolded; finalise once soland publishes Circle creation \
         + member endpoints and teabay's `directory/circles` projection honours \
         the `Members` vs. `RealmMembers` enum. Expected assertions: \
         (a) outsider sees empty list (anti-enumeration on Realm gate), \
         (b) realm-only sees ONLY the RealmMembers Circle, opaque commitment \
         only (no title/display/member_count/mls_group_ref), and crucially \
         the other two Circles are ABSENT (NOT redacted-present), \
         (c) circle-member sees all three with full metadata."
    );
}
