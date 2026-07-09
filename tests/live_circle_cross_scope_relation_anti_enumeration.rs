#![allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
//! Live-stack integration test for CKP-0007 §Cross-Scope Relation
//! Anti-Enumeration; defaults to ignored — set `COTEST_LIVE_STACK=1` to
//! enable (or invoke with
//! `cargo test --test live_circle_cross_scope_relation_anti_enumeration -- --ignored`).
//!
//! Scenario (Phase B scaffold):
//!   1. Boot soland + teabay (teabay is hard-required for the directory projection assertion).
//!   2. Create a Realm. Create:
//!        - F1: Realm-scoped *public* Strand (`scope_circle_id` unset).
//!        - F2: Circle-scoped *private* Strand whose `scope_circle_id` binds to a Circle inside the
//!          same Realm.
//!   3. Establish `Relation::ConfidentialDiscussionOf` (F1 → F2). Per CKP-0007 spec, this is the
//!      canonical cross-scope edge.
//!   4. Query F1 from two client identities: a) `circle_member` — actor in the Circle: MUST see the
//!      F1 → F2 edge with the `confidential_discussion_of` kind AND a presence hint (e.g.
//!      `circle_member_count`) proving F2 exists, b) `realm_member_not_in_circle` — Realm member
//!      but NOT in the Circle: MUST NOT see the F1 → F2 edge at all (anti-enumeration — the
//!      existence of F2 is itself confidential to Circle members; even a redacted edge would leak
//!      the Circle's activity), and a directory query for F2 against teabay MUST 404 (NOT 403 —
//!      anti-enumeration; 403 would confirm existence).
//!   5. teabay projection cross-check: the directory's `directory/spaces` / `directory/strands`
//!      query as a Realm-but-not-Circle member MUST return F1 only; F2 MUST be absent (NOT
//!      redacted-present).
//!
//! Gating mirrors the other `live_circle_*` tests: `#[ignore]` + soft
//! `bail!` when the stack cannot be bootstrapped.

use anyhow::{Result, anyhow, bail};
use arkret_core::{
    Circle, CircleColorToken, CircleDisplay, CircleGlyph, CircleId, CircleSymbol, Did, RealmId,
    RelationKind,
};
use cotest::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, try_bootstrap};
use serde_json::json;
use serial_test::serial;

/// Gating: live soland + teabay stack — default-ignored, set
/// `COTEST_LIVE_STACK=1` (or `--ignored`) once P5 stack is up.
/// Issue: CKP-0007 (Circle cross-scope Relation anti-enumeration)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CKP-0007 Circle cross-scope Relation anti-enumeration — live soland + teabay stack; default-ignored, opt in with --ignored once P5 stack is up or COTEST_LIVE_STACK=1"]
#[serial]
async fn confidential_discussion_of_edge_invisible_to_non_circle_members() -> Result<()> {
    // ── 0. SDK-level invariant: the relation kind serialises to the
    //       canonical wire token. The non-Circle-member projection check
    //       below keys on this exact token; a drift would silently mask
    //       the assertion.
    let json_kind = serde_json::to_value(RelationKind::ConfidentialDiscussionOf)
        .map_err(|e| anyhow!("serialise ConfidentialDiscussionOf: {e}"))?;
    let s = json_kind
        .as_str()
        .ok_or_else(|| anyhow!("RelationKind MUST serialise as a string; got {json_kind:?}"))?;
    if s != "confidential_discussion_of" {
        bail!(
            "RelationKind::ConfidentialDiscussionOf wire token drifted: `{s}`; \
             update `live_circle_cross_scope_relation_anti_enumeration.rs` if intentional"
        );
    }

    // ── 1. Bootstrap soland + teabay (teabay is required for the
    //       directory projection assertion).
    let stack = try_bootstrap(FourServiceConfig::new("ak.0007-rel-antienum")).await?;
    if stack.teabay.is_none() {
        bail!(
            "live anti-enumeration scenario requires teabay (directory projection); \
             teabay bootstrap returned None — ensure TEABAY_BIN + DATABASE_URL are \
             present, then re-run with --ignored"
        );
    }
    stack
        .assert_healthy()
        .await
        .map_err(|e| anyhow!("stack health check failed: {e}"))?;

    // ── 2. Register admin + two probe actors (Circle member and Realm-
    //       only member). The Realm-only actor is the anti-enumeration
    //       probe.
    let admin = stack
        .soland
        .register_client(
            "did:web:admin.ckp0007.example",
            "@admin",
            "ak:device:01904100-0000-7000-8000-00000000ad01",
        )
        .await?;
    let circle_member = stack
        .soland
        .register_client(
            "did:web:incircle.ckp0007.example",
            "@incircle",
            "ak:device:01904100-0000-7000-8000-0000000000e1",
        )
        .await?;
    let realm_only = stack
        .soland
        .register_client(
            "did:web:realm-only.ckp0007.example",
            "@realm-only",
            "ak:device:01904100-0000-7000-8000-00000000e002",
        )
        .await?;
    let _ = (circle_member.actor.as_str(), realm_only.actor.as_str());

    let admin_did: Did = "did:web:admin.ckp0007.example"
        .parse()
        .map_err(|e| anyhow!("admin did: {e}"))?;
    let realm_id = RealmId::new("ak:realm:0196419b-0000-7000-8000-ckp0007rel001".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))?;
    let circle_id = CircleId::new("ak:circle:0196419b-0000-7000-8000-ckp0007rel002".to_owned())
        .map_err(|e| anyhow!("circle id: {e}"))?;
    let display = CircleDisplay {
        short_name: "Rel".to_owned(),
        color_token: CircleColorToken::Fuchsia,
        symbol: CircleSymbol::Glyph {
            glyph: CircleGlyph::Eye,
        },
    };
    let _circle = Circle::new(
        circle_id.clone(),
        realm_id.clone(),
        "Anti-Enum",
        display,
        admin_did,
    );

    // ── 3. Drive the live wire (P5 unblock). Expected endpoints:
    //         POST /_arkret/self/realms                                 (admin)
    //         POST /_arkret/self/realms/<rid>/circles                   (admin)
    //         POST /_arkret/self/realms/<rid>/members                   add incircle + realm-only
    //         POST /_arkret/self/circles/<cid>/members                  add incircle only
    //         POST /_arkret/self/realms/<rid>/strands                     create F1
    // (scope_circle_id: null)         POST /_arkret/self/realms/<rid>/strands
    // create F2 (scope_circle_id: <cid>)         POST /_arkret/self/relations
    // kind=confidential_discussion_of, from=F1, to=F2         GET
    // /_arkret/self/strands/<F1>/relations as incircle       expect edge present + F2 hint
    // GET  /_arkret/self/strands/<F1>/relations as realm-only     expect F2 edge OMITTED
    // GET  /_arkret/self/strands/<F2> as realm-only expect 404 (NOT 403)         (teabay) POST
    // /_arkret/find/directory/search-strands        as realm-only → F2 absent
    //
    //       Assertions:
    //         (a) circle_member's view: edge present, points at F2,
    //             includes `circle_member_count` hint (>0),
    //         (b) realm_only's view: F1 returned but `relations[]` MUST
    //             NOT contain any edge whose `to_ref` is F2 (and MUST
    //             NOT contain a redacted/opaque placeholder either —
    //             the F2 reference is fully absent),
    //         (c) GET on F2 itself as realm_only returns HTTP 404 with
    //             a generic "not found" body (NO `permission_denied`
    //             leak — anti-enumeration),
    //         (d) teabay's directory search as realm_only returns 0
    //             hits for F2's title/id; same query as circle_member
    //             returns F2.
    let _ = admin
        .post("/_arkret/self/realms")
        .json(&json!({
            "schema": "ak.schema.realm.v1",
            "id": realm_id.as_str(),
            "title": "Anti-Enum Realm",
        }))
        .send()
        .await
        .map_err(|e| anyhow!("realm create probe failed: {e}"))?;

    bail!(
        "TODO(P5/CKP-0007): live-stack wiring for `confidential_discussion_of` \
         cross-scope anti-enumeration is scaffolded; finalise once soland \
         publishes Strand + Relation endpoints carrying scope_circle_id projection \
         tiers and teabay's directory projection honours Circle membership in \
         its search filter. Expected assertions: \
         (a) circle_member sees the edge + presence hint, \
         (b) realm-only sees NO edge to F2 (full omission, not redacted), \
         (c) GET F2 as realm-only returns 404 (not 403 — anti-enumeration), \
         (d) teabay directory search hides F2 from realm-only."
    );
}
