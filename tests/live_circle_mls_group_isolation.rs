#![allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
//! Live-stack integration test for CKP-0007 §MLS Group Isolation;
//! defaults to ignored — set `COTEST_LIVE_STACK=1` to enable (or invoke with
//! `cargo test --test live_circle_mls_group_isolation -- --ignored`).
//!
//! Scenario (Phase B scaffold):
//!   1. Boot soland (via `FourServiceStack`; coauth/starid/teabay are best-effort optional but
//!      soland is required).
//!   2. Create a Realm — soland MUST bind a Realm-default MLS group at creation time (CKP-0007
//!      §Realm.encryption_profile=mls_rfc9420).
//!   3. Create a Circle in that Realm. Soland MUST bind a NEW MLS group to the Circle whose
//!      `group_id` is distinct from the Realm's default group.
//!   4. Assert isolation: a) `Circle.mls_group_ref != Realm.default_mls_group_ref` (group
//!      identifiers differ), b) rotating the Circle's key (or driving a Circle-member-add commit)
//!      MUST NOT change the Realm-default group's epoch, c) adding a member to the Circle triggers
//!      exactly one MLS commit on the Circle's group (epoch += 1) and zero commits on the
//!      Realm-default group.
//!   5. Cryptographic isolation: spin up two distinct client instances (`SdkClient` with the same
//!      actor's bearer but separate keystores / device IDs). Client A joins the Realm-default
//!      group; client B joins the Circle's group. Each client SHOULD only be able to decrypt
//!      traffic from the group it joined; the Circle-only client MUST NOT decrypt a
//!      Realm-default-encrypted plaintext probe.
//!
//! Gating mirrors the other `live_circle_*` tests: `#[ignore]` + soft
//! `bail!` when the bootstrap can't bring up the stack.

use anyhow::{Result, anyhow, bail};
use arkret_core::{
    Circle, CircleColorToken, CircleDisplay, CircleGlyph, CircleId, CircleSymbol, Did,
    EncryptionProfile, RealmId,
};
use cotest::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, try_bootstrap};
use serde_json::json;
use serial_test::serial;

/// Gating: live soland stack — default-ignored, set
/// `COTEST_LIVE_STACK=1` (or `--ignored`) once P5 stack is up.
/// Issue: CKP-0007 (Circle / Realm-default MLS group isolation)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CKP-0007 Circle / Realm-default MLS group isolation — live soland stack; default-ignored, opt in with --ignored once P5 stack is up or COTEST_LIVE_STACK=1"]
#[serial]
async fn circle_mls_group_independent_from_realm_default_group() -> Result<()> {
    // ── 0. SDK-level invariant: a freshly-constructed Circle declares
    //       `EncryptionProfile::MlsRfc9420` (the only profile that has a
    //       distinct MLS group). The reducer MUST honour this.
    let admin_did: Did = "did:web:admin.ckp0007.example"
        .parse()
        .map_err(|e| anyhow!("admin did: {e}"))?;
    let display = CircleDisplay {
        short_name: "MLS".to_owned(),
        color_token: CircleColorToken::Teal,
        symbol: CircleSymbol::Glyph {
            glyph: CircleGlyph::Key,
        },
    };
    let circle_id = CircleId::new("ak:circle:0196419b-0000-7000-8000-ckp0007mls001".to_owned())
        .map_err(|e| anyhow!("circle id: {e}"))?;
    let realm_id = RealmId::new("ak:realm:0196419b-0000-7000-8000-ckp0007mls000".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))?;
    let circle = Circle::new(
        circle_id.clone(),
        realm_id.clone(),
        "MLS Isolation",
        display,
        admin_did.clone(),
    );
    if circle.encryption_profile != EncryptionProfile::MlsRfc9420 {
        bail!(
            "Circle::new MUST default encryption_profile to MlsRfc9420; got {:?}",
            circle.encryption_profile
        );
    }
    // `mls_group_ref` is reducer-derived; on the wire it MUST be unset until
    // soland binds a group. Catch any drift in the SDK default.
    if circle.mls_group_ref.is_some() {
        bail!(
            "Circle::new MUST leave mls_group_ref unset (reducer-derived); got {:?}",
            circle.mls_group_ref
        );
    }

    // ── 1. Bootstrap soland (coauth optional for this scenario) ─────────
    let stack = try_bootstrap(FourServiceConfig::new("ckp0007-mls-iso")).await?;
    stack
        .assert_healthy()
        .await
        .map_err(|e| anyhow!("stack health check failed: {e}"))?;

    // ── 2. Register an admin + two probe clients. We deliberately use
    //       distinct `device_id` values so each TestActorClient wraps a
    //       separate keystore (matching the spec's two-instance
    //       requirement for cryptographic-isolation verification).
    let admin = stack
        .soland
        .register_client(
            "did:web:admin.ckp0007.example",
            "@admin",
            "ak:device:01904100-0000-7000-8000-00000000ad01",
        )
        .await?;
    let client_realm_default = stack
        .soland
        .register_client(
            "did:web:probe.ckp0007.example",
            "@probe-realm",
            "ak:device:01904100-0000-7000-8000-00000000e006",
        )
        .await?;
    let client_circle_only = stack
        .soland
        .register_client(
            "did:web:probe.ckp0007.example",
            "@probe-circle",
            "ak:device:01904100-0000-7000-8000-00000000e007",
        )
        .await?;

    let _ = (
        client_realm_default.actor.as_str(),
        client_circle_only.actor.as_str(),
    );

    // ── 3. Drive the live wire (P5 unblock). Expected endpoints:
    //         POST /_arkret/self/realms                       (ck.realm.create) →
    //              response carries `default_mls_group_ref`
    //         POST /_arkret/self/realms/<rid>/circles         (ck.circle.create) →
    //              response carries Circle.mls_group_ref (distinct id)
    //         POST /_arkret/self/circles/<cid>/members        membership commit
    //              advances the Circle group's epoch (verify via GET on
    //              the Circle projection)
    //         GET  /_arkret/self/realms/<rid>                 → realm-default
    //              group epoch UNCHANGED across the Circle commit
    //
    //       Cryptographic isolation: drive two `SdkClient` channels (one
    //       per device_id above). Send a Realm-default-scoped envelope
    //       through `client_realm_default.sdk()` and confirm
    //       `client_circle_only.sdk()` returns a key-not-found error
    //       (NOT a decoding error — soland must withhold the key, not
    //       hand it out + fail decode).
    let _ = admin
        .post("/_arkret/self/realms")
        .json(&json!({
            "schema": "ck.schema.realm.v1",
            "id": realm_id.as_str(),
            "title": "MLS Iso Realm",
            "encryption_profile": "mls_rfc9420",
        }))
        .send()
        .await
        .map_err(|e| anyhow!("realm create probe failed: {e}"))?;

    bail!(
        "TODO(P5/CKP-0007): live-stack wiring for Circle / Realm-default MLS \
         isolation is scaffolded; finalise once soland's CKP-0007 surface returns \
         (a) `default_mls_group_ref` on `ck.realm.create` responses and \
         (b) `mls_group_ref` on `ck.circle.create` / Circle projection. \
         Expected assertions: \
         (a) Circle.mls_group_ref != Realm.default_mls_group_ref, \
         (b) Circle member-add advances Circle epoch by exactly 1 + leaves \
         Realm-default epoch unchanged, \
         (c) Realm-default-scoped ciphertext is NOT decryptable by a \
         Circle-only client (key withhold, not decode failure)."
    );
}
