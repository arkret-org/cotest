use anyhow::Result;
use arkret_models_collaboration::event_sync::SealFrontierState;
use arkret_models_collaboration::http_bodies::{
    SealResolveOutcome, SealResolveSelection, SelfSealResolveRequestBody,
};
use cotest::harness::{ArkretServer, expect_json};
use cotest::scenarios::identity_test_support::{
    actor_did_for_service_did, seal_current_principal_control_frontier,
};
use reqwest::StatusCode;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn pcr_seal_resolve_is_owner_only_without_synthetic_membership() -> Result<()> {
    let server = ArkretServer::spawn("pcr-seal-visibility").await?;
    let alice = server
        .demo_client(
            &actor_did_for_service_did(server.service_did(), "alice-pcr-seals")?,
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = server
        .register_client(
            &actor_did_for_service_did(server.service_did(), "bob-pcr-seals")?,
            "bob-pcr-seals",
            "ak:device:01904100-0000-7000-8000-0000000000b1",
        )
        .await?;
    let realm_id = alice.principal.as_ref().unwrap().pcr_realm_id.clone();
    let frontier: SealFrontierState =
        serde_json::from_value(alice.realm_seal_frontier(realm_id.as_str()).await?)?;
    let seal_ref = frontier.frontier.sole_leaf()?.clone();
    seal_current_principal_control_frontier(
        &alice,
        &alice.principal.as_ref().unwrap().device_signing_key,
    )
    .await?;
    let unchanged: SealFrontierState =
        serde_json::from_value(alice.realm_seal_frontier(realm_id.as_str()).await?)?;
    assert_eq!(unchanged.frontier.sole_leaf()?, &seal_ref);
    let body = SelfSealResolveRequestBody {
        realm_id,
        selection: SealResolveSelection::SealRefs {
            seal_refs: vec![seal_ref.clone()],
        },
        history_traversal_access: None,
    };
    let owner: SealResolveOutcome = serde_json::from_value(
        expect_json(
            alice.query("/_arkret/self/seals/resolve").json(&body),
            StatusCode::OK,
        )
        .await?,
    )?;
    let SealResolveOutcome::Seals {
        seals,
        missing_seal_refs,
    } = owner
    else {
        panic!("Seal ref request returned conclusion mode")
    };
    assert!(missing_seal_refs.is_empty());
    assert_eq!(seals.len(), 1);
    assert_eq!(seals[0].id, seal_ref);
    let outsider: SealResolveOutcome = serde_json::from_value(
        expect_json(
            bob.query("/_arkret/self/seals/resolve").json(&body),
            StatusCode::OK,
        )
        .await?,
    )?;
    let SealResolveOutcome::Seals {
        seals,
        missing_seal_refs,
    } = outsider
    else {
        panic!("Seal ref request returned conclusion mode")
    };
    assert!(seals.is_empty());
    assert_eq!(missing_seal_refs, vec![seal_ref]);
    Ok(())
}
