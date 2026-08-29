use anyhow::Result;
use arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody;
use arkret_models_collaboration::objects::media::{MediaIceConfigRequestBody, MediaIceMode};
use arkret_models_integration::{
    PushKey, PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody,
};
use arkret_wire::{
    DeviceId, DidCoreId, MorphId, RealmId, RelationId, ResourceSelectorKind, StrandId,
    WireResourceSelector,
};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    TestActorClient, actor_core_id, expect_api_error, expect_json, expect_status, submit_event,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
};

pub async fn authz_grant_lifecycle_and_audit_work() -> Result<()> {
    let server = spawn_with_harness_account_authority("authz-grants", &[]).await?;
    let alice_actor = actor_did_for_service_did(server.service_did(), "authz-alice")?;
    let alice = server
        .demo_client(
            &alice_actor,
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
        )
        .await?;
    let _presence_realm = alice.create_realm("Presence Policy Realm").await?;
    let bob_did = actor_did_for_service_did(server.service_did(), "authz-bob")?;
    let bob = server
        .register_client(
            &bob_did,
            "@bob-authz",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let bob_core_id = actor_core_id(&bob.actor)?;
    let realm_id = alice.create_realm("Grant Lifecycle Realm").await?;

    let denied_before_grant = expect_json(
        bob.post("/_arkret/self/authz/check")
            .json(&AuthzCheckRequestBody {
                actor_id: DidCoreId::new(bob_core_id.clone())?,
                action: "ak.realm.admin".to_owned(),
                resource: Some(WireResourceSelector::realm(RealmId::new(realm_id.clone())?)),
                context: None,
            }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied_before_grant["decision"], "hard_deny");
    assert_eq!(denied_before_grant["reason_code"], "capability_denied");
    assert!(
        denied_before_grant["obligations"]
            .as_array()
            .expect("authz obligations")
            .is_empty()
    );
    assert!(
        denied_before_grant.get("signature").is_none(),
        "authz/check is diagnostic and must not mint signed policy decisions"
    );

    let (manage_grant_id, manage_grant) = alice
        .grant_realm_actions_to(&realm_id, &bob.actor, &["ak.realm.admin"])
        .await?;
    assert_eq!(manage_grant["status"], "accepted");

    let effective_grants = expect_json(
        alice.get("/_arkret/self/authz/effective-grants").query(&[
            ("subject", bob_core_id.as_str()),
            ("subject_principal_server_id", alice.service_id()),
            ("realm_id", realm_id.as_str()),
        ]),
        StatusCode::OK,
    )
    .await?;
    assert!(effective_grants["state_digest"].is_string());
    assert!(
        effective_grants["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |grant| grant["id"].as_str() == Some(manage_grant_id.as_str())
                    || grant["grant_id"].as_str() == Some(manage_grant_id.as_str())
            ),
        "effective grants did not include projected manage grant: {effective_grants}"
    );

    expect_api_error(
        alice.get("/_arkret/self/authz/effective-grants").query(&[
            ("subject", bob_core_id.as_str()),
            ("realm_id", realm_id.as_str()),
        ]),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    let wrong_authority = expect_json(
        alice.get("/_arkret/self/authz/effective-grants").query(&[
            ("subject", bob_core_id.as_str()),
            (
                "subject_principal_server_id",
                "ak:did_core:web:other-principal.example",
            ),
            ("realm_id", realm_id.as_str()),
        ]),
        StatusCode::OK,
    )
    .await?;
    assert!(
        wrong_authority["grants"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "wrong authority pair leaked grants: {wrong_authority}"
    );

    let allowed_after_grant = expect_json(
        bob.post("/_arkret/self/authz/check")
            .json(&AuthzCheckRequestBody {
                actor_id: DidCoreId::new(bob_core_id.clone())?,
                action: "ak.realm.admin".to_owned(),
                resource: Some(WireResourceSelector::realm(RealmId::new(realm_id.clone())?)),
                context: None,
            }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(allowed_after_grant["decision"], "allow");
    assert!(
        allowed_after_grant["obligations"]
            .as_array()
            .expect("authz obligations")
            .is_empty()
    );
    assert_eq!(
        allowed_after_grant["matched_grants"][0]["grant_id"],
        manage_grant_id
    );

    alice.add_member(&realm_id, &bob).await?;
    let strand_id = alice.default_strand_id(&realm_id)?;
    // These negative authorization probes do not create the target objects;
    // keep independent frozen Event-derived coordinates instead of retyping
    // the Realm token into unrelated object kinds.
    let relation_id = "ak:relation:AU2FuIl7Kq70taw5RT2eOqgjJZDbJIZs_nCtuwEaOLTH";
    let morph_id = "ak:morph:AeoIMm0SoT07OMMZlyYNG7b9bvXo9Dj-aK28dRBThbn7";
    let negative_realm = RealmId::new(realm_id.clone())?;
    let negative_strand = StrandId::new(strand_id)?;
    let negative_checks = [
        (
            "ak.message.create",
            WireResourceSelector::strand(negative_realm.clone(), negative_strand.clone()),
            "no_strand_track_message_grant",
        ),
        (
            "ak.pin.add",
            WireResourceSelector::strand(negative_realm.clone(), negative_strand.clone()),
            "capability_denied",
        ),
        (
            "ak.rsvp.set",
            WireResourceSelector::strand(negative_realm.clone(), negative_strand),
            "capability_denied",
        ),
        (
            "ak.policy.manage",
            WireResourceSelector::realm(negative_realm.clone()),
            "capability_denied",
        ),
        (
            "ak.relation.create",
            WireResourceSelector {
                kind: ResourceSelectorKind::Relation,
                relation_id: Some(RelationId::new(relation_id)?),
                ..WireResourceSelector::realm(negative_realm.clone())
            },
            "capability_denied",
        ),
        (
            "ak.morph.create",
            WireResourceSelector {
                kind: ResourceSelectorKind::Morph,
                morph_id: Some(MorphId::new(morph_id)?),
                ..WireResourceSelector::realm(negative_realm)
            },
            "capability_denied",
        ),
    ];
    for (action, resource, reason_code) in negative_checks {
        expect_authz_check_hard_deny(&bob, &bob_core_id, action, resource, reason_code).await?;
    }

    let revoked_manage = submit_event(
        &server,
        &alice.token,
        &alice.actor,
        &realm_id,
        "ak.capability.revoke",
        json!({ "grant_id": manage_grant_id }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(revoked_manage["status"], "accepted");

    let denied_after_revoke = expect_json(
        bob.post("/_arkret/self/authz/check")
            .json(&AuthzCheckRequestBody {
                actor_id: DidCoreId::new(bob_core_id)?,
                action: "ak.realm.admin".to_owned(),
                resource: Some(WireResourceSelector::realm(RealmId::new(realm_id)?)),
                context: None,
            }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied_after_revoke["decision"], "hard_deny");
    assert_eq!(denied_after_revoke["reason_code"], "capability_denied");

    Ok(())
}

async fn expect_authz_check_hard_deny(
    client: &TestActorClient,
    actor_id: &str,
    action: &str,
    resource: WireResourceSelector,
    reason_code: &str,
) -> Result<()> {
    let denied = expect_json(
        client
            .post("/_arkret/self/authz/check")
            .json(&AuthzCheckRequestBody {
                actor_id: DidCoreId::new(actor_id)?,
                action: action.to_owned(),
                resource: Some(resource),
                context: None,
            }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied["decision"], "hard_deny", "{action}: {denied}");
    assert_eq!(denied["reason_code"], reason_code, "{action}: {denied}");
    assert!(
        denied["matched_grants"]
            .as_array()
            .expect("matched grants array")
            .is_empty(),
        "{action}: member baseline must not synthesize a matched grant"
    );
    Ok(())
}

pub async fn push_and_ice_contracts_work() -> Result<()> {
    let server = spawn_with_harness_account_authority("presence-policy", &[]).await?;
    let alice_actor = actor_did_for_service_did(server.service_did(), "presence-alice")?;
    let alice = server
        .demo_client(
            &alice_actor,
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
        )
        .await?;
    let alice_core_id = actor_core_id(&alice.actor)?;

    // client-sync.md: the account subscribe surface is read-only — there is no
    // `set_presence` subscribe parameter, and the stream carries no presence at
    // all in v1. Presence rides the encrypted Signal rail
    // (`profiles-presence.md` §3.1), whose plaintext the Sync Service may not
    // decrypt, aggregate or project (§3.3); the receiver-side contract is
    // covered by `conformance::presence_signal`.
    expect_status(
        server
            .http()
            .get(server.url("/_arkret/self/account/subscribe?catchup=true&set_presence=online")),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    let push_registration: arkret_models_integration::PushRegisterDeviceOutcome =
        serde_json::from_value(
            expect_json(
                alice.post("/_arkret/edge/push/register-device").json(
                    &PushRegisterDeviceRequestBody {
                        device_id: DeviceId::new(alice.device_id.clone())?,
                        push_gateway_url: "https://push.example".to_owned(),
                        push_key: PushKey::new("opaque").map_err(anyhow::Error::msg)?,
                        platform: Some("desktop".to_owned()),
                        app_id: Some("inkson".to_owned()),
                        display_name: None,
                        recipient_id: None,
                    },
                ),
                StatusCode::OK,
            )
            .await?,
        )?;
    assert!(!push_registration.push_target_id.as_str().is_empty());

    expect_status(
        alice
            .post("/_arkret/edge/push/unregister-device")
            .json(&PushUnregisterDeviceRequestBody {
                device_id: DeviceId::new(alice.device_id.clone())?,
                push_key: Some(PushKey::new("opaque").map_err(anyhow::Error::msg)?),
                app_id: Some("inkson".to_owned()),
            }),
        StatusCode::NO_CONTENT,
    )
    .await?;

    let media_realm_id = alice.create_realm("Presence Media Realm").await?;

    let ice = expect_json(
        alice
            .post("/_arkret/self/rtc/ice-config")
            .json(&MediaIceConfigRequestBody {
                realm_id: RealmId::new(media_realm_id)?,
                call_id: "ak:call:AbhvODyrIRCskAIoS9IXLjMfD-Zsr8lwDpiCU_zLR4it".to_owned(),
                actor_id: DidCoreId::new(alice_core_id.clone())?,
                device_id: DeviceId::new(alice.device_id.clone())?,
                mode: MediaIceMode::P2p,
            }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(ice["actor_id"], alice_core_id);
    assert!(ice["ice_servers"].is_array());
    assert!(ice["signature"].is_object());

    Ok(())
}
