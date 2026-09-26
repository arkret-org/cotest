use anyhow::Result;
use arkret_models_collaboration::governance::authorization::{AuthzCheckRequestBody, GrantList};
use arkret_models_collaboration::objects::media::{MediaIceConfigRequestBody, MediaIceMode};
use arkret_models_integration::{
    PushKey, PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody,
};
use arkret_wire::{
    AccountId, ActorId, DeviceId, DidCoreId, MorphId, RealmId, RelationId, ResourceSelectorKind,
    StrandId, WireResourceSelector,
};
use reqwest::StatusCode;

use crate::harness::{
    TestActorClient, actor_core_id, expect_api_error, expect_json, expect_status,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, create_human_actor_profile, spawn_with_standard_grant_authority,
};

pub async fn authz_grant_lifecycle_and_audit_work() -> Result<()> {
    let station = spawn_with_standard_grant_authority("authz-grants", &[]).await?;
    let server = &station.server;
    let alice_actor = actor_did_for_service_did(server.service_did(), "authz-alice")?;
    // Alice authors Realm Events, which needs her Standard SessionGrant.
    let alice = station.standard_grant_client(
        &server
            .demo_client(
                &alice_actor,
                "ak:device:01904100-0000-7000-8000-a11ce0000001",
            )
            .await?,
    )?;
    let _presence_realm = alice.create_realm("Presence Policy Realm").await?;
    let bob_did = actor_did_for_service_did(server.service_did(), "authz-bob")?;
    // Bob authors his own `ak.invite.accept`, which needs his Standard
    // SessionGrant.
    let bob = station.standard_grant_client(
        &server
            .register_client(
                &bob_did,
                "@bob-authz",
                "ak:device:01904100-0000-7000-8000-0000000000b0",
            )
            .await?,
    )?;
    create_human_actor_profile(&bob, "Bob Authz").await?;
    let bob_core_id = actor_core_id(&bob.actor)?;
    let realm_id = alice.create_realm("Grant Lifecycle Realm").await?;

    let denied_before_grant = expect_json(
        bob.post("/_arkret/self/authz/check")
            .json(&AuthzCheckRequestBody {
                actor_id: account_actor(&bob, &bob_core_id)?,
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
    assert_eq!(manage_grant["status"], "committed");

    // Human kind comes from Bob's accepted PCR profile above. A regular
    // high-risk Realm admin grant may be indefinite, while the broadcast
    // action's registry entry requires a finite global grant lifetime for
    // every subject.
    let issued_at = chrono::Utc::now();
    let mut broadcast_grant = serde_json::json!({
        "schema": "ak.schema.capability.v1",
        "realm_id": realm_id,
        "issuer_id": account_actor(&alice, &actor_core_id(&alice.actor)?)?,
        "subject": account_actor(&bob, &bob_core_id)?,
        "actions": ["ak.message.mention.broadcast"],
        "resources": [{"kind":"realm", "realm_id":realm_id, "match_scope":"realm_wide"}],
        "constraints": [{
            "constraint_kind":"quota",
            "effect":"allow",
            "max_operations":5,
            "period":"PT1H",
            "constraint_scope":"per_realm"
        }],
        "issuer_authority_refs": [{
            "kind":"realm_root",
            "realm_id":realm_id,
            "authority_event_ref": RealmId::new(realm_id.clone())?.event_id(),
            "authority_generation":0
        }],
        "issued_at": issued_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    });
    let missing_expiry = alice
        .author_event(
            &realm_id,
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            serde_json::json!({"grant": broadcast_grant.clone()}),
        )
        .await?;
    expect_api_error(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(missing_expiry, "")?),
        StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await?;
    broadcast_grant["constraints"]
        .as_array_mut()
        .expect("broadcast grant constraints")
        .push(serde_json::json!({
            "constraint_kind":"temporal",
            "effect":"allow",
            "expires_at": (issued_at + chrono::Duration::days(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        }));
    let broadcast = alice
        .submit_event(
            &realm_id,
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            serde_json::json!({"grant": broadcast_grant}),
        )
        .await?;
    assert_eq!(broadcast["status"], "committed");

    let subject_actor_id = account_actor(&bob, &bob_core_id)?.to_string();
    let effective_grants = expect_json(
        alice.get("/_arkret/self/authz/effective-grants").query(&[
            ("subject_actor_id", subject_actor_id.as_str()),
            ("realm_id", realm_id.as_str()),
        ]),
        StatusCode::OK,
    )
    .await?;
    let effective_list: GrantList = serde_json::from_value(effective_grants.clone())?;
    assert!(
        effective_list
            .grants
            .iter()
            .any(|row| row.grant.id.as_str() == manage_grant_id.as_str()),
        "effective grants did not include the committed manage grant: {effective_grants}"
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

    let wrong_subject = ActorId::account(AccountId::new(
        DidCoreId::new(bob_core_id.clone())?,
        DidCoreId::new("ak:did_core:web:other-principal.example")?,
    ))
    .to_string();
    let wrong_authority = expect_json(
        alice.get("/_arkret/self/authz/effective-grants").query(&[
            ("subject_actor_id", wrong_subject.as_str()),
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
                actor_id: account_actor(&bob, &bob_core_id)?,
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

    let revoked_manage = alice
        .revoke_realm_grant(&realm_id, &manage_grant_id)
        .await?;
    assert_eq!(revoked_manage["status"], "committed");

    let denied_after_revoke = expect_json(
        bob.post("/_arkret/self/authz/check")
            .json(&AuthzCheckRequestBody {
                actor_id: account_actor(&bob, &bob_core_id)?,
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
                actor_id: account_actor(client, actor_id)?,
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
    let station = spawn_with_standard_grant_authority("presence-policy", &[]).await?;
    let server = &station.server;
    let alice_actor = actor_did_for_service_did(server.service_did(), "presence-alice")?;
    // Alice creates a Realm below, which needs her Standard SessionGrant.
    let alice = station.standard_grant_client(
        &server
            .demo_client(
                &alice_actor,
                "ak:device:01904100-0000-7000-8000-a11ce0000001",
            )
            .await?,
    )?;
    let alice_core_id = actor_core_id(&alice.actor)?;

    // client-sync.md: the account subscribe surface is read-only — there is no
    // `set_presence` subscribe parameter, and the stream carries no presence at
    // all in v1. Presence rides the encrypted Signal rail
    // (`profiles-presence.md` §3.1), whose plaintext the Sync Service may not
    // decrypt, aggregate or project (§3.3); the receiver-side contract is
    // covered by `conformance::presence_signal`. An authenticated caller that
    // names the parameter is refused instead of having it silently ignored.
    expect_api_error(
        alice.get("/_arkret/self/account/subscribe?catchup=true&set_presence=online"),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    // push-notifications.md §3.3: a bare `push_gateway_url` never establishes
    // trust. This Station has onboarded no public Gateway, so registration
    // fails closed with the operation's registered `push_gateway_unreachable`
    // and installs nothing; §3.2 unregistration of the same device is then
    // the idempotent 204. The onboarded-Gateway success path belongs to the
    // joint registration handoff run, which supplies a live Gateway.
    let refused = expect_api_error(
        alice
            .post("/_arkret/edge/push/register-device")
            .json(&PushRegisterDeviceRequestBody {
                device_id: DeviceId::new(alice.device_id.clone())?,
                push_gateway_url: "https://push.example".to_owned(),
                push_key: PushKey::new("opaque").map_err(anyhow::Error::msg)?,
                platform: Some("desktop".to_owned()),
                app_id: Some("inkson".to_owned()),
                display_name: None,
                visible_notification_opt_in: false,
            }),
        StatusCode::SERVICE_UNAVAILABLE,
        "push_gateway_unreachable",
    )
    .await?;
    assert!(
        !serde_json::to_string(&refused)?.contains("opaque"),
        "a refused registration must not echo the provider route: {refused:?}"
    );

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
                actor_id: account_actor(&alice, &alice_core_id)?,
                device_id: DeviceId::new(alice.device_id.clone())?,
                mode: MediaIceMode::P2p,
            }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        ice["actor_id"],
        serde_json::to_value(account_actor(&alice, &alice_core_id)?)?
    );
    assert!(ice["ice_servers"].is_array());
    assert!(ice["signature"].is_object());

    Ok(())
}

fn account_actor(client: &TestActorClient, principal_id: &str) -> Result<ActorId> {
    Ok(ActorId::account(AccountId::new(
        DidCoreId::new(principal_id)?,
        DidCoreId::new(client.service_id().to_owned())?,
    )))
}
