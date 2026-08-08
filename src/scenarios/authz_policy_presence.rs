use anyhow::Result;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, TestActorClient, expect_api_error, expect_json, expect_status, submit_event,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service, authorize_device_public_key, spawn_with_harness_account_authority,
};

pub async fn authz_grant_lifecycle_and_audit_work() -> Result<()> {
    let server = ArkretServer::spawn("authz-grants").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
        )
        .await?;
    let _presence_realm = alice.create_realm("Presence Policy Realm").await?;
    let bob = server
        .register_client(
            "did:web:bob-authz.example",
            "@bob-authz",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let realm_id = alice.create_realm("Grant Lifecycle Realm").await?;

    let denied_before_grant = expect_json(
        bob.post("/_arkret/self/authz/check")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody,
            >(json!({
                "actor_id": bob.actor,
                "action": "ak.realm.admin",
                "resource": {
                    "kind": "realm",
                    "id": realm_id,
                    "realm_id": realm_id
                }
            }))?),
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

    let actions = vec!["ak.realm.admin".to_owned()];
    let current_registry_digest = arkret::current_capability_action_registry_digest()?;
    let missing_basis = arkret::validate_capability_action_registry_binding(&actions, None)
        .expect_err("aggregate-admin grant without registry basis must fail closed");
    assert!(
        missing_basis
            .to_string()
            .contains("capability_registry_basis_unavailable")
    );
    let wrong_registry_digest =
        arkret_identifiers::Hash::new(format!("sha256:{}", "f".repeat(64)))?;
    let wrong_basis =
        arkret::validate_capability_action_registry_binding(&actions, Some(&wrong_registry_digest))
            .expect_err("aggregate-admin grant with unknown registry basis must fail closed");
    assert!(
        wrong_basis
            .to_string()
            .contains("capability_registry_basis_unavailable")
    );
    arkret::validate_capability_action_registry_binding(&actions, Some(&current_registry_digest))?;
    let (manage_grant_id, manage_grant) = alice
        .grant_realm_actions_to(&realm_id, &bob.actor, &["ak.realm.admin"])
        .await?;
    assert_eq!(manage_grant["status"], "accepted");

    let effective_grants = expect_json(
        alice.get("/_arkret/self/authz/effective-grants").query(&[
            ("subject", bob.actor.as_str()),
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

    let allowed_after_grant = expect_json(
        bob.post("/_arkret/self/authz/check")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody,
            >(json!({
                "actor_id": bob.actor,
                "action": "ak.realm.admin",
                "resource": {
                    "kind": "realm",
                    "id": realm_id,
                    "realm_id": realm_id
                }
            }))?),
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
    let id_suffix = realm_id.trim_start_matches("ak:realm:");
    let strand_id = format!("ak:strand:{id_suffix}");
    let relation_id = format!("ak:relation:{id_suffix}");
    let morph_id = format!("ak:morph:{id_suffix}");
    let negative_checks = [
        (
            "ak.message.create",
            json!({
                "kind": "strand",
                "id": strand_id,
                "realm_id": realm_id,
                "strand_id": strand_id
            }),
            "no_strand_track_message_grant",
        ),
        (
            "ak.pin.add",
            json!({
                "kind": "strand",
                "id": strand_id,
                "realm_id": realm_id,
                "strand_id": strand_id
            }),
            "capability_denied",
        ),
        (
            "ak.rsvp.set",
            json!({
                "kind": "strand",
                "id": strand_id,
                "realm_id": realm_id,
                "strand_id": strand_id
            }),
            "capability_denied",
        ),
        (
            "ak.policy.manage",
            json!({
                "kind": "realm",
                "id": realm_id,
                "realm_id": realm_id
            }),
            "capability_denied",
        ),
        (
            "ak.relation.create",
            json!({
                "kind": "relation",
                "id": relation_id,
                "realm_id": realm_id,
                "cell": format!("ak:cell:ak.component.relation.v1:{relation_id}")
            }),
            "capability_denied",
        ),
        (
            "ak.morph.create",
            json!({
                "kind": "morph",
                "id": morph_id,
                "realm_id": realm_id,
                "cell": format!("ak:cell:ak.component.morph.v1:{morph_id}")
            }),
            "capability_denied",
        ),
    ];
    for (action, resource, reason_code) in negative_checks {
        expect_authz_check_hard_deny(&bob, &bob.actor, action, resource, reason_code).await?;
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
            .json(&serde_json::from_value::<
                arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody,
            >(json!({
                "actor_id": bob.actor,
                "action": "ak.realm.admin",
                "resource": {
                    "kind": "realm",
                    "id": realm_id,
                    "realm_id": realm_id
                }
            }))?),
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
    resource: Value,
    reason_code: &str,
) -> Result<()> {
    let denied = expect_json(
        client
            .post("/_arkret/self/authz/check")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody,
            >(json!({
                "actor_id": actor_id,
                "action": action,
                "resource": resource
            }))?),
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

pub async fn push_policy_and_ice_contracts_work() -> Result<()> {
    let server = spawn_with_harness_account_authority("presence-policy", &[]).await?;
    let alice_actor = actor_did_for_service(server.service_id(), "presence-alice")?;
    let alice = server
        .demo_client(
            &alice_actor,
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
        )
        .await?;
    let alice_device_key = SigningKey::from_bytes(&[0xa1; 32]);
    authorize_device_public_key(
        &server,
        &alice.token,
        &alice.actor,
        &alice.device_id,
        &alice_device_key,
    )
    .await?;

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

    let push_registration = expect_json(
        alice
            .post("/_arkret/edge/push/register-device")
            .json(&serde_json::from_value::<
                arkret_models_integration::PushRegisterDeviceRequestBody,
            >(json!({
                "device_id": alice.device_id.as_str(),
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "inkson"
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push_registration["ok"], true);

    let push_unregister = expect_json(
        alice
            .post("/_arkret/edge/push/unregister-device")
            .json(&serde_json::from_value::<
                arkret_models_integration::PushUnregisterDeviceRequestBody,
            >(json!({
                "device_id": alice.device_id.as_str(),
                "push_key": "opaque",
                "app_id": "inkson"
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push_unregister["ok"], true);

    let policy_realm_id = alice.create_realm("Presence Policy Check Realm").await?;
    let policy_document = expect_json(
        alice
            .post("/_soland/self/policies")
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "policy_id": "ak:policy:presence-policy-allow",
                "scope": policy_realm_id,
                "subject_ref": alice.actor,
                "policy_kind": "ak.message.create",
                // Realm-scoped resource constraint: soland matches `resource.kind`
                // against the request's `source.service_kind`, so leave `kind` unset
                // (the policy applies to the realm regardless of calling service) and
                // constrain only on realm_id.
                "resource": {"realm_id": policy_realm_id},
                "effect": "allow",
                "actions": ["ak.message.create"],
                "obligations": []
            }))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(policy_document["active"], true);

    let allow_policy = expect_json(
        alice
            .post("/_arkret/self/policy/check")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::governance::policy_check::PolicyCheckRequestBody,
            >(json!({
                "request_id": "req-allow",
                "realm_id": policy_realm_id,
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "ak.message.create",
                "actor_id": alice.actor.as_str(),
                "source": {
                    "service_id": "did:web:soland.cotest.local",
                    "service_kind": "principal_server",
                    "signed_transport": true
                }
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(allow_policy["decision"], "allow");
    assert_eq!(allow_policy["reason_code"], "policy_allowed");
    assert!(
        allow_policy["signature"].is_object(),
        "policy/check must return a signed decision envelope"
    );
    assert!(
        allow_policy["auth_state_digest"].is_string(),
        "policy/check must bind the auth state digest"
    );

    let review_policy = expect_json(
        alice
            .post("/_arkret/self/policy/check")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::governance::policy_check::PolicyCheckRequestBody,
            >(json!({
                "request_id": "req-review",
                "realm_id": policy_realm_id,
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "ak.realm.destroy",
                "actor_id": alice.actor.as_str(),
                "source": {
                    "service_id": "did:web:soland.cotest.local",
                    "service_kind": "principal_server",
                    "signed_transport": true
                }
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(review_policy["decision"], "require_review");
    assert_eq!(review_policy["reason_code"], "review_required");
    assert!(review_policy["signature"].is_object());

    let policy_baseline = serde_json::from_value::<
        arkret_models_collaboration::governance::policy_check::PolicyCheckRequestBody,
    >(json!({
        "request_id": "req-invalid",
        "realm_id": "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
        "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "action": "ak.message.create",
        "actor_id": alice.actor.as_str(),
        "source": {
            "service_id": "did:web:soland.cotest.local",
            "service_kind": "principal_server",
            "signed_transport": true
        }
    }))?;
    let invalid_actor_body = crate::harness::wire_negative_from_sdk(&policy_baseline, |body| {
        body["actor_id"] = json!("alice")
    })?;
    expect_api_error(
        alice
            .post("/_arkret/self/policy/check")
            .json(&invalid_actor_body),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    let ice = expect_json(
        alice
            .post("/_arkret/self/rtc/ice-config")
            .json(&serde_json::from_value::<
                arkret_models_collaboration::objects::media::MediaIceConfigRequestBody,
            >(json!({
                "realm_id": policy_realm_id,
                "call_id": "ak:call:AbhvODyrIRCskAIoS9IXLjMfD-Zsr8lwDpiCU_zLR4it",
                "actor_id": alice.actor.as_str(),
                "device_id": alice.device_id.as_str(),
                "mode": "p2p"
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(ice["actor_id"], alice.actor);
    assert!(ice["ice_servers"].is_array());
    assert!(ice["signature"].is_object());

    Ok(())
}
