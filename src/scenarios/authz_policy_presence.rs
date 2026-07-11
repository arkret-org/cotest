use anyhow::Result;
use chrono::{Duration as ChronoDuration, Timelike, Utc};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, TestActorClient, attach_ephemeral_proof, expect_account_subscribe_delta,
    expect_api_error, expect_json, expect_status, submit_event,
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
        alice.post("/_arkret/self/authz/check").json(&json!({
            "actor_id": bob.actor,
            "action": "ak.realm.admin",
            "resource": {
                "kind": "realm",
                "id": realm_id,
                "realm_id": realm_id
            }
        })),
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

    let manage_grant_id = "ak:grant:01999999-0000-7000-8000-0000000000a1";
    let manage_grant = submit_event(
        &server,
        &alice.token,
        &alice.actor,
        &realm_id,
        "ak.capability.grant",
        json!({
            "grant_id": manage_grant_id,
            "grant": {
                "id": manage_grant_id,
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer": alice.actor,
                "subject": bob.actor,
                "actions": ["ak.realm.admin"],
                "resources": [{
                    "kind": "realm",
                    "realm_id": realm_id
                }],
                "constraints": [],
                "issued_at": "2026-05-02T00:00:00Z",
                "proofs": [{
                    "kind": "detached_jws",
                    "alg": "EdDSA",
                    "verification_method": format!("{}#cotest", alice.actor),
                    "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2026-05-02T00:00:00Z",
                    "jws": "a..b"
                }]
            }
        }),
        StatusCode::OK,
    )
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
            .any(|grant| grant["id"].as_str() == Some(manage_grant_id)
                || grant["grant_id"].as_str() == Some(manage_grant_id)),
        "effective grants did not include projected manage grant: {effective_grants}"
    );

    let allowed_after_grant = expect_json(
        alice.post("/_arkret/self/authz/check").json(&json!({
            "actor_id": bob.actor,
            "action": "ak.realm.admin",
            "resource": {
                "kind": "realm",
                "id": realm_id,
                "realm_id": realm_id
            }
        })),
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
        expect_authz_check_hard_deny(&alice, &bob.actor, action, resource, reason_code).await?;
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
        alice.post("/_arkret/self/authz/check").json(&json!({
            "actor_id": bob.actor,
            "action": "ak.realm.admin",
            "resource": {
                "kind": "realm",
                "id": realm_id,
                "realm_id": realm_id
            }
        })),
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
        client.post("/_arkret/self/authz/check").json(&json!({
            "actor_id": actor_id,
            "action": action,
            "resource": resource
        })),
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

pub async fn presence_push_policy_and_ice_contracts_work() -> Result<()> {
    let server = ArkretServer::spawn("presence-policy").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
        )
        .await?;

    // client-sync.md: the account subscribe surface is read-only —
    // `set_presence` is not a subscribe parameter (the server ignores the
    // stray query value). Presence intent goes through
    // `POST /_arkret/self/ephemeral` as a proof-bound `ak.presence`.
    expect_status(
        server
            .http()
            .get(server.url("/_arkret/self/account/subscribe?catchup=true&set_presence=online")),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    let presence_realm_id = alice.create_realm("Presence Broadcast Realm").await?;

    // Closed v1 state set (profiles-presence.md §3.2): the Matrix-legacy
    // `unavailable` fails closed as schema_violation, never remapped to a
    // nearby state.
    expect_api_error(
        alice
            .post("/_arkret/self/ephemeral")
            .json(&presence_envelope(
                &alice.actor,
                alice.device_id.as_str(),
                &presence_realm_id,
                json!({"state": "unavailable"}),
            )),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    // Fail-closed `last_active_at` admission (§3.3): a bucket start not
    // aligned to its duration on the Unix-epoch UTC grid is malformed.
    expect_api_error(
        alice
            .post("/_arkret/self/ephemeral")
            .json(&presence_envelope(
                &alice.actor,
                alice.device_id.as_str(),
                &presence_realm_id,
                json!({"state": "idle", "last_active_at": "2026-06-22T10:34:00Z/PT1H"}),
            )),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    // A bucket duration below the PT60S protocol floor is malformed too.
    expect_api_error(
        alice
            .post("/_arkret/self/ephemeral")
            .json(&presence_envelope(
                &alice.actor,
                alice.device_id.as_str(),
                &presence_realm_id,
                json!({"state": "idle", "last_active_at": "2026-06-22T10:00:00Z/PT30S"}),
            )),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    // A valid precise (second-level) timestamp is schema-clean but needs
    // an explicit disclosure policy → policy_violation, not accepted.
    expect_api_error(
        alice
            .post("/_arkret/self/ephemeral")
            .json(&presence_envelope(
                &alice.actor,
                alice.device_id.as_str(),
                &presence_realm_id,
                json!({"state": "idle", "last_active_at": "2026-06-22T10:34:56Z"}),
            )),
        StatusCode::FORBIDDEN,
        "policy_violation",
    )
    .await?;

    // status_message over 256 Unicode code points fails closed (§3.3).
    expect_api_error(
        alice
            .post("/_arkret/self/ephemeral")
            .json(&presence_envelope(
                &alice.actor,
                alice.device_id.as_str(),
                &presence_realm_id,
                json!({"state": "dnd", "status_message": "字".repeat(257)}),
            )),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    // Legal manual-dnd broadcast with a transient status message is
    // admitted and survives into the presence projection for an
    // authorized observer (self sees full activity detail).
    let presence_accepted = expect_json(
        alice
            .post("/_arkret/self/ephemeral")
            .json(&presence_envelope(
                &alice.actor,
                alice.device_id.as_str(),
                &presence_realm_id,
                json!({"state": "dnd", "status_message": "In a meeting"}),
            )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(presence_accepted["accepted"], true);
    assert_eq!(presence_accepted["kind"], "ak.presence");

    let presence_sync = expect_account_subscribe_delta(
        alice.get("/_arkret/self/account/subscribe?catchup=true"),
        StatusCode::OK,
    )
    .await?;
    assert!(presence_sync["cursor"].is_string());

    let presence_events = presence_sync["presence"]["events"]
        .as_array()
        .expect("account subscribe presence events array");
    let alice_presence = presence_events
        .iter()
        .find(|event| {
            event["actor_id"] == "did:web:alice.example"
                || event["user_id"] == "did:web:alice.example"
        })
        .expect("alice presence in account subscribe baseline");
    assert_eq!(alice_presence["status"], "dnd");
    assert_eq!(
        alice_presence["status_message"], "In a meeting",
        "admitted status_message must survive into the projection: {alice_presence}"
    );

    // §3.4 activity-side-channel downgrade: an observer outside alice's
    // accepted-contact set sees `dnd` degraded to `offline`, with no
    // status_message or activity bucket leaking alongside.
    let observer = server
        .register_client(
            "did:web:observer-presence.example",
            "@observer-presence",
            "ak:device:01904100-0000-7000-8000-0000000000e0",
        )
        .await?;
    alice.add_member(&presence_realm_id, &observer).await?;
    let observer_sync = expect_account_subscribe_delta(
        observer.get("/_arkret/self/account/subscribe?catchup=true"),
        StatusCode::OK,
    )
    .await?;
    if let Some(observed_alice) = observer_sync["presence"]["events"]
        .as_array()
        .expect("observer presence events array")
        .iter()
        .find(|event| {
            event["actor_id"] == "did:web:alice.example"
                || event["user_id"] == "did:web:alice.example"
        })
    {
        assert_eq!(
            observed_alice["status"], "offline",
            "dnd must degrade to offline for non-contact observers: {observed_alice}"
        );
        assert!(
            observed_alice.get("status_message").is_none(),
            "degraded presence must not leak the status message: {observed_alice}"
        );
    }

    let push_registration = expect_json(
        alice
            .post("/_arkret/edge/push/register-device")
            .json(&json!({
                "device_id": alice.device_id.as_str(),
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "inkson"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push_registration["ok"], true);

    let push_unregister = expect_json(
        alice
            .post("/_arkret/edge/push/unregister-device")
            .json(&json!({
                "device_id": alice.device_id.as_str(),
                "push_key": "opaque",
                "app_id": "inkson"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push_unregister["ok"], true);

    let policy_realm_id = alice.create_realm("Presence Policy Check Realm").await?;
    let policy_document = expect_json(
        alice.post("/_soland/self/policies").json(&json!({
            "policy_id": "ak:policy:presence-policy-allow",
            "scope": policy_realm_id,
            "subject_ref": alice.actor,
            "policy_type": "ak.message.create",
            // Realm-scoped resource constraint: soland matches `resource.kind`
            // against the request's `source.service_type`, so leave `kind` unset
            // (the policy applies to the realm regardless of calling service) and
            // constrain only on realm_id.
            "resource": {"realm_id": policy_realm_id},
            "effect": "allow",
            "actions": ["ak.message.create"],
            "obligations": []
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(policy_document["active"], true);

    let allow_policy = expect_json(
        alice
            .post("/_arkret/self/policy/check")
            .json(&json!({
                "request_id": "req-allow",
                "realm_id": policy_realm_id,
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "ak.message.create",
                "actor_id": "did:web:alice.example",
                "source": {
                    "service_id": "did:web:soland.cotest.local",
                    "service_type": "principal_server",
                    "signed_transport": true
                }
            })),
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
            .json(&json!({
                "request_id": "req-review",
                "realm_id": policy_realm_id,
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "ak.realm.destroy",
                "actor_id": "did:web:alice.example",
                "source": {
                    "service_id": "did:web:soland.cotest.local",
                    "service_type": "principal_server",
                    "signed_transport": true
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(review_policy["decision"], "require_review");
    assert_eq!(review_policy["reason_code"], "review_required");
    assert!(review_policy["signature"].is_object());

    expect_api_error(
        alice
            .post("/_arkret/self/policy/check")
            .json(&json!({
                "request_id": "req-invalid",
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "ak.message.create",
                // `actor_id` is a typed Did; a bare "alice" parses as JSON but
                // violates the declared schema, so it is rejected as
                // `schema_violation` (422) before any semantic policy validation.
                "actor_id": "alice",
                "source": {
                    "service_id": "did:web:soland.cotest.local",
                    "service_type": "principal_server",
                    "signed_transport": true
                }
            })),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    let ice = expect_json(
        alice.post("/_arkret/self/rtc/ice-config").json(&json!({
            "realm_id": policy_realm_id,
            "call_id": "ak:call:01964137-0000-7000-8000-000000000001",
            "actor_id": alice.actor.as_str(),
            "device_id": alice.device_id.as_str(),
            "mode": "p2p"
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(ice["actor_id"], alice.actor);
    assert!(ice["ice_servers"].is_array());
    assert!(ice["signature"].is_object());

    Ok(())
}

/// ephemeral-envelope.schema.json: broadcast `ak.presence` with the
/// proof-bound sending device (detached JWS over the canonical envelope
/// without `proof`). `payload_fields` merges over the base
/// `{realm_id, actor_id, ttl_ms}` payload so callers only spell the
/// fields under test.
fn presence_envelope(
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    payload_fields: Value,
) -> arkret_core::EphemeralEnvelope {
    let sent_at = Utc::now()
        .with_nanosecond(0)
        .expect("zeroing nanos is valid");
    let expires_at = sent_at + ChronoDuration::seconds(30);
    let mut payload = json!({
        "realm_id": realm_id,
        "actor_id": actor_id,
        "ttl_ms": 30000
    });
    if let (Some(base), Some(extra)) = (payload.as_object_mut(), payload_fields.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    let mut envelope = arkret_core::EphemeralEnvelope::new(
        "ak.presence",
        arkret_core::RealmId::new(realm_id.to_owned()).expect("test realm id is typed"),
        arkret_core::Did::new(actor_id.to_owned()).expect("test actor DID is typed"),
        Some(arkret_core::DeviceId::new(device_id.to_owned()).expect("test device id is typed")),
        sent_at,
        expires_at,
        payload,
        None,
    )
    .expect("presence envelope is well-formed");
    attach_ephemeral_proof(&mut envelope, &SigningKey::from_bytes(&[0x5e; 32]));
    envelope
}
