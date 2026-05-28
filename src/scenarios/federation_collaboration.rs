use anyhow::Result;
use contrix_core::{Operation, OperationId, RealmId, canonical::canonical_sha256};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ContrixServer, TestServerGroup, encrypted_envelope, expect_account_subscribe_delta,
    expect_json, expect_text, register_account, submit_event,
};

const ALICE_DID: &str = "did:web:cotest-fed-alice.example";
const BOB_DID: &str = "did:web:cotest-fed-bob-b.example";
const ALICE_MESSAGE_OPERATION_ID: &str = "cx:operation:01904100-0000-7000-8000-fedc00000001";
const BOB_JOIN_OPERATION_ID: &str = "cx:operation:01904100-0000-7000-8000-fedc00000002";
const BOB_MESSAGE_OPERATION_ID: &str = "cx:operation:01904100-0000-7000-8000-fedc00000003";
const ALICE_MESSAGE_EVENT_ID: &str = "cx:event:01904100-0000-7000-8000-fedc00000001";
const BOB_MESSAGE_EVENT_ID: &str = "cx:event:01904100-0000-7000-8000-fedc00000003";

pub async fn cross_server_collaboration_flow_works() -> Result<()> {
    let group = TestServerGroup::multi("federation-collaboration", 2).await?;
    let server_a = group.server(0);
    let server_b = group.server(1);
    let alice = register_account(server_a, ALICE_DID, "@cotest-fed-alice", "dev_alice").await?;
    let bob = register_account(server_b, BOB_DID, "@cotest-fed-bob-b", "dev_bob_b").await?;

    let describe_a = expect_json(
        server_a.http().get(server_a.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    let describe_b = expect_json(
        server_b.http().get(server_b.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe_a["service_type"], "principal_server");
    assert_eq!(describe_b["service_type"], "principal_server");

    let bob_document = expect_json(
        server_a
            .http()
            .post(server_a.url("/api/v1/identity/resolve"))
            .json(&json!({"did": BOB_DID})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(bob_document["did_document"]["id"], BOB_DID);

    let verify_bob_body = json!({
        "actor_id": BOB_DID,
        "signature": {"alg": "none"},
        "purpose": "cross-server-invite"
    });
    let verify_bob = expect_json(
        with_round4_federation_headers(
            server_a
                .http()
                .post(server_a.url("/api/v1/federation/verify-actor"))
                .json(&verify_bob_body),
            server_b,
            server_a,
            &verify_bob_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(verify_bob["valid"], true);

    let realm_id = create_federated_realm(server_a, &alice).await?;

    let alice_message = Operation::create(
        OperationId::new(ALICE_MESSAGE_OPERATION_ID)?,
        RealmId::new(realm_id.clone())?,
        "cx.message.create",
        json!({
            "event_id": ALICE_MESSAGE_EVENT_ID,
            "sender": ALICE_DID,
            "thread_id": "cx:thread:federation",
            "space_title": "Federated Collaboration Space",
            "space_summary": "cross server collaboration",
            "discoverability": "invite_only",
            "history_visibility": "shared",
            "encryption_profile": "none",
            "plaintext_visible_services": [server_a.service_did(), server_b.service_did()],
            "members": [ALICE_DID, BOB_DID],
            "content": {
                "kind": "cx.content.text",
                "body": "hello bob from server a"
            },
            "encrypted": false
        }),
    );
    let bob_join = Operation::create(
        OperationId::new(BOB_JOIN_OPERATION_ID)?,
        RealmId::new(realm_id.clone())?,
        "cx.member.state",
        json!({
            "actor_id": BOB_DID,
            "member": BOB_DID,
            "membership": "join",
            "delivery_status": "unroutable"
        }),
    );
    let a_to_b_body = json!({
        "origin": server_a.service_did(),
        "destination": server_b.service_did(),
        "service_binding_ref": "cotest",
        "operations": [alice_message, bob_join]
    });
    let pushed_to_b = expect_json(
        with_round4_federation_headers(
            server_b
                .http()
                .put(server_b.url("/api/v1/federation/transactions/federation-a-to-b-01"))
                .json(&a_to_b_body),
            server_a,
            server_b,
            &a_to_b_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(&pushed_to_b["accepted"], ALICE_MESSAGE_OPERATION_ID);
    assert_json_array_contains(&pushed_to_b["accepted"], BOB_JOIN_OPERATION_ID);

    let pulled_on_b = expect_json(
        server_b.http().get(server_b.url(&format!(
            "/api/v1/federation/pull-operations?space_id={realm_id}"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert!(
        pulled_on_b["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["operation_id"] == ALICE_MESSAGE_OPERATION_ID),
        "server B pull did not include alice federation message: {pulled_on_b}"
    );

    let bob_sync = expect_account_subscribe_delta(
        server_b
            .http()
            .get(server_b.url("/api/v1/account/subscribe?catchup=true"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    assert!(
        sync_timeline_events(&bob_sync, &realm_id)?
            .iter()
            .any(|event| event["content"]["body"] == "hello bob from server a"),
        "bob sync did not include alice federation message: {bob_sync}"
    );

    let bob_reply = Operation::create(
        OperationId::new(BOB_MESSAGE_OPERATION_ID)?,
        RealmId::new(realm_id.clone())?,
        "cx.message.create",
        json!({
            "event_id": BOB_MESSAGE_EVENT_ID,
            "sender": BOB_DID,
            "thread_id": "cx:thread:federation",
            "space_title": "Federated Collaboration Space",
            "space_summary": "cross server collaboration",
            "discoverability": "invite_only",
            "history_visibility": "shared",
            "encryption_profile": "none",
            "plaintext_visible_services": [server_a.service_did(), server_b.service_did()],
            "members": [ALICE_DID, BOB_DID],
            "content": {
                "kind": "cx.content.text",
                "body": "hello alice from server b"
            },
            "encrypted": false
        }),
    );
    let b_to_a_body = json!({
        "origin": server_b.service_did(),
        "destination": server_a.service_did(),
        "service_binding_ref": "cotest",
        "operations": [bob_reply]
    });
    let txn = expect_json(
        with_round4_federation_headers(
            server_a
                .http()
                .put(server_a.url("/api/v1/federation/transactions/federation-b-to-a-01"))
                .json(&b_to_a_body),
            server_b,
            server_a,
            &b_to_a_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(txn["accepted"][0], BOB_MESSAGE_OPERATION_ID);
    let alice_sync = expect_account_subscribe_delta(
        server_a
            .http()
            .get(server_a.url("/api/v1/account/subscribe?catchup=true"))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    assert!(
        sync_timeline_events(&alice_sync, &realm_id)?
            .iter()
            .any(|event| event["content"]["body"] == "hello alice from server b"),
        "alice sync did not include bob federation reply: {alice_sync}"
    );

    let key_upload = expect_json(
        server_b
            .http()
            .post(server_b.url("/api/v1/keys/upload"))
            .bearer_auth(&bob)
            .json(&json!({
                "device_id": "dev_bob_b",
                "one_time_keys": [{
                    "algorithm": "signed_curve25519",
                    "key_id": "bob-otk1",
                    "key": "bob-one-time"
                }],
                "fallback_keys": {},
                "device_signature": {"alg": "EdDSA", "signature": "bob-device-signature"}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(key_upload["one_time_key_counts"]["signed_curve25519"], 1);

    let device_message = expect_json(
        server_b
            .http()
            .post(server_b.url("/api/v1/device_messages"))
            .bearer_auth(&bob)
            .header("Idempotency-Key", "federation-to-bob-01")
            .json(&json!({
                "messages": {
                    BOB_DID: {
                        "dev_bob_b": {
                            "type": "cx.mls.welcome",
                            "content": encrypted_envelope("cx.mls.welcome", "opaque-cross-server-welcome")
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(device_message["ok"], true);

    let received = expect_json(
        server_b
            .http()
            .get(server_b.url("/api/v1/device_messages"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        received["events"][0]["content"]["content"]["ciphertext"],
        "opaque-cross-server-welcome"
    );

    let blob = expect_json(
        server_a
            .http()
            .post(server_a.url("/api/v1/blob/upload"))
            .bearer_auth(&alice)
            .header("content-type", "application/octet-stream")
            .body("federated-media"),
        StatusCode::OK,
    )
    .await?;
    let downloaded = expect_text(
        server_a
            .http()
            .get(server_a.url(&format!(
                "/api/v1/blob/get?blob_ref={}&purpose=federation.media",
                blob["blob_ref"].as_str().unwrap()
            )))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(downloaded, "federated-media");

    let push = expect_json(
        server_b
            .http()
            .post(server_b.url("/api/v1/push/register-device"))
            .bearer_auth(&bob)
            .json(&json!({
                "device_id": "dev_bob_b",
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "yougen"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push["ok"], true);

    let report = expect_json(
        server_b
            .http()
            .post(server_b.url("/api/v1/moderation/report"))
            .bearer_auth(&bob)
            .json(&json!({
                "realm_id": realm_id,
                "target_ref": ALICE_MESSAGE_EVENT_ID,
                "reason": "spam",
                "reporter": BOB_DID
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "queued");

    Ok(())
}

async fn create_federated_realm(server: &ContrixServer, alice: &str) -> Result<String> {
    let realm_id = "cx:realm:01904100-0000-7000-8000-fedc011ab001".to_owned();
    let created = submit_event(
        server,
        alice,
        ALICE_DID,
        &realm_id,
        "cx.realm.create",
        json!({
            "object": {
                "id": &realm_id,
                "schema": "cx.schema.realm.v1",
                "title": "Federated Collaboration Space",
                "summary": "cross server collaboration",
                "trust_domain": "cx:trust_domain:federation-collaboration.cotest.local",
                "created_by": ALICE_DID,
                "schema_refs": ["cx.schema.realm.v1"],
                "default_discoverability": "invite_only",
                "default_join_rule": "invite",
                "history_visibility": "shared",
                "encryption_profile": "none",
                "security_class": "standard",
                "federation_policy": "open",
                "anchor_profile": "single_did",
                "digest_algorithm": "sha256",
                "plaintext_visible_services": [server.service_did()],
                "anchorer": {
                    "type": "single_did",
                    "did": ALICE_DID,
                    "recovery_members": ["did:web:recovery-anchorer.cotest.local"],
                    "controller_organization": "did:web:federation-collaboration.cotest.local",
                    "recovery_controller_organizations": ["did:web:recovery-org.cotest.local"]
                },
                "created_at": "2026-05-02T00:00:00Z"
            }
        }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(created["status"], "accepted");
    Ok(realm_id)
}

fn with_round4_federation_headers(
    builder: reqwest::RequestBuilder,
    source: &ContrixServer,
    destination: &ContrixServer,
    body: &Value,
) -> Result<reqwest::RequestBuilder> {
    Ok(builder
        .header("Source-Trust-Domain", trust_domain_for(source))
        .header("Destination-Trust-Domain", trust_domain_for(destination))
        .header("Request-Canonical-Digest", canonical_sha256(body)?))
}

fn trust_domain_for(server: &ContrixServer) -> String {
    format!(
        "cx:trust_domain:{}",
        server.service_did().trim_start_matches("did:web:")
    )
}

fn sync_timeline_events<'a>(delta: &'a Value, realm_id: &str) -> Result<&'a Vec<Value>> {
    delta
        .get("realms")
        .or_else(|| delta.get("spaces"))
        .and_then(|realms| realms.get(realm_id))
        .and_then(|realm| realm.get("timeline"))
        .and_then(|timeline| timeline.get("events"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!("sync delta missing timeline events for {realm_id}: {delta}")
        })
}

fn assert_json_array_contains(array: &Value, expected: &str) {
    assert!(
        array
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some(expected)),
        "expected {array} to contain {expected}"
    );
}
