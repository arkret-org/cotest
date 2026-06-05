use anyhow::Result;
use cokret::http_signature::{
    ContentDigest, ContentDigestAlgorithm, sign_message, signing_key_from_seed,
};
use cokret_core::canonical::{canonical_json_bytes, canonical_sha256};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::harness::{
    CokretServer, TestServerGroup, encrypted_envelope, expect_account_subscribe_delta, expect_json,
    expect_text, register_account, submit_event,
};

const ALICE_DID: &str = "did:web:cotest-fed-alice.example";
const BOB_DID: &str = "did:web:cotest-fed-bob-b.example";
const ALICE_MESSAGE_EVENT_ID: &str = "ck:event:01904100-0000-7000-8000-fedc00000001";
const BOB_JOIN_EVENT_ID: &str = "ck:event:01904100-0000-7000-8000-fedc00000002";
const BOB_MESSAGE_EVENT_ID: &str = "ck:event:01904100-0000-7000-8000-fedc00000003";

pub async fn cross_server_collaboration_flow_works() -> Result<()> {
    let group = TestServerGroup::multi("federation-collaboration", 2).await?;
    let server_a = group.server(0);
    let server_b = group.server(1);
    let alice = register_account(server_a, ALICE_DID, "@cotest-fed-alice", "dev_alice").await?;
    let bob = register_account(server_b, BOB_DID, "@cotest-fed-bob-b", "dev_bob_b").await?;

    let describe_a = expect_json(
        server_a.http().get(server_a.url("/_cokret/describe")),
        StatusCode::OK,
    )
    .await?;
    let describe_b = expect_json(
        server_b.http().get(server_b.url("/_cokret/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe_a["service_type"], "principal_server");
    assert_eq!(describe_b["service_type"], "principal_server");

    let bob_document = expect_json(
        server_a
            .http()
            .post(server_a.url("/_cokret/root/identity/resolve"))
            .json(&json!({"did": BOB_DID})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(bob_document["did_document"]["id"], BOB_DID);

    let realm_id = create_federated_realm(server_a, &alice).await?;
    // Federation ck.message.create Event payload carries the message
    // addressing/identity fields soland's federation projection consumes
    // (event_id, actor_id, flow_id, track_name, content). The forbidden wire
    // field `sender` is replaced by `actor_id`; Realm/membership metadata
    // (discoverability, history_visibility, members, encryption_profile, …)
    // belongs on the Realm object and `ck.member.state`, not the message.
    let flow_id = format!(
        "ck:flow:{}",
        realm_id.strip_prefix("ck:realm:").unwrap_or(&realm_id)
    );

    let alice_message = signed_federation_event(
        ALICE_MESSAGE_EVENT_ID,
        "ck.message.create",
        &realm_id,
        ALICE_DID,
        1,
        json!({
            "flow_id": flow_id.clone(),
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.text",
                "body": "hello bob from server a"
            }
        }),
    )?;
    let bob_join = signed_federation_event(
        BOB_JOIN_EVENT_ID,
        "ck.member.state",
        &realm_id,
        BOB_DID,
        1,
        json!({
            "membership": "join",
            "delivery_status": "unroutable"
        }),
    )?;
    let a_to_b_body =
        peer_events_submit_body(&realm_id, vec![alice_message, bob_join], Some("a-to-b-01"))?;
    let a_to_b_url = server_b.url("/_cokret/peer/events");
    let pushed_to_b = expect_json(
        with_federation_trust_headers(
            server_b.http().post(&a_to_b_url).json(&a_to_b_body),
            "POST",
            &a_to_b_url,
            server_a,
            server_b,
            &a_to_b_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(&pushed_to_b["accepted"], ALICE_MESSAGE_EVENT_ID);
    assert_json_array_contains(&pushed_to_b["accepted"], BOB_JOIN_EVENT_ID);

    let pulled_on_b = expect_json(
        server_b
            .http()
            .get(server_b.url(&format!("/_cokret/peer/events?realms={realm_id}"))),
        StatusCode::OK,
    )
    .await?;
    assert!(
        pulled_on_b["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event"]["event_id"] == ALICE_MESSAGE_EVENT_ID),
        "server B pull did not include alice federation message: {pulled_on_b}"
    );

    let bob_sync = expect_account_subscribe_delta(
        server_b
            .http()
            .get(server_b.url("/_cokret/self/account/subscribe?catchup=true"))
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

    let bob_reply = signed_federation_event(
        BOB_MESSAGE_EVENT_ID,
        "ck.message.create",
        &realm_id,
        BOB_DID,
        2,
        json!({
            "flow_id": flow_id,
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.text",
                "body": "hello alice from server b"
            }
        }),
    )?;
    let b_to_a_body = peer_events_submit_body(&realm_id, vec![bob_reply], Some("b-to-a-01"))?;
    let b_to_a_url = server_a.url("/_cokret/peer/events");
    let txn = expect_json(
        with_federation_trust_headers(
            server_a.http().post(&b_to_a_url).json(&b_to_a_body),
            "POST",
            &b_to_a_url,
            server_b,
            server_a,
            &b_to_a_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(txn["accepted"][0], BOB_MESSAGE_EVENT_ID);
    let alice_sync = expect_account_subscribe_delta(
        server_a
            .http()
            .get(server_a.url("/_cokret/self/account/subscribe?catchup=true"))
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
            .post(server_b.url("/_cokret/self/keys/upload"))
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
            .post(server_b.url("/_cokret/self/device_messages"))
            .bearer_auth(&bob)
            .header("Idempotency-Key", "federation-to-bob-01")
            .json(&json!({
                "messages": {
                    BOB_DID: {
                        "dev_bob_b": {
                            "type": "ck.mls.welcome",
                            "content": encrypted_envelope("ck.mls.welcome", "opaque-cross-server-welcome")
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
            .get(server_b.url("/_cokret/self/device_messages"))
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
            .post(server_a.url("/_cokret/self/blob/upload"))
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
                "/_cokret/self/blob/get?blob_ref={}&purpose=federation.media",
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
            .post(server_b.url("/_cokret/edge/push/register-device"))
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
            .post(server_b.url("/_cokret/self/moderation/report"))
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

async fn create_federated_realm(server: &CokretServer, alice: &str) -> Result<String> {
    let realm_id = "ck:realm:01904100-0000-7000-8000-fedc011ab001".to_owned();
    let created = submit_event(
        server,
        alice,
        ALICE_DID,
        &realm_id,
        "ck.realm.create",
        json!({
            "object": {
                "id": &realm_id,
                "schema": "ck.schema.realm.v1",
                "title": "Federated Collaboration Space",
                "summary": "cross server collaboration",
                "trust_domain": "ck:trust_domain:federation-collaboration.cotest.local",
                "created_by": ALICE_DID,
                "schema_refs": ["ck.schema.realm.v1"],
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

fn signed_federation_event(
    event_id: &str,
    kind: &str,
    realm_id: &str,
    actor_id: &str,
    actor_seq: u64,
    payload: Value,
) -> Result<Value> {
    let mut event = json!({
        "event_id": event_id,
        "kind": kind,
        "schema_id": schema_id_for_event_kind(kind),
        "actor_id": actor_id,
        "actor_seq": actor_seq,
        "realm_id": realm_id,
        "device_id": "ck:device:01904100-0000-7000-8000-fedc00000011",
        "audience": "did:web:soland.local",
        "domain": "did:web:soland.local",
        "prev_refs": [],
        "auth_refs": [],
        "payload": payload,
        "proofs": [{
            "type": "dev-proof",
            "verification_method": format!("{actor_id}#01904100-0000-7000-8000-fedc00000011"),
            "device_id": "ck:device:01904100-0000-7000-8000-fedc00000011",
            "audience": "did:web:soland.local",
            "domain": "did:web:soland.local"
        }]
    });
    event["canonical_digest"] = Value::String(event_canonical_digest(&event)?);
    Ok(event)
}

fn schema_id_for_event_kind(kind: &str) -> &'static str {
    match kind {
        "ck.member.state" => "ck.schema.member_state.v1",
        "ck.message.create" => "ck.schema.message.v1",
        _ => "ck.schema.event.v1",
    }
}

fn event_canonical_digest(event: &Value) -> Result<String> {
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
        object.remove("canonical_digest");
        object.remove("canonical_hash");
    }
    Ok(canonical_sha256(&canonical)?)
}

fn peer_events_submit_body(
    realm_id: &str,
    events: Vec<Value>,
    idempotency_key: Option<&str>,
) -> Result<Value> {
    let first_event_id = events
        .first()
        .and_then(|event| event.get("event_id"))
        .and_then(Value::as_str)
        .unwrap_or("ck:event:01904100-0000-7000-8000-fedc00000000");
    let binding_payload = json!({
        "domain": "ck.peer.events.submit.service_binding.v1",
        "realm_id": realm_id,
        "first_event_id": first_event_id,
    });
    let mut body = json!({
        "service_binding_ref": {
            "realm_id": realm_id,
            "realm_policy_digest": canonical_sha256(&binding_payload)?,
            "membership_frontier": [first_event_id],
            "delivery_binding_frontier": [first_event_id],
            "destination_service_type": "principal_server",
            "reducer_profile_digest": canonical_sha256(&json!({
                "domain": "ck.peer.events.submit.reducer_profile.v1",
                "profile": "ck.reducer.v1",
            }))?,
        },
        "events": events,
    });
    if let Some(key) = idempotency_key {
        body["idempotency_key"] = Value::String(key.to_owned());
    }
    Ok(body)
}

fn with_federation_trust_headers(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    source: &CokretServer,
    destination: &CokretServer,
    body: &Value,
) -> Result<reqwest::RequestBuilder> {
    let body_bytes = canonical_json_bytes(body)?;
    let content_digest =
        ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = canonical_sha256(body)?;
    let source_service_did = source.service_did();
    let destination_service_did = destination.service_did();
    let source_trust_domain = trust_domain_for(source_service_did);
    let destination_trust_domain = trust_domain_for(destination_service_did);

    let parsed_url = Url::parse(target_url)?;
    let authority = parsed_url
        .port()
        .map(|port| format!("{}:{port}", parsed_url.host_str().unwrap_or("server")))
        .unwrap_or_else(|| parsed_url.host_str().unwrap_or("server").to_owned());
    let path_and_query = parsed_url
        .query()
        .map(|query| format!("{}?{query}", parsed_url.path()))
        .unwrap_or_else(|| parsed_url.path().to_owned());
    let target_uri = format!("{}://{}{}", parsed_url.scheme(), authority, path_and_query);

    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = format!("{source_service_did}#federation-fanout-key");
    let signature_params = format!(
        "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
         \"source-service-did\" \"destination-service-did\" \"source-trust-domain\" \
         \"destination-trust-domain\" \"request-canonical-digest\");created={created};\
         expires={expires};keyid=\"{keyid}\";alg=\"ed25519\""
    );
    let signature_base = format!(
        "\"@method\": {}\n\
         \"@target-uri\": {target_uri}\n\
         \"@authority\": {authority}\n\
         \"content-digest\": {content_digest}\n\
         \"source-service-did\": {source_service_did}\n\
         \"destination-service-did\": {destination_service_did}\n\
         \"source-trust-domain\": {source_trust_domain}\n\
         \"destination-trust-domain\": {destination_trust_domain}\n\
         \"request-canonical-digest\": {request_canonical_digest}\n\
         \"@signature-params\": {signature_params}",
        method.to_ascii_uppercase()
    );
    let signing_key = development_service_signing_key(source_service_did);
    let signature = sign_message(signature_base.as_bytes(), &signing_key);

    Ok(builder
        .header("Content-Digest", content_digest)
        .header("Source-Service-DID", source_service_did)
        .header("Destination-Service-DID", destination_service_did)
        .header("Source-Trust-Domain", source_trust_domain)
        .header("Destination-Trust-Domain", destination_trust_domain)
        .header("Request-Canonical-Digest", request_canonical_digest)
        .header("Signature-Input", format!("sig1={signature_params}"))
        .header("Signature", format!("sig1=:{signature}:")))
}

fn trust_domain_for(service_did: &str) -> String {
    format!(
        "ck:trust_domain:{}",
        service_did.trim_start_matches("did:web:").replace(':', ".")
    )
}

fn development_service_signing_key(service_did: &str) -> cokret::http_signature::Ed25519SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:anchorer-ephemeral:");
    hasher.update(service_did.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    signing_key_from_seed(&seed)
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
