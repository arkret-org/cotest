use anyhow::{Context, Result};
use cokret::http_signature::{
    ContentDigest, ContentDigestAlgorithm, sign_message, signing_key_from_seed,
};
use cokret_core::canonical::{canonical_json_bytes, canonical_sha256, sha256_digest};
use cokret_core::{Did, Event, EventId, Hash, Hlc, Proof, RealmId, proof_kind};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::harness::{
    CokretServer, TestServerGroup, add_member, encrypted_envelope, expect_account_subscribe_delta,
    expect_json, expect_text, register_account, submit_event,
};
use crate::scenarios::_helpers::federation_binding::peer_events_submit_body;

const ALICE_DID: &str = "did:web:federation-collaboration-0.cotest.local";
const BOB_DID: &str = "did:web:federation-collaboration-1.cotest.local";
const REALM_CREATE_EVENT_ID: &str = "ck:event:01904100-0000-7000-8000-fedc011ab000";
const ALICE_MESSAGE_EVENT_ID: &str = "ck:event:01904100-0000-7000-8000-fedc00000001";
const BOB_JOIN_EVENT_ID: &str = "ck:event:01904100-0000-7000-8000-fedc00000002";
const BOB_MESSAGE_EVENT_ID: &str = "ck:event:01904100-0000-7000-8000-fedc00000003";

pub async fn cross_server_collaboration_strand_works() -> Result<()> {
    let group = TestServerGroup::multi("federation-collaboration", 2).await?;
    let server_a = group.server(0);
    let server_b = group.server(1);
    let alice = register_account(
        server_a,
        ALICE_DID,
        "@cotest-fed-alice",
        "ck:device:01904100-0000-7000-8000-0000000000a1",
    )
    .await?;
    let bob = register_account(
        server_b,
        BOB_DID,
        "@cotest-fed-bob-b",
        "ck:device:01904100-0000-7000-8000-0000000000bb",
    )
    .await?;

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
    assert_eq!(bob_document["did_document"]["document"]["id"], BOB_DID);

    let visible_services = vec![
        server_a.service_did().to_owned(),
        server_b.service_did().to_owned(),
    ];
    let realm_id = create_federated_realm(server_a, &alice, &visible_services).await?;
    add_member(server_a, &alice, ALICE_DID, &realm_id, BOB_DID).await?;
    // Federation ck.message.create Event payload carries the message
    // addressing/identity fields soland's federation projection consumes
    // (event_id, actor_id, strand_id, track_name, content). The forbidden wire
    // field `sender` is replaced by `actor_id`; Realm/membership metadata
    // (discoverability, history_visibility, members, encryption_profile, …)
    // belongs on the Realm object and `ck.member.state`, not the message.
    let strand_id = format!(
        "ck:strand:{}",
        realm_id.strip_prefix("ck:realm:").unwrap_or(&realm_id)
    );

    let realm_create = signed_federation_event(
        REALM_CREATE_EVENT_ID,
        "ck.realm.create",
        &realm_id,
        ALICE_DID,
        1,
        federated_realm_payload(&realm_id, &visible_services),
    )?;
    let alice_message = signed_federation_event(
        ALICE_MESSAGE_EVENT_ID,
        "ck.message.create",
        &realm_id,
        ALICE_DID,
        2,
        json!({
            "strand_id": strand_id.clone(),
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
        ALICE_DID,
        3,
        json!({
            "realm_id": realm_id,
            "actor_id": BOB_DID,
            "membership": "join",
            "delivery_status": "unroutable"
        }),
    )?;
    let a_to_b_body = peer_events_submit_body(
        &realm_id,
        vec![realm_create, alice_message, bob_join],
        Some("a-to-b-01"),
    )?;
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
    assert_json_array_contains(
        &pushed_to_b["accepted"],
        REALM_CREATE_EVENT_ID,
        &pushed_to_b,
    );
    assert_json_array_contains(
        &pushed_to_b["accepted"],
        ALICE_MESSAGE_EVENT_ID,
        &pushed_to_b,
    );
    assert_json_array_contains(&pushed_to_b["accepted"], BOB_JOIN_EVENT_ID, &pushed_to_b);

    let pulled_url = server_b.url(&format!("/_cokret/peer/events?realms={realm_id}"));
    let pulled_on_b = expect_json(
        with_federation_trust_headers_empty(
            server_b.http().get(&pulled_url),
            "GET",
            &pulled_url,
            server_a,
            server_b,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        pulled_on_b["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_id"] == ALICE_MESSAGE_EVENT_ID),
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
            .any(|event| event_body(event) == Some("hello bob from server a")),
        "bob sync did not include alice federation message: {bob_sync}"
    );

    let bob_reply = signed_federation_event(
        BOB_MESSAGE_EVENT_ID,
        "ck.message.create",
        &realm_id,
        BOB_DID,
        1,
        json!({
            "strand_id": strand_id,
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
    assert_json_array_contains(&txn["accepted"], BOB_MESSAGE_EVENT_ID, &txn);
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
            .any(|event| event_body(event) == Some("hello alice from server b")),
        "alice sync did not include bob federation reply: {alice_sync}"
    );

    let key_upload = expect_json(
        server_b
            .http()
            .post(server_b.url("/_cokret/self/keys/upload"))
            .bearer_auth(&bob)
            .json(&json!({
                "device_id": "ck:device:01904100-0000-7000-8000-0000000000bb",
                "one_time_keys": {
                    "signed_curve25519:bob-otk1": {
                        "algorithm": "signed_curve25519",
                        "key_id": "bob-otk1",
                        "key": "bob-one-time"
                    }
                },
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
                        "ck:device:01904100-0000-7000-8000-0000000000bb": {
                            "kind": "ck.mls.welcome",
                            "content": encrypted_envelope("ck.mls.welcome", "opaque-cross-server-welcome"),
                            "expires_at": "2026-12-31T00:00:00Z"
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
        received["messages"][0]["content"]["ciphertext"],
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
                "device_id": "ck:device:01904100-0000-7000-8000-0000000000bb",
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
                "report_reason_code": "spam",
                "reporter": BOB_DID
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "submitted");

    Ok(())
}

async fn create_federated_realm(
    server: &CokretServer,
    alice: &str,
    visible_services: &[String],
) -> Result<String> {
    let realm_id = "ck:realm:01904100-0000-7000-8000-fedc011ab001".to_owned();
    let created = submit_event(
        server,
        alice,
        ALICE_DID,
        &realm_id,
        "ck.realm.create",
        federated_realm_payload(&realm_id, visible_services),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(created["status"], "accepted");
    Ok(realm_id)
}

fn federated_realm_payload(realm_id: &str, visible_services: &[String]) -> Value {
    json!({
        "object": {
            "id": realm_id,
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
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "plaintext_visible_services": visible_services,
            "notary": {
                "type": "single_did",
                "did": ALICE_DID,
                "recovery_members": ["did:web:recovery-anchorer.cotest.local"],
                "controller_organization": "did:web:federation-collaboration.cotest.local",
                "recovery_controller_organizations": ["did:web:recovery-org.cotest.local"]
            },
            "created_at": "2026-05-02T00:00:00Z"
        }
    })
}

fn signed_federation_event(
    event_id: &str,
    kind: &str,
    realm_id: &str,
    actor_id: &str,
    actor_seq: u64,
    payload: Value,
) -> Result<Event> {
    let mut event = Event::new(
        kind,
        RealmId::new(realm_id.to_owned())
            .with_context(|| format!("invalid federation realm_id `{realm_id}`"))?,
        Did::new(actor_id.to_owned())
            .with_context(|| format!("invalid federation actor_id `{actor_id}`"))?,
        actor_seq,
        Hlc::new(format!("01970e589d21-{actor_seq:04x}-a13f9c2e"))
            .context("invalid federation event HLC")?,
        payload,
    )?;
    event.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-02T00:00:00Z")
        .context("invalid fixed federation event timestamp")?
        .with_timezone(&chrono::Utc);
    event.event_id = EventId::new(event_id.to_owned())
        .with_context(|| format!("invalid federation event_id `{event_id}`"))?;
    let event_digest =
        Hash::new(event.event_digest()?).context("invalid federation event digest")?;
    event.proofs.push(Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: format!("{actor_id}#01904100-0000-7000-8000-fedc00000011"),
        event_digest,
        created_at: event.created_at,
        domain: None,
        audience: None,
        jws: "dev-cotest-federation".to_owned(),
    });
    Ok(event)
}

fn with_federation_trust_headers(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    source: &CokretServer,
    destination: &CokretServer,
    body: &impl Serialize,
) -> Result<reqwest::RequestBuilder> {
    let body_bytes = canonical_json_bytes(body)?;
    let content_digest =
        ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = canonical_sha256(body)?;
    with_federation_trust_headers_for_digest(
        builder,
        method,
        target_url,
        source,
        destination,
        content_digest,
        request_canonical_digest,
    )
}

fn with_federation_trust_headers_empty(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    source: &CokretServer,
    destination: &CokretServer,
) -> Result<reqwest::RequestBuilder> {
    let content_digest = ContentDigest::compute(&[], ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = sha256_digest([]);
    with_federation_trust_headers_for_digest(
        builder,
        method,
        target_url,
        source,
        destination,
        content_digest,
        request_canonical_digest,
    )
}

fn with_federation_trust_headers_for_digest(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    source: &CokretServer,
    destination: &CokretServer,
    content_digest: String,
    request_canonical_digest: String,
) -> Result<reqwest::RequestBuilder> {
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
    hasher.update(b"soland:notary-ephemeral:");
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

fn event_body(event: &Value) -> Option<&str> {
    event
        .pointer("/content/body")
        .or_else(|| event.pointer("/payload/content/body"))
        .or_else(|| event.pointer("/payload/body"))
        .and_then(Value::as_str)
}

fn assert_json_array_contains(array: &Value, expected: &str, context: &Value) {
    assert!(
        array
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some(expected)),
        "expected {array} to contain {expected}; response: {context}"
    );
}
