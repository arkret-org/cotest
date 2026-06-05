use anyhow::{Context, Result, anyhow};
use cokret::http_signature::{
    ContentDigest, ContentDigestAlgorithm, sign_message, signing_key_from_seed,
};
use cokret_core::canonical::{canonical_json_bytes, canonical_sha256};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::harness::{CokretServer, dev_login, expect_api_error, expect_json, expect_response};

fn with_signed_federation_request(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    destination: &CokretServer,
    source_service_did: &str,
    body: &Value,
) -> Result<reqwest::RequestBuilder> {
    let body_bytes = canonical_json_bytes(body)?;
    let content_digest =
        ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = canonical_sha256(body)?;
    let source_trust_domain = trust_domain_from_service_did(source_service_did);
    let destination_service_did = destination.service_did();
    let destination_trust_domain = trust_domain_from_service_did(destination_service_did);

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

fn trust_domain_from_service_did(service_did: &str) -> String {
    let scope = service_did
        .strip_prefix("did:web:")
        .or_else(|| service_did.strip_prefix("did:key:"))
        .or_else(|| service_did.strip_prefix("did:webvh:"))
        .unwrap_or(service_did)
        .to_ascii_lowercase()
        .replace(':', ".");
    format!("ck:trust_domain:{scope}")
}

fn development_service_signing_key(service_did: &str) -> cokret::http_signature::Ed25519SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:anchorer-ephemeral:");
    hasher.update(service_did.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    signing_key_from_seed(&seed)
}

fn account_delta_from_text(ndjson: &str) -> Result<Value> {
    for line in ndjson
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let frame: Value = serde_json::from_str(line)
            .with_context(|| format!("invalid subscribe frame: {line}"))?;
        if frame.get("kind").and_then(Value::as_str) == Some("delta") {
            return Ok(frame.get("payload").cloned().unwrap_or(frame));
        }
    }
    Err(anyhow!(
        "account subscribe response did not include a delta frame"
    ))
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
        "ck.message.redact" => "ck.schema.redaction.v1",
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

pub async fn federation_endpoints_reject_invalid_input_shapes() -> Result<()> {
    let server = CokretServer::spawn("federation-invalid").await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/peer/events"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/peer/events"))
            .json(&json!({"operations": []})),
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await?;
    expect_api_error(
        server.http().get(server.url("/_cokret/peer/events")),
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/_cokret/peer/events?realms=bad")),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    Ok(())
}

pub async fn federation_replay_snapshot_and_redaction_contracts_work() -> Result<()> {
    let server = CokretServer::spawn("federation-replay").await?;
    let realm_id = "ck:realm:0196419b-0000-7000-8000-00000000fed0";
    let replay_event_id = "ck:event:0196419b-0000-7000-8000-00000000f101";
    let invalid_event_id = "ck:event:0196419b-0000-7000-8000-00000000f102";
    let redaction_event_id = "ck:event:0196419b-0000-7000-8000-00000000f103";

    let event = signed_federation_event(
        replay_event_id,
        "ck.message.create",
        realm_id,
        "did:web:remote.example",
        1,
        json!({
            "flow_id": realm_id.replacen("ck:realm:", "ck:flow:", 1),
            "track_name": "discussion",
            "content": {"kind": "ck.content.text", "body": "from federation"}
        }),
    )?;

    let first_push_url = server.url("/_cokret/peer/events");
    let first_push_body = peer_events_submit_body(realm_id, vec![event.clone()], Some("replay-1"))?;
    let first_push = expect_json(
        with_signed_federation_request(
            server.http().post(&first_push_url).json(&first_push_body),
            "POST",
            &first_push_url,
            &server,
            "did:web:remote.example",
            &first_push_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first_push["accepted"][0], replay_event_id);
    assert!(first_push["rejected"].as_array().unwrap().is_empty());

    let pulled = expect_json(
        server
            .http()
            .get(server.url(&format!("/_cokret/peer/events?realms={realm_id}"))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(pulled["events"][0]["event"]["event_id"], replay_event_id);

    let bootstrap = expect_json(
        server
            .http()
            .get(server.url(&format!("/_cokret/peer/snapshot/head?realm_id={realm_id}"))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(bootstrap["realm_id"], realm_id);
    assert!(
        bootstrap["state_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let replay_url = server.url("/_cokret/peer/events");
    let replay_body = peer_events_submit_body(realm_id, vec![event], Some("replay-1"))?;
    let replay = expect_json(
        with_signed_federation_request(
            server.http().post(&replay_url).json(&replay_body),
            "POST",
            &replay_url,
            &server,
            "did:web:remote.example",
            &replay_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(replay["accepted"][0], replay_event_id);
    assert!(replay["rejected"].as_array().unwrap().is_empty());

    let after_replay_pull = expect_json(
        server
            .http()
            .get(server.url(&format!("/_cokret/peer/events?realms={realm_id}"))),
        StatusCode::OK,
    )
    .await?;
    let after_replay_events = after_replay_pull["events"].as_array().unwrap();
    assert_eq!(
        after_replay_events.len(),
        1,
        "idempotent federation replay must not duplicate persisted events: {}",
        serde_json::to_string_pretty(&after_replay_pull)?
    );
    assert_eq!(after_replay_events[0]["event"]["event_id"], replay_event_id);

    let invalid_event = signed_federation_event(
        invalid_event_id,
        "ck.message.create",
        realm_id,
        "did:web:remote.example",
        2,
        json!({
            "encrypted": true,
            "content": {"ciphertext": "missing-envelope-fields"}
        }),
    )?;
    let invalid_push_url = server.url("/_cokret/peer/events");
    let invalid_push_body =
        peer_events_submit_body(realm_id, vec![invalid_event], Some("invalid-1"))?;
    let invalid_push = expect_json(
        with_signed_federation_request(
            server
                .http()
                .post(&invalid_push_url)
                .json(&invalid_push_body),
            "POST",
            &invalid_push_url,
            &server,
            "did:web:remote.example",
            &invalid_push_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert!(invalid_push["accepted"].as_array().unwrap().is_empty());
    assert_eq!(
        invalid_push["rejected"][0]["reason_code"],
        "invalid_semantics"
    );

    let redaction = signed_federation_event(
        redaction_event_id,
        "ck.message.redact",
        realm_id,
        "did:web:remote.example",
        3,
        json!({
            "target_event_id": replay_event_id
        }),
    )?;
    let redaction_push_url = server.url("/_cokret/peer/events");
    let redaction_push_body =
        peer_events_submit_body(realm_id, vec![redaction], Some("redaction-1"))?;
    let redaction_push = expect_json(
        with_signed_federation_request(
            server
                .http()
                .post(&redaction_push_url)
                .json(&redaction_push_body),
            "POST",
            &redaction_push_url,
            &server,
            "did:web:remote.example",
            &redaction_push_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(redaction_push["accepted"][0], redaction_event_id);

    let redacted_pull = expect_json(
        server
            .http()
            .get(server.url(&format!("/_cokret/peer/events?realms={realm_id}"))),
        StatusCode::OK,
    )
    .await?;
    assert!(redacted_pull["events"].as_array().unwrap().is_empty());

    Ok(())
}

pub async fn federation_remote_operations_project_to_sync_and_index() -> Result<()> {
    let server = CokretServer::spawn("federation-project").await?;
    let alice = dev_login(&server, "did:web:alice.example", "dev_alice").await?;
    let realm_id = "ck:realm:0196419b-0000-7000-8000-00000000fe20";
    let event_id = "ck:event:0196419b-0000-7000-8000-00000000fe22";
    let event = signed_federation_event(
        event_id,
        "ck.message.create",
        realm_id,
        "did:web:alice.example",
        1,
        json!({
            "flow_id": realm_id.replacen("ck:realm:", "ck:flow:", 1),
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.text",
                "body": "searchable federated payload",
                "format": "plain"
            }
        }),
    )?;

    let txn_url = server.url("/_cokret/peer/events");
    let txn_body = peer_events_submit_body(realm_id, vec![event], Some("project-1"))?;
    let txn = expect_json(
        with_signed_federation_request(
            server.http().post(&txn_url).json(&txn_body),
            "POST",
            &txn_url,
            &server,
            "did:web:remote-server.example",
            &txn_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    if txn["accepted"][0] != event_id {
        return Err(anyhow!(
            "federation project message event was not accepted: {}",
            serde_json::to_string_pretty(&txn)?
        ));
    }

    let sync_response = expect_response(
        server
            .http()
            .get(server.url("/_cokret/self/account/subscribe?catchup=true"))
            .bearer_auth(&alice)
            .header("accept", "application/x-ndjson"),
        StatusCode::OK,
    )
    .await?;
    let sync = account_delta_from_text(&sync_response.text())?;
    let synced_body = &sync["realms"][realm_id]["timeline"]["events"][0]["content"]["body"];
    if synced_body != "searchable federated payload" {
        return Err(anyhow!(
            "federated realm sync did not expose projected message body: {}",
            serde_json::to_string_pretty(&sync["realms"][realm_id])?
        ));
    }

    Ok(())
}
