use anyhow::{Context, Result, anyhow};
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
    CokretServer, dev_login, expect_api_error, expect_json, expect_response, submit_event,
};
use crate::scenarios::_helpers::federation_binding::peer_events_submit_body;

fn with_signed_federation_request(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    destination: &CokretServer,
    source_service_did: &str,
    body: &impl Serialize,
) -> Result<reqwest::RequestBuilder> {
    let body_bytes = canonical_json_bytes(body)?;
    let content_digest =
        ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = canonical_sha256(body)?;
    with_signed_federation_request_digests(
        builder,
        method,
        target_url,
        destination,
        source_service_did,
        content_digest,
        request_canonical_digest,
    )
}

fn with_signed_federation_empty_request(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    destination: &CokretServer,
    source_service_did: &str,
) -> Result<reqwest::RequestBuilder> {
    let content_digest = ContentDigest::compute(&[], ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = sha256_digest([]);
    with_signed_federation_request_digests(
        builder,
        method,
        target_url,
        destination,
        source_service_did,
        content_digest,
        request_canonical_digest,
    )
}

fn with_signed_federation_request_digests(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    destination: &CokretServer,
    source_service_did: &str,
    content_digest: String,
    request_canonical_digest: String,
) -> Result<reqwest::RequestBuilder> {
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
    // Bodyless GET peer reads MUST NOT carry — nor bind in their signature —
    // the body-digest components: soland rejects `content-digest` /
    // `request-canonical-digest` headers AND a Signature-Input that lists those
    // components for a GET (federation.md §3.2; peer.rs GET branch). Only
    // body-carrying requests bind the two digest components.
    let bind_body_digests = !method.eq_ignore_ascii_case("GET");
    let signature_params = if bind_body_digests {
        format!(
            "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
             \"source-service-did\" \"destination-service-did\" \"source-trust-domain\" \
             \"destination-trust-domain\" \"request-canonical-digest\");created={created};\
             expires={expires};keyid=\"{keyid}\";alg=\"ed25519\""
        )
    } else {
        format!(
            "(\"@method\" \"@target-uri\" \"@authority\" \
             \"source-service-did\" \"destination-service-did\" \"source-trust-domain\" \
             \"destination-trust-domain\");created={created};\
             expires={expires};keyid=\"{keyid}\";alg=\"ed25519\""
        )
    };
    let signature_base = if bind_body_digests {
        format!(
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
        )
    } else {
        format!(
            "\"@method\": {}\n\
             \"@target-uri\": {target_uri}\n\
             \"@authority\": {authority}\n\
             \"source-service-did\": {source_service_did}\n\
             \"destination-service-did\": {destination_service_did}\n\
             \"source-trust-domain\": {source_trust_domain}\n\
             \"destination-trust-domain\": {destination_trust_domain}\n\
             \"@signature-params\": {signature_params}",
            method.to_ascii_uppercase()
        )
    };
    let signing_key = development_service_signing_key(source_service_did);
    let signature = sign_message(signature_base.as_bytes(), &signing_key);

    let mut builder = builder
        .header("Source-Service-DID", source_service_did)
        .header("Destination-Service-DID", destination_service_did)
        .header("Source-Trust-Domain", source_trust_domain)
        .header("Destination-Trust-Domain", destination_trust_domain)
        .header("Signature-Input", format!("sig1={signature_params}"))
        .header("Signature", format!("sig1=:{signature}:"));
    if bind_body_digests {
        builder = builder
            .header("Content-Digest", content_digest)
            .header("Request-Canonical-Digest", request_canonical_digest);
    }
    Ok(builder)
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
    hasher.update(b"soland:notary-ephemeral:");
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

fn federation_realm_payload(realm_id: &str, creator: &str, visible_services: &[&str]) -> Value {
    json!({
        "object": {
            "id": realm_id,
            "schema": "ck.schema.realm.v1",
            "title": "Federation Contract Realm",
            "summary": "federation contract fixture",
            "trust_domain": trust_domain_from_service_did(creator),
            "created_by": creator,
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
                "did": creator,
                "recovery_members": ["did:web:recovery-federation-contract.cotest.local"],
                "controller_organization": creator,
                "recovery_controller_organizations": ["did:web:recovery-org-federation-contract.cotest.local"]
            },
            "created_at": "2026-05-02T00:00:00Z"
        }
    })
}

pub async fn federation_endpoints_reject_invalid_input_shapes() -> Result<()> {
    let server = CokretServer::spawn("federation-invalid").await?;

    // A body that is not even parseable JSON fails at the JSON layer and is
    // reported as `bad_json`.
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/peer/events"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_json",
    )
    .await?;
    // A well-formed JSON object that lacks the federation trust headers is
    // rejected at the inbound trust-header gate (Source-Trust-Domain missing),
    // which soland reports as `schema_violation` with minimal disclosure
    // (federation.md §3.2) — body-shape details are not leaked to an
    // unauthenticated peer.
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/peer/events"))
            .json(&json!({"operations": []})),
        StatusCode::BAD_REQUEST,
        "schema_violation",
    )
    .await?;
    expect_api_error(
        server.http().get(server.url("/_cokret/peer/events")),
        StatusCode::BAD_REQUEST,
        "schema_violation",
    )
    .await?;
    let invalid_realms_url = server.url("/_cokret/peer/events?realms=bad");
    expect_api_error(
        with_signed_federation_empty_request(
            server.http().get(&invalid_realms_url),
            "GET",
            &invalid_realms_url,
            &server,
            "did:web:invalid-shape.remote",
        )?,
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    Ok(())
}

pub async fn federation_replay_snapshot_and_redaction_contracts_work() -> Result<()> {
    let server = CokretServer::spawn("federation-replay").await?;
    let realm_id = "ck:realm:0196419b-0000-7000-8000-00000000fed0";
    let realm_create_event_id = "ck:event:0196419b-0000-7000-8000-00000000f100";
    let replay_event_id = "ck:event:0196419b-0000-7000-8000-00000000f101";
    let invalid_event_id = "ck:event:0196419b-0000-7000-8000-00000000f102";
    let redaction_event_id = "ck:event:0196419b-0000-7000-8000-00000000f103";
    let remote_service_did = "did:web:remote.example";

    let realm_create = signed_federation_event(
        realm_create_event_id,
        "ck.realm.create",
        realm_id,
        remote_service_did,
        1,
        federation_realm_payload(
            realm_id,
            remote_service_did,
            &[remote_service_did, server.service_did()],
        ),
    )?;
    let event = signed_federation_event(
        replay_event_id,
        "ck.message.create",
        realm_id,
        remote_service_did,
        2,
        json!({
            "strand_id": realm_id.replacen("ck:realm:", "ck:strand:", 1),
            "track_name": "discussion",
            "content": {"kind": "ck.content.text", "body": "from federation"}
        }),
    )?;

    let first_push_url = server.url("/_cokret/peer/events");
    let first_push_body = peer_events_submit_body(
        realm_id,
        vec![realm_create.clone(), event.clone()],
        Some("replay-1"),
    )?;
    let first_push = expect_json(
        with_signed_federation_request(
            server.http().post(&first_push_url).json(&first_push_body),
            "POST",
            &first_push_url,
            &server,
            remote_service_did,
            &first_push_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(&first_push["accepted"], realm_create_event_id, &first_push);
    assert_json_array_contains(&first_push["accepted"], replay_event_id, &first_push);
    assert!(json_array_absent_or_empty(&first_push["rejected"]));

    let pulled_url = server.url(&format!("/_cokret/peer/events?realms={realm_id}"));
    let pulled = expect_json(
        with_signed_federation_empty_request(
            server.http().get(&pulled_url),
            "GET",
            &pulled_url,
            &server,
            remote_service_did,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        peer_events_contain_event_id(&pulled["events"], replay_event_id),
        "peer pull did not include replay event: {pulled}"
    );

    let snapshot_head_url = server.url(&format!("/_cokret/peer/snapshot/head?realm_id={realm_id}"));
    expect_api_error(
        with_signed_federation_empty_request(
            server.http().get(&snapshot_head_url),
            "GET",
            &snapshot_head_url,
            &server,
            remote_service_did,
        )?,
        StatusCode::NOT_IMPLEMENTED,
        "not_implemented",
    )
    .await?;

    let replay_url = server.url("/_cokret/peer/events");
    let replay_body =
        peer_events_submit_body(realm_id, vec![realm_create, event], Some("replay-1"))?;
    let replay = expect_json(
        with_signed_federation_request(
            server.http().post(&replay_url).json(&replay_body),
            "POST",
            &replay_url,
            &server,
            remote_service_did,
            &replay_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(&replay["accepted"], replay_event_id, &replay);
    assert!(json_array_absent_or_empty(&replay["rejected"]));

    let after_replay_pull_url = server.url(&format!("/_cokret/peer/events?realms={realm_id}"));
    let after_replay_pull = expect_json(
        with_signed_federation_empty_request(
            server.http().get(&after_replay_pull_url),
            "GET",
            &after_replay_pull_url,
            &server,
            remote_service_did,
        )?,
        StatusCode::OK,
    )
    .await?;
    let after_replay_events = after_replay_pull["events"].as_array().unwrap();
    assert_eq!(
        after_replay_events
            .iter()
            .filter(|event| peer_event_id(event) == Some(replay_event_id))
            .count(),
        1,
        "idempotent federation replay must not duplicate persisted events: {}",
        serde_json::to_string_pretty(&after_replay_pull)?
    );

    let invalid_event = signed_federation_event(
        invalid_event_id,
        "ck.message.create",
        realm_id,
        remote_service_did,
        3,
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
            remote_service_did,
            &invalid_push_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert!(invalid_push["accepted"].as_array().unwrap().is_empty());
    assert_eq!(
        invalid_push["rejected"][0]["reason_code"], "schema_violation",
        "invalid encrypted federation event response: {invalid_push}"
    );

    let redaction = signed_federation_event(
        redaction_event_id,
        "ck.message.redact",
        realm_id,
        remote_service_did,
        4,
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
            remote_service_did,
            &redaction_push_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(
        &redaction_push["accepted"],
        redaction_event_id,
        &redaction_push,
    );

    let redacted_pull_url = server.url(&format!("/_cokret/peer/events?realms={realm_id}"));
    let redacted_pull = expect_json(
        with_signed_federation_empty_request(
            server.http().get(&redacted_pull_url),
            "GET",
            &redacted_pull_url,
            &server,
            remote_service_did,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        peer_events_contain_event_id(&redacted_pull["events"], replay_event_id),
        "peer history should retain the redacted target event: {redacted_pull}"
    );
    assert!(
        peer_events_contain_event_id(&redacted_pull["events"], redaction_event_id),
        "peer history should include the redaction event: {redacted_pull}"
    );

    Ok(())
}

pub async fn federation_remote_operations_project_to_sync_and_index() -> Result<()> {
    let server = CokretServer::spawn("federation-project").await?;
    let alice = dev_login(
        &server,
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-0000000000a1",
    )
    .await?;
    let realm_id = "ck:realm:0196419b-0000-7000-8000-00000000fe20";
    let created = submit_event(
        &server,
        &alice,
        "did:web:alice.example",
        realm_id,
        "ck.realm.create",
        federation_realm_payload(realm_id, "did:web:alice.example", &[server.service_did()]),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(created["status"], "accepted");

    let event_id = "ck:event:0196419b-0000-7000-8000-00000000fe22";
    let event = signed_federation_event(
        event_id,
        "ck.message.create",
        realm_id,
        "did:web:alice.example",
        100,
        json!({
            "strand_id": realm_id.replacen("ck:realm:", "ck:strand:", 1),
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
    let timeline_events = sync["realms"][realm_id]["timeline"]["events"]
        .as_array()
        .ok_or_else(|| anyhow!("sync response missing timeline events: {sync}"))?;
    if !timeline_events
        .iter()
        .any(|event| event_body(event) == Some("searchable federated payload"))
    {
        return Err(anyhow!(
            "federated realm sync did not expose projected message body: {}",
            serde_json::to_string_pretty(&sync["realms"][realm_id])?
        ));
    }

    Ok(())
}

fn peer_event_id(event: &Value) -> Option<&str> {
    event
        .get("event")
        .unwrap_or(event)
        .get("event_id")
        .and_then(Value::as_str)
}

fn peer_events_contain_event_id(events: &Value, expected: &str) -> bool {
    events.as_array().is_some_and(|events| {
        events
            .iter()
            .any(|event| peer_event_id(event) == Some(expected))
    })
}

fn event_body(event: &Value) -> Option<&str> {
    event
        .pointer("/content/body")
        .or_else(|| event.pointer("/payload/content/body"))
        .or_else(|| event.pointer("/payload/body"))
        .and_then(Value::as_str)
}

fn json_array_absent_or_empty(value: &Value) -> bool {
    value.is_null() || value.as_array().is_some_and(Vec::is_empty)
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
