use std::sync::atomic::Ordering;

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::{Value, json};

use super::assertions::expect_json;
use super::proof::refresh_event_proof;
use super::server::CokretServer;
use super::{
    NEXT_EVENT_SEQ, canonical_device_id, member_join_payload, next_typed_id, realm_create_payload,
};

pub async fn register_account(
    server: &CokretServer,
    did: &str,
    handle: &str,
    device_id: &str,
) -> Result<String> {
    let device_id = canonical_device_id(device_id);
    expect_json(
        server
            .http()
            .post(server.url("/_cokret/gate/account/register"))
            .json(&json!({
                "principal_id": did,
                "display_name": handle.trim_start_matches('@'),
                "device_id": device_id
            })),
        StatusCode::OK,
    )
    .await?;

    dev_login(server, did, &device_id).await
}

pub async fn dev_login(server: &CokretServer, actor: &str, device_id: &str) -> Result<String> {
    let device_id = canonical_device_id(device_id);
    let login = expect_json(
        server
            .http()
            .post(server.url("/_soland/gate/auth/dev-login"))
            .json(&json!({
                "actor": actor,
                "device_id": device_id,
                "display_name": device_id
            })),
        StatusCode::OK,
    )
    .await?;
    login["access_token"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("login response did not include access_token: {login}"))
}

pub async fn create_realm(
    server: &CokretServer,
    token: &str,
    actor: &str,
    title: &str,
) -> Result<String> {
    let realm_id = next_typed_id("realm");
    let payload = realm_create_payload(
        actor,
        server.service_did(),
        &realm_id,
        &json!({
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": [server.service_did()]
        }),
    );
    submit_event(
        server,
        token,
        actor,
        &realm_id,
        "ck.realm.create",
        payload,
        StatusCode::OK,
    )
    .await?;
    Ok(realm_id)
}

pub async fn add_member(
    server: &CokretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
    member: &str,
) -> Result<()> {
    submit_event(
        server,
        token,
        actor,
        realm_id,
        "ck.member.state",
        member_join_payload(realm_id, member),
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

pub async fn send_message(
    server: &CokretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
    thread_id: &str,
    body: &str,
) -> Result<Value> {
    submit_event(
        server,
        token,
        actor,
        realm_id,
        "ck.message.create",
        json!({
            "body": body,
            "content": {"body": body},
            "thread_id": thread_id,
        }),
        StatusCode::OK,
    )
    .await
}

pub async fn submit_event(
    server: &CokretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
    kind: &str,
    payload: Value,
    status: StatusCode,
) -> Result<Value> {
    let event = event_envelope(actor, realm_id, kind, payload);
    let mut body = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/events"))
            .bearer_auth(token)
            .json(&event),
        status,
    )
    .await?;
    if status.is_success() {
        ensure_submit_event_id(&mut body, &event);
    }
    Ok(body)
}

pub fn event_envelope(actor: &str, realm_id: &str, kind: &str, mut payload: Value) -> Value {
    let seq = NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let hlc_logical = seq & 0xffff;
    let suffix = format!("01999999-0000-7000-8000-{seq:012x}");
    let event_id = format!("ck:event:{suffix}");
    normalize_message_payload(kind, realm_id, &mut payload);
    let mut event = json!({
        "event_id": event_id,
        "kind": kind,
        "realm_id": realm_id,
        "actor_id": actor,
        "actor_seq": seq,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": format!("01970e589d21-{hlc_logical:04x}-a13f9c2e"),
        "prev_refs": [],
        "refs": [],
        "payload": payload,
        "unsigned": {
            "local_operation_idempotency_alias": format!("ck:operation:{suffix}"),
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor}#cotest"),
            "event_digest": "",
            "created_at": "2026-05-02T00:00:00Z",
            "jws": "a..b",
        }],
    });
    refresh_event_proof(&mut event);
    event
}

fn normalize_message_payload(kind: &str, realm_id: &str, payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };

    match kind {
        "ck.message.create" => {
            let strand_id = realm_id
                .strip_prefix("ck:realm:")
                .map(|suffix| format!("ck:strand:{suffix}"))
                .unwrap_or_else(|| "ck:strand:01904100-0000-7000-8000-f10dc0000001".to_owned());
            object
                .entry("strand_id".to_owned())
                .or_insert_with(|| Value::String(strand_id));
            object
                .entry("track_name".to_owned())
                .or_insert_with(|| Value::String("discussion".to_owned()));
            object.remove("thread_id");
            normalize_message_content(object);
        }
        "ck.message.revise" => {
            if let Some(target_event_id) = object.remove("target_event_id")
                && !object.contains_key("target_ref")
                && !object.contains_key("message_id")
                && !object.contains_key("revision_of")
            {
                object.insert(
                    "target_ref".to_owned(),
                    message_ref_from_event_ref(target_event_id),
                );
            }
            object.remove("thread_id");
            normalize_message_content(object);
        }
        "ck.message.redact" => {
            if !object.contains_key("target_event_id") {
                if let Some(event_id) = object.get("event_id").cloned() {
                    object.insert("target_event_id".to_owned(), event_id);
                } else if let Some(target_ref) = object.get("target_ref").and_then(Value::as_str) {
                    if target_ref.starts_with("ck:event:") {
                        object.insert(
                            "target_event_id".to_owned(),
                            Value::String(target_ref.to_owned()),
                        );
                    } else if let Some(suffix) = target_ref.strip_prefix("ck:message:") {
                        object.insert(
                            "target_event_id".to_owned(),
                            Value::String(format!("ck:event:{suffix}")),
                        );
                    }
                }
            }
            object.remove("thread_id");
        }
        _ => {}
    }
}

pub(crate) fn ensure_submit_event_id(body: &mut Value, event: &Value) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    if object.contains_key("event_id") {
        return;
    }
    let accepted_id = object
        .get("accepted")
        .and_then(Value::as_array)
        .and_then(|accepted| accepted.first())
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let event_id = accepted_id.or_else(|| {
        event
            .get("event_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    });
    if let Some(event_id) = event_id {
        object.insert("event_id".to_owned(), Value::String(event_id));
    }
}

fn normalize_message_content(object: &mut serde_json::Map<String, Value>) {
    let body = object.remove("body");
    if !object.contains_key("content")
        && let Some(body) = body
    {
        object.insert(
            "content".to_owned(),
            json!({
                "kind": "ck.content.text",
                "body": body,
            }),
        );
    }
    if let Some(content) = object.get_mut("content").and_then(Value::as_object_mut)
        && content.get("kind").is_none()
        && content.get("body").is_some()
    {
        content.insert(
            "kind".to_owned(),
            Value::String("ck.content.text".to_owned()),
        );
    }
}

fn message_ref_from_event_ref(value: Value) -> Value {
    if let Some(event_id) = value.as_str()
        && let Some(suffix) = event_id.strip_prefix("ck:event:")
    {
        return Value::String(format!("ck:message:{suffix}"));
    }
    value
}

pub fn encrypted_envelope(content_type: &str, ciphertext: &str) -> Value {
    json!({
        "scheme": "mls-rfc9420",
        "version": 1,
        "group_id": "ck:mls:test",
        "epoch": 1,
        "content_type": content_type,
        "ciphertext": ciphertext,
        "authentication_tag": "opaque-tag",
        "aad": {"suite": "test"},
        "key_ref": {"kid": "did:web:alice.example#device"},
        "digests": {
            "ciphertext": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    })
}
