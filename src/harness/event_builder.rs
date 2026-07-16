use std::sync::atomic::Ordering;

use anyhow::{Result, anyhow};
use arkret_core::{
    ContentBlock, DeliveryStatus, Did, EventId, Hash, InviteCreatePayload, InviteDeliveryTarget,
    InviteId, MemberDeliveryBinding, MembershipInviteRef, MembershipPayload,
    MembershipPayloadState, MessageCreatePayload, MessageId, MessageRedactPayload,
    MessageRevisePayload, RealmId, StrandId,
};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};

use super::assertions::expect_json;
use super::proof::refresh_event_proof;
use super::server::{ArkretServer, EMBEDDED_WEBVH_REGISTRATION_BEARER};
use super::{
    NEXT_EVENT_SEQ, canonical_device_id, member_join_payload, next_typed_id, realm_create_payload,
};

pub async fn register_account(
    server: &ArkretServer,
    did: &str,
    handle: &str,
    device_id: &str,
) -> Result<String> {
    register_account_with_handle(server, did, handle, None, device_id).await
}

/// Register an account and, when `published_handle` is `Some`, also publish a
/// primary localpart binding via the canonical `<localpart>:<domain>` handle.
/// soland leaves an account with no published handle when the registration
/// omits `handle`, so directory/handle assertions that expect a resolvable
/// `localpart:host` must opt in here.
pub async fn register_account_with_handle(
    server: &ArkretServer,
    did: &str,
    display_handle: &str,
    published_handle: Option<&str>,
    device_id: &str,
) -> Result<String> {
    let device_id = canonical_device_id(device_id);
    let mut body = json!({
        "principal_id": did,
        "display_name": display_handle.trim_start_matches('@'),
        "device_id": device_id
    });
    if let Some(handle) = published_handle {
        body["handle"] = json!(handle);
    }
    expect_json(
        server
            .http()
            .post(server.url("/_arkret/gate/account/register"))
            .bearer_auth(EMBEDDED_WEBVH_REGISTRATION_BEARER)
            .json(&body),
        StatusCode::OK,
    )
    .await?;

    dev_login(server, did, &device_id).await
}

pub async fn dev_login(server: &ArkretServer, actor: &str, device_id: &str) -> Result<String> {
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
    login["session_credential"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("login response did not include session_credential: {login}"))
}

pub async fn create_realm(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    title: &str,
) -> Result<String> {
    let realm_id = next_typed_id("realm");
    let payload = realm_create_payload(
        actor,
        server.service_id(),
        &realm_id,
        &json!({
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": [server.service_id()]
        }),
    );
    submit_event(
        server,
        token,
        actor,
        &realm_id,
        "ak.realm.create",
        payload,
        StatusCode::OK,
    )
    .await?;
    Ok(realm_id)
}

pub async fn add_member(
    server: &ArkretServer,
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
        "ak.member.state",
        member_join_payload(realm_id, member),
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

pub async fn send_message(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    realm_id: &str,
    _thread_id: &str,
    body: &str,
) -> Result<Value> {
    let payload = message_create_text_payload(realm_id, body)?;
    submit_event(
        server,
        token,
        actor,
        realm_id,
        "ak.message.create",
        payload,
        StatusCode::OK,
    )
    .await
}

pub async fn submit_event(
    server: &ArkretServer,
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
            .post(server.url("/_arkret/self/events"))
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
    let event_id = format!("ak:event:{suffix}");
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
            "local_operation_idempotency_alias": format!("ak:operation:{suffix}"),
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
        "ak.message.create" => {
            let strand_id = realm_id
                .strip_prefix("ak:realm:")
                .map(|suffix| format!("ak:strand:{suffix}"))
                .unwrap_or_else(|| "ak:strand:01904100-0000-7000-8000-f10dc0000001".to_owned());
            object
                .entry("strand_id".to_owned())
                .or_insert_with(|| Value::String(strand_id));
            object
                .entry("track_name".to_owned())
                .or_insert_with(|| Value::String("discussion".to_owned()));
            object.remove("thread_id");
            normalize_message_content(object);
        }
        "ak.message.revise" => {
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
        "ak.message.redact" => {
            if !object.contains_key("target_event_id") {
                if let Some(event_id) = object.get("event_id").cloned() {
                    object.insert("target_event_id".to_owned(), event_id);
                } else if let Some(target_ref) = object.get("target_ref").and_then(Value::as_str) {
                    if target_ref.starts_with("ak:event:") {
                        object.insert(
                            "target_event_id".to_owned(),
                            Value::String(target_ref.to_owned()),
                        );
                    } else if let Some(suffix) = target_ref.strip_prefix("ak:message:") {
                        object.insert(
                            "target_event_id".to_owned(),
                            Value::String(format!("ak:event:{suffix}")),
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
                "kind": "ak.content.text",
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
            Value::String("ak.content.text".to_owned()),
        );
    }
}

fn message_ref_from_event_ref(value: Value) -> Value {
    if let Some(event_id) = value.as_str()
        && let Some(suffix) = event_id.strip_prefix("ak:event:")
    {
        return Value::String(format!("ak:message:{suffix}"));
    }
    value
}

pub(crate) fn message_create_text_payload(realm_id: &str, body: &str) -> Result<Value> {
    message_create_text_payload_for_strand(strand_id_for_realm(realm_id)?, body)
}

pub(crate) fn message_create_text_payload_for_strand(
    strand_id: StrandId,
    body: &str,
) -> Result<Value> {
    let content = ContentBlock::text(body);
    MessageCreatePayload::with_content(strand_id, "discussion", content)
        .to_value()
        .map_err(|err| anyhow!("message create payload serialize: {err}"))
}

pub(crate) fn parse_strand_id(strand_id: &str) -> Result<StrandId> {
    StrandId::new(strand_id.to_owned()).map_err(|err| anyhow!("invalid strand_id: {err}"))
}

pub(crate) fn message_revise_text_payload(target_event_id: &str, body: &str) -> Result<Value> {
    serialize_payload(
        &MessageRevisePayload {
            message_id: Some(message_id_from_event_id(target_event_id)?),
            target_ref: None,
            revision_of: None,
            track_name: None,
            content: Some(ContentBlock::text(body)),
            encrypted_content: None,
            metadata: None,
            encrypted_metadata: None,
            reason: None,
        },
        "message revise payload",
    )
}

pub(crate) fn message_redact_payload(target_event_id: &str, reason: Option<&str>) -> Result<Value> {
    serialize_payload(
        &MessageRedactPayload {
            message_id: Some(message_id_from_event_id(target_event_id)?),
            target_ref: None,
            event_id: None,
            target_event_id: Some(
                EventId::new(target_event_id.to_owned())
                    .map_err(|err| anyhow!("invalid message target event_id: {err}"))?,
            ),
            track_name: None,
            reason: reason.map(ToOwned::to_owned),
            preserve: None,
        },
        "message redact payload",
    )
}

pub(crate) fn member_join_payload_value(realm_id: &str, actor_id: &str) -> Result<Value> {
    member_payload(
        realm_id,
        actor_id,
        MembershipPayloadState::Join,
        Some(DeliveryStatus::Unroutable),
        None,
        None,
        None,
    )
}

pub(crate) fn member_join_payload_with_delivery_binding(
    realm_id: &str,
    actor_id: &str,
    delivery_binding: Value,
) -> Result<Value> {
    member_payload(
        realm_id,
        actor_id,
        MembershipPayloadState::Join,
        Some(DeliveryStatus::Routable),
        Some(delivery_binding),
        None,
        None,
    )
}

pub(crate) fn member_join_payload_with_invite_ref(
    realm_id: &str,
    actor_id: &str,
    invite_ref: &str,
) -> Result<Value> {
    member_payload(
        realm_id,
        actor_id,
        MembershipPayloadState::Join,
        Some(DeliveryStatus::Unroutable),
        None,
        Some(invite_ref.to_owned()),
        None,
    )
}

pub(crate) fn member_transition_payload(
    realm_id: &str,
    actor_id: &str,
    membership: MembershipPayloadState,
    reason: Option<&str>,
) -> Result<Value> {
    member_payload(
        realm_id,
        actor_id,
        membership,
        None,
        None,
        None,
        reason.map(ToOwned::to_owned),
    )
}

pub(crate) fn invite_create_payload(
    invite_id: &str,
    invitee: &str,
    recipient_service_id: &str,
    introduction_evidence_digest: impl Into<String>,
    expires_at: DateTime<Utc>,
) -> Result<Value> {
    InviteCreatePayload::new(
        InviteId::new(invite_id.to_owned()).map_err(|err| anyhow!("invalid invite_id: {err}"))?,
        Did::new(invitee.to_owned()).map_err(|err| anyhow!("invalid invitee did: {err}"))?,
        InviteDeliveryTarget::principal_server(
            Did::new(recipient_service_id.to_owned())
                .map_err(|err| anyhow!("invalid recipient_service_id: {err}"))?,
        ),
        Hash::new(introduction_evidence_digest.into())
            .map_err(|err| anyhow!("invalid introduction_evidence_digest: {err}"))?,
        expires_at,
    )
    .to_value()
    .map_err(|err| anyhow!("invite create payload serialize: {err}"))
}

fn member_payload(
    realm_id: &str,
    actor_id: &str,
    membership: MembershipPayloadState,
    delivery_status: Option<DeliveryStatus>,
    delivery_binding: Option<Value>,
    invite_ref: Option<String>,
    reason: Option<String>,
) -> Result<Value> {
    let delivery_binding = delivery_binding
        .map(serde_json::from_value::<MemberDeliveryBinding>)
        .transpose()
        .map_err(|error| anyhow!("invalid member delivery binding: {error}"))?;
    let invite_ref = invite_ref
        .map(|value| serde_json::from_value::<MembershipInviteRef>(Value::String(value)))
        .transpose()
        .map_err(|error| anyhow!("invalid membership invite ref: {error}"))?;
    MembershipPayload {
        membership,
        strand_id: None,
        realm_id: Some(RealmId::new(realm_id.to_owned()).map_err(|err| anyhow!("{err}"))?),
        actor_id: Some(Did::new(actor_id.to_owned()).map_err(|err| anyhow!("{err}"))?),
        delivery_status,
        delivery_binding,
        gate_proofs: Vec::new(),
        via_service_ids: Vec::new(),
        reason,
        invite_ref,
    }
    .to_value()
    .map_err(|err| anyhow!("member state payload serialize: {err}"))
}

fn strand_id_for_realm(realm_id: &str) -> Result<StrandId> {
    let suffix = realm_id
        .strip_prefix("ak:realm:")
        .ok_or_else(|| anyhow!("realm_id must start with ak:realm:"))?;
    StrandId::new(format!("ak:strand:{suffix}"))
        .map_err(|err| anyhow!("invalid derived strand_id: {err}"))
}

fn message_id_from_event_id(event_id: &str) -> Result<MessageId> {
    let message_id = event_id
        .strip_prefix("ak:event:")
        .map(|suffix| format!("ak:message:{suffix}"))
        .unwrap_or_else(|| event_id.to_owned());
    MessageId::new(message_id).map_err(|err| anyhow!("invalid message_id: {err}"))
}

fn serialize_payload<T: Serialize>(payload: &T, context: &str) -> Result<Value> {
    serde_json::to_value(payload).map_err(|err| anyhow!("{context} serialize: {err}"))
}

pub fn encrypted_envelope(content_type: &str, ciphertext: &str) -> Value {
    json!({
        "scheme": "mls-rfc9420",
        "version": 1,
        "group_id": "ak:mls:test",
        "epoch": 1,
        "content_type": content_type,
        "ciphertext": ciphertext,
        "authentication_tag": "opaque-tag",
        "aad": {"suite": "test"},
        "key_ref": {"kid": "did:webvh:z6mkfixture:alice.example#device"},
        "digests": {
            "ciphertext": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    })
}
