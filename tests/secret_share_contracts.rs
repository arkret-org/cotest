use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret_canonical::{canonical_json_bytes, from_canonical_json_slice};
use arkret_crypto::secret_share::{SecretShareRequestContent, SecretShareSendContent};
use arkret_identifiers::{DeviceId, DeviceMessageId, DidCoreId};
use arkret_models_collaboration::sync_frames::account_sync::{
    DeviceMessageEnvelope, DeviceMessageSender, DeviceMessageTarget, DeviceMessagesSendRequestBody,
};
use arkret_wire::{
    HPKE_SUITE_X25519_CHACHA20POLY1305_V1, ProtocolKind, SECRET_REQUEST_KIND, SECRET_SEND_KIND,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use serde_json::{Value, json};

const ACCOUNT_ID: &str = "ak:did_core:web:alice.example";
const OLD_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000a";
const NEW_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000b";
const OTHER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000000c";
const REQUEST_ID: &str = "secret-share-request-001";
const SECRET_ID: &str = "inkson_mls_account_secret";
const EXPIRES_AT: &str = "2026-06-10T00:30:00.000Z";
const ACCOUNT_SECRET: &str = "base64url-account-mls-root-secret";

#[derive(Clone, Debug)]
struct PendingRequest {
    request_id: String,
    secret_id: String,
    recipient_private_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OpenedSecret {
    account_secret: String,
    secret_version: u32,
}

#[derive(Clone, Debug)]
struct HpkeSealed {
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[test]
fn d2d_root_secret_share_uses_typed_device_message_wire_and_hpke() -> Result<()> {
    let (requester_sk, requester_pk) = derive_keypair(0x42)?;
    let request = PendingRequest {
        request_id: REQUEST_ID.to_owned(),
        secret_id: SECRET_ID.to_owned(),
        recipient_private_key: requester_sk,
    };

    let request_content = request_content(&request, &requester_pk)?;
    let request_target = DeviceMessageTarget {
        message_id: DeviceMessageId::new("ak:device_message:0196419b-0000-7000-8000-000000000091")?,
        kind: ProtocolKind::new(SECRET_REQUEST_KIND).map_err(anyhow::Error::msg)?,
        content: serde_json::from_value(serde_json::to_value(&request_content)?)?,
        expires_at: parse_utc(EXPIRES_AT)?,
    };
    let request_body = device_message_body(device_id(OLD_DEVICE)?, request_target)?;
    let request_value = serde_json::to_value(&request_body)?;

    assert_eq!(
        request_value.pointer(
            "/messages/ak:did_core:web:alice.example/ak:device:01904100-0000-7000-8000-00000000000a/kind"
        ),
        Some(&json!(SECRET_REQUEST_KIND))
    );
    assert_eq!(
        request_value.pointer("/messages/ak:did_core:web:alice.example/ak:device:01904100-0000-7000-8000-00000000000a/content/secret_id"),
        Some(&json!(SECRET_ID))
    );
    assert!(request_value.get("type").is_none());
    assert!(request_value.get("event").is_none());

    let parsed_request: SecretShareRequestContent = serde_json::from_value(
        request_value["messages"][ACCOUNT_ID][OLD_DEVICE]["content"].clone(),
    )?;
    assert_eq!(parsed_request.request_id, REQUEST_ID);
    assert_eq!(parsed_request.secret_id, SECRET_ID);
    assert_eq!(parsed_request.from_device, device_id(NEW_DEVICE)?);

    let send_content = seal_secret_send(&parsed_request, ACCOUNT_SECRET, 7, EXPIRES_AT)?;
    let send_target = DeviceMessageTarget {
        message_id: DeviceMessageId::new("ak:device_message:0196419b-0000-7000-8000-000000000092")?,
        kind: ProtocolKind::new(SECRET_SEND_KIND).map_err(anyhow::Error::msg)?,
        content: serde_json::from_value(serde_json::to_value(&send_content)?)?,
        expires_at: parse_utc(EXPIRES_AT)?,
    };
    let send_body = device_message_body(device_id(NEW_DEVICE)?, send_target)?;
    let send_value = serde_json::to_value(&send_body)?;
    let content = &send_value["messages"][ACCOUNT_ID][NEW_DEVICE]["content"];

    assert_eq!(content["scheme"], HPKE_SUITE_X25519_CHACHA20POLY1305_V1);
    assert_eq!(content["request_id"], REQUEST_ID);
    assert_eq!(content["secret_id"], SECRET_ID);
    assert!(content.get("account_secret").is_none());
    assert!(content.get("secret_version").is_none());
    assert!(content.get("plaintext").is_none());

    let envelope = materialized_send_envelope(content.clone(), EXPIRES_AT)?;
    let opened = open_secret_send(&request, &envelope)?;
    assert_eq!(
        opened,
        OpenedSecret {
            account_secret: ACCOUNT_SECRET.to_owned(),
            secret_version: 7,
        }
    );

    let mut keys = BTreeSet::new();
    for key in send_value["messages"][ACCOUNT_ID][NEW_DEVICE]
        .as_object()
        .ok_or_else(|| anyhow!("secret send target is not an object"))?
        .keys()
    {
        keys.insert(key.as_str());
    }
    assert_eq!(
        keys,
        BTreeSet::from(["content", "expires_at", "kind", "message_id"])
    );

    Ok(())
}

#[test]
fn d2d_root_secret_share_rejects_unsolicited_or_tampered_sends() -> Result<()> {
    let (requester_sk, requester_pk) = derive_keypair(0x43)?;
    let request = PendingRequest {
        request_id: REQUEST_ID.to_owned(),
        secret_id: SECRET_ID.to_owned(),
        recipient_private_key: requester_sk,
    };
    let parsed_request = request_content(&request, &requester_pk)?;
    let send = seal_secret_send(&parsed_request, ACCOUNT_SECRET, 3, EXPIRES_AT)?;
    let envelope = materialized_send_envelope(serde_json::to_value(&send)?, EXPIRES_AT)?;

    let unsolicited = PendingRequest {
        request_id: "different-request".to_owned(),
        secret_id: SECRET_ID.to_owned(),
        recipient_private_key: request.recipient_private_key.clone(),
    };
    let err = open_secret_send(&unsolicited, &envelope).unwrap_err();
    assert!(format!("{err}").contains("unsolicited"));

    let wrong_secret = PendingRequest {
        request_id: REQUEST_ID.to_owned(),
        secret_id: "some_other_secret".to_owned(),
        recipient_private_key: request.recipient_private_key.clone(),
    };
    let err = open_secret_send(&wrong_secret, &envelope).unwrap_err();
    assert!(format!("{err}").contains("secret_id"));

    let mut wrong_sender = envelope.clone();
    wrong_sender.sender = DeviceMessageSender::Device {
        sender_device_id: device_id(OTHER_DEVICE)?,
    };
    assert!(open_secret_send(&request, &wrong_sender).is_err());

    let mut wrong_recipient = envelope.clone();
    wrong_recipient.recipient_device_id = device_id(OTHER_DEVICE)?;
    assert!(open_secret_send(&request, &wrong_recipient).is_err());

    let mut wrong_scheme = envelope.clone();
    wrong_scheme.content.insert(
        "scheme".to_owned(),
        json!("ak.hpke_x25519_aead_aesgcm128.v1"),
    );
    let err = open_secret_send(&request, &wrong_scheme).unwrap_err();
    assert!(format!("{err}").contains("scheme"));

    Ok(())
}

#[test]
fn d2d_root_secret_aad_requires_canonical_millisecond_timestamps() -> Result<()> {
    let (requester_sk, requester_pk) = derive_keypair(0x44)?;
    let request = PendingRequest {
        request_id: REQUEST_ID.to_owned(),
        secret_id: SECRET_ID.to_owned(),
        recipient_private_key: requester_sk,
    };
    let parsed_request = request_content(&request, &requester_pk)?;
    let send = seal_secret_send(&parsed_request, ACCOUNT_SECRET, 11, EXPIRES_AT)?;
    let envelope = materialized_send_envelope(serde_json::to_value(&send)?, EXPIRES_AT)?;

    let opened = open_secret_send(&request, &envelope)?;
    assert_eq!(opened.secret_version, 11);
    assert!(
        send_aad(OLD_DEVICE, NEW_DEVICE, "2026-06-10T00:30:00+00:00").is_err(),
        "non-canonical RFC 3339 spelling must not enter the signed AAD"
    );
    Ok(())
}

fn request_content(
    request: &PendingRequest,
    recipient_pk: &[u8],
) -> Result<SecretShareRequestContent> {
    Ok(SecretShareRequestContent {
        request_id: request.request_id.clone(),
        secret_id: request.secret_id.clone(),
        from_device: device_id(NEW_DEVICE)?,
        recipient_hpke_public_key: URL_SAFE_NO_PAD.encode(recipient_pk),
    })
}

fn seal_secret_send(
    request: &SecretShareRequestContent,
    secret: &str,
    secret_version: u32,
    expires_at: &str,
) -> Result<SecretShareSendContent> {
    if request.secret_id != SECRET_ID {
        bail!("unsupported secret_id");
    }
    let recipient_pk = URL_SAFE_NO_PAD.decode(request.recipient_hpke_public_key.as_bytes())?;
    let plaintext = secret_plaintext(secret, secret_version, &request.request_id)?;
    let aad = send_aad(OLD_DEVICE, request.from_device.as_str(), expires_at)?;
    let sealed = hpke_seal(
        &recipient_pk,
        arkret_wire::SECRET_SHARE_HPKE_INFO,
        &aad,
        &plaintext,
    )?;
    Ok(SecretShareSendContent {
        request_id: request.request_id.clone(),
        secret_id: request.secret_id.clone(),
        from_device: device_id(OLD_DEVICE)?,
        scheme: HPKE_SUITE_X25519_CHACHA20POLY1305_V1.to_owned(),
        enc: URL_SAFE_NO_PAD.encode(sealed.enc),
        ciphertext: URL_SAFE_NO_PAD.encode(sealed.ciphertext),
    })
}

fn open_secret_send(
    request: &PendingRequest,
    envelope: &DeviceMessageEnvelope,
) -> Result<OpenedSecret> {
    if envelope.kind != SECRET_SEND_KIND {
        bail!("not a ak.secret.send envelope");
    }
    let content: SecretShareSendContent =
        serde_json::from_value(serde_json::to_value(&envelope.content)?)?;
    if content.request_id != request.request_id {
        bail!("unsolicited ak.secret.send");
    }
    if content.secret_id != request.secret_id || content.secret_id != SECRET_ID {
        bail!("unsupported ak.secret.send secret_id");
    }
    // `ak.secret.send` is a device-to-device secret transfer, so the envelope
    // MUST carry the `device` sender branch: an Agent runtime has no device
    // identity to match `from_device` against.
    let sender_device_id = envelope
        .sender
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("ak.secret.send envelope has no sender device"))?;
    if &content.from_device != sender_device_id {
        bail!("ak.secret.send from_device does not match envelope sender");
    }
    if content.scheme != HPKE_SUITE_X25519_CHACHA20POLY1305_V1 {
        bail!("unsupported ak.secret.send scheme");
    }

    let aad = send_aad(
        sender_device_id.as_str(),
        envelope.recipient_device_id.as_str(),
        &arkret_canonical::format_timestamp_canonical(envelope.expires_at),
    )?;
    let enc = URL_SAFE_NO_PAD.decode(content.enc.as_bytes())?;
    let ciphertext = URL_SAFE_NO_PAD.decode(content.ciphertext.as_bytes())?;
    let plaintext = hpke_open(
        &request.recipient_private_key,
        &enc,
        arkret_wire::SECRET_SHARE_HPKE_INFO,
        &aad,
        &ciphertext,
    )?;
    let parsed: Value = from_canonical_json_slice(&plaintext)?;

    if parsed.get("request_id").and_then(Value::as_str) != Some(request.request_id.as_str()) {
        bail!("secret-share plaintext request_id mismatch");
    }
    if parsed.get("secret_id").and_then(Value::as_str) != Some(SECRET_ID) {
        bail!("secret-share plaintext secret_id mismatch");
    }
    let account_secret = parsed
        .get("account_secret")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("secret-share plaintext missing account_secret"))?
        .to_owned();
    let secret_version = parsed
        .get("secret_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("secret-share plaintext missing secret_version"))?
        .try_into()?;

    Ok(OpenedSecret {
        account_secret,
        secret_version,
    })
}

fn secret_plaintext(secret: &str, secret_version: u32, request_id: &str) -> Result<Vec<u8>> {
    Ok(canonical_json_bytes(&json!({
        "account_secret": secret,
        "secret_version": secret_version,
        "request_id": request_id,
        "secret_id": SECRET_ID,
    }))?)
}

fn send_aad(
    sender_device_id: &str,
    recipient_device_id: &str,
    expires_at: &str,
) -> Result<Vec<u8>> {
    arkret_canonical::validate_timestamp_canonical(expires_at)?;
    Ok(canonical_json_bytes(&json!({
        "kind": SECRET_SEND_KIND,
        "sender_principal_id": ACCOUNT_ID,
        "sender_device_id": sender_device_id,
        "recipient_principal_id": ACCOUNT_ID,
        "recipient_device_id": recipient_device_id,
        "expires_at": expires_at,
    }))?)
}

fn device_message_body(
    recipient_device_id: DeviceId,
    target: DeviceMessageTarget,
) -> Result<DeviceMessagesSendRequestBody> {
    let mut by_device = BTreeMap::new();
    by_device.insert(recipient_device_id, target);
    let mut messages = BTreeMap::new();
    messages.insert(DidCoreId::new(ACCOUNT_ID.to_owned())?, by_device);
    Ok(DeviceMessagesSendRequestBody { messages })
}

fn materialized_send_envelope(content: Value, expires_at: &str) -> Result<DeviceMessageEnvelope> {
    Ok(DeviceMessageEnvelope {
        message_id: DeviceMessageId::new("ak:device_message:0196419b-0000-7000-8000-000000000099")?,
        kind: ProtocolKind::new(SECRET_SEND_KIND).map_err(anyhow::Error::msg)?,
        sender_principal_id: DidCoreId::new(ACCOUNT_ID.to_owned())?,
        sender: DeviceMessageSender::Device {
            sender_device_id: device_id(OLD_DEVICE)?,
        },
        recipient_principal_id: DidCoreId::new(ACCOUNT_ID.to_owned())?,
        recipient_device_id: device_id(NEW_DEVICE)?,
        sent_at: parse_utc("2026-06-10T00:00:00.000Z")?,
        expires_at: parse_utc(expires_at)?,
        content: serde_json::from_value(content)?,
        device_proof: None,
        unsigned: None,
    })
}

fn parse_utc(value: &str) -> Result<DateTime<Utc>> {
    Ok(arkret_canonical::parse_timestamp_canonical(value)?)
}

fn device_id(value: &str) -> Result<DeviceId> {
    Ok(DeviceId::new(value.to_owned())?)
}

fn suite() -> Hpke<HpkeRustCrypto> {
    Hpke::<HpkeRustCrypto>::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

fn derive_keypair(seed: u8) -> Result<(Vec<u8>, Vec<u8>)> {
    let ikm = [seed; 32];
    let keypair = suite()
        .derive_key_pair(&ikm)
        .map_err(|err| anyhow!("hpke derive key pair: {err:?}"))?;
    let (sk, pk) = keypair.into_keys();
    Ok((sk.as_slice().to_vec(), pk.as_slice().to_vec()))
}

fn hpke_seal(
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed> {
    let mut hpke = suite();
    let pk = HpkePublicKey::new(recipient_public_key.to_vec());
    let (enc, ciphertext) = hpke
        .seal(&pk, info, aad, plaintext, None, None, None)
        .map_err(|err| anyhow!("hpke seal: {err:?}"))?;
    Ok(HpkeSealed { enc, ciphertext })
}

fn hpke_open(
    recipient_private_key: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let hpke = suite();
    let sk = HpkePrivateKey::new(recipient_private_key.to_vec());
    hpke.open(enc, &sk, info, aad, ciphertext, None, None, None)
        .map_err(|err| anyhow!("hpke open: {err:?}"))
}
