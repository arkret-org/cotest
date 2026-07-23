//! Media AEAD nonce conformance vectors.
//!
//! Covers the v1 deterministic sender nonce prefix contract from
//! `zh/conformance/encoding.md` section 10.1.

use anyhow::{Result, anyhow, bail};
use arkret_crypto::{
    AEAD_NONCE_AES_GCM_LEN, AEAD_NONCE_EXPORTER_LABEL, AEAD_NONCE_XCHACHA20_POLY1305_LEN,
    AEAD_PROFILE_AES_256_GCM, AEAD_PROFILE_XCHACHA20_POLY1305, AeadNonceContext,
    AeadNonceReplayTracker, Error, compose_aead_nonce, derive_aead_sender_nonce_prefix,
    verify_aead_nonce_derivation, verify_aead_sender_nonce,
};
use serde_json::{Value, json};

pub const VECTOR_ID_AEAD_NONCE_SENDER_DOMAIN_COLLISION: &str =
    "ak.vector.media.aead_nonce_sender_domain_collision.v1";
pub const VECTOR_ID_AEAD_NONCE_COUNTER_REPLAY: &str =
    "ak.vector.media.aead_nonce_counter_replay.v1";
pub const VECTOR_ID_AEAD_NONCE_RANDOM_REJECTED: &str =
    "ak.vector.media.aead_nonce_random_rejected.v1";

pub const ALL_MEDIA_AEAD_NONCE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_AEAD_NONCE_SENDER_DOMAIN_COLLISION,
    VECTOR_ID_AEAD_NONCE_COUNTER_REPLAY,
    VECTOR_ID_AEAD_NONCE_RANDOM_REJECTED,
];

const MEDIA_AEAD_NONCE_FIXTURE_FILE: &str = "media-aead-nonce-fixture.json";
const MEDIA_AEAD_NONCE_PROFILE: &str = "ak.profile.e2ee_client.v1";
const DEVICE_ONE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
const DEVICE_TWO: &str = "ak:device:01964137-0000-7000-8000-000000000002";
const PURPOSE_MESSAGE_PAYLOAD: &str = "ak.message.encrypted_payload";
// Golden derived from the current SDK's canonical key_ref/epoch/device/purpose
// transcript (the context binding was tightened in the v1 encoder update).
const EXPECTED_DEVICE_ONE_XCHACHA_PREFIX_HEX: &str = "5d62cff5f7a7befee1e39e3dc287cb67";
const EXPORTER_SECRET: [u8; 32] = [0x24u8; 32];

fn validate_media_aead_nonce_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(MEDIA_AEAD_NONCE_FIXTURE_FILE)?;
    super::validate_profile(&fixture, MEDIA_AEAD_NONCE_PROFILE)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("media AEAD nonce fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("media AEAD nonce fixture missing cases[]"))?;

    for vector_id in ALL_MEDIA_AEAD_NONCE_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("media AEAD nonce fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("media AEAD nonce fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

fn nonce_context(device_id: &str, aead_profile: &str) -> AeadNonceContext {
    AeadNonceContext {
        key_ref: json!({
            "algorithm": "MLS",
            "group_state_ref": "ak:event:01964148-0000-7000-8000-000000000000"
        }),
        epoch: 42,
        device_id: device_id.to_owned(),
        purpose: PURPOSE_MESSAGE_PAYLOAD.to_owned(),
        aead_profile: aead_profile.to_owned(),
    }
}

fn protocol_reason(error: Error) -> Result<String> {
    match error {
        Error::Protocol(message) => Ok(message.split(':').next().unwrap_or("").to_owned()),
        other => bail!("expected protocol error, got {other:?}"),
    }
}

fn expect_reason(error: Error, expected: &str) -> Result<()> {
    let actual = protocol_reason(error)?;
    if actual != expected {
        bail!("expected reason {expected}, got {actual}");
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub fn run_aead_nonce_sender_domain_collision_vector() -> Result<()> {
    if AEAD_NONCE_EXPORTER_LABEL != "arkret-aead-sender-nonce-prefix-v1" {
        bail!("AEAD nonce exporter label drifted: {AEAD_NONCE_EXPORTER_LABEL}");
    }

    let device_one = nonce_context(DEVICE_ONE, AEAD_PROFILE_XCHACHA20_POLY1305);
    let device_two = nonce_context(DEVICE_TWO, AEAD_PROFILE_XCHACHA20_POLY1305);
    let prefix_one = derive_aead_sender_nonce_prefix(
        &EXPORTER_SECRET,
        &device_one,
        AEAD_NONCE_XCHACHA20_POLY1305_LEN,
    )?;
    let prefix_two = derive_aead_sender_nonce_prefix(
        &EXPORTER_SECRET,
        &device_two,
        AEAD_NONCE_XCHACHA20_POLY1305_LEN,
    )?;

    let prefix_one_hex = hex_lower(&prefix_one);
    if prefix_one_hex != EXPECTED_DEVICE_ONE_XCHACHA_PREFIX_HEX {
        bail!(
            "AEAD nonce prefix golden vector drifted: expected {}, got {}",
            EXPECTED_DEVICE_ONE_XCHACHA_PREFIX_HEX,
            prefix_one_hex
        );
    }
    if prefix_one == prefix_two {
        bail!("distinct sender devices produced the same sender_nonce_prefix");
    }

    let device_one_nonce = compose_aead_nonce(&prefix_one, 1);
    let counter = verify_aead_sender_nonce(
        &EXPORTER_SECRET,
        &device_one,
        &device_one_nonce,
        AEAD_NONCE_XCHACHA20_POLY1305_LEN,
        None,
    )?;
    if counter != 1 {
        bail!("device nonce counter parsed incorrectly: expected 1, got {counter}");
    }

    expect_reason(
        verify_aead_sender_nonce(
            &EXPORTER_SECRET,
            &device_two,
            &device_one_nonce,
            AEAD_NONCE_XCHACHA20_POLY1305_LEN,
            None,
        )
        .unwrap_err(),
        arkret_wire::ReasonCode::AEAD_NONCE_SENDER_DOMAIN_COLLISION,
    )?;

    Ok(())
}

pub fn run_aead_nonce_counter_replay_vector() -> Result<()> {
    let context = nonce_context(DEVICE_ONE, AEAD_PROFILE_XCHACHA20_POLY1305);
    let prefix = derive_aead_sender_nonce_prefix(
        &EXPORTER_SECRET,
        &context,
        AEAD_NONCE_XCHACHA20_POLY1305_LEN,
    )?;
    let mut tracker = AeadNonceReplayTracker::new();
    let nonce_counter_nine = compose_aead_nonce(&prefix, 9);
    let counter = verify_aead_sender_nonce(
        &EXPORTER_SECRET,
        &context,
        &nonce_counter_nine,
        AEAD_NONCE_XCHACHA20_POLY1305_LEN,
        Some(&mut tracker),
    )?;
    if counter != 9 {
        bail!("device nonce counter parsed incorrectly: expected 9, got {counter}");
    }

    expect_reason(
        verify_aead_sender_nonce(
            &EXPORTER_SECRET,
            &context,
            &nonce_counter_nine,
            AEAD_NONCE_XCHACHA20_POLY1305_LEN,
            Some(&mut tracker),
        )
        .unwrap_err(),
        arkret_wire::ReasonCode::AEAD_NONCE_COUNTER_REPLAY,
    )?;

    let nonce_counter_ten = compose_aead_nonce(&prefix, 10);
    verify_aead_sender_nonce(
        &EXPORTER_SECRET,
        &context,
        &nonce_counter_ten,
        AEAD_NONCE_XCHACHA20_POLY1305_LEN,
        Some(&mut tracker),
    )?;

    let other_context = nonce_context(DEVICE_TWO, AEAD_PROFILE_XCHACHA20_POLY1305);
    let other_prefix = derive_aead_sender_nonce_prefix(
        &EXPORTER_SECRET,
        &other_context,
        AEAD_NONCE_XCHACHA20_POLY1305_LEN,
    )?;
    let other_nonce_counter_nine = compose_aead_nonce(&other_prefix, 9);
    verify_aead_sender_nonce(
        &EXPORTER_SECRET,
        &other_context,
        &other_nonce_counter_nine,
        AEAD_NONCE_XCHACHA20_POLY1305_LEN,
        Some(&mut tracker),
    )?;

    Ok(())
}

pub fn run_aead_nonce_random_rejected_vector() -> Result<()> {
    let context = nonce_context(DEVICE_ONE, AEAD_PROFILE_AES_256_GCM);
    let expected_prefix =
        derive_aead_sender_nonce_prefix(&EXPORTER_SECRET, &context, AEAD_NONCE_AES_GCM_LEN)?;
    if expected_prefix.len() != 4 {
        bail!(
            "AES-GCM sender nonce prefix must be 4 bytes, got {}",
            expected_prefix.len()
        );
    }
    let expected_nonce = compose_aead_nonce(&expected_prefix, 0);
    if expected_nonce.len() != AEAD_NONCE_AES_GCM_LEN {
        bail!("AES-GCM nonce must be 12 bytes");
    }

    let random_nonce = [0xa5u8; AEAD_NONCE_AES_GCM_LEN];
    if random_nonce.as_slice() == expected_nonce.as_slice() {
        bail!("representative random nonce unexpectedly equals deterministic nonce");
    }
    expect_reason(
        verify_aead_nonce_derivation(&expected_nonce, &random_nonce).unwrap_err(),
        arkret_wire::ReasonCode::AEAD_NONCE_DERIVATION_INVALID,
    )?;

    Ok(())
}

pub fn run_media_aead_nonce_fixture_suite() -> Result<()> {
    validate_media_aead_nonce_fixture_metadata()?;
    if ALL_MEDIA_AEAD_NONCE_VECTOR_IDS.len() != 3 {
        bail!(
            "expected 3 media AEAD nonce vectors, got {}",
            ALL_MEDIA_AEAD_NONCE_VECTOR_IDS.len()
        );
    }

    run_aead_nonce_sender_domain_collision_vector()?;
    run_aead_nonce_counter_replay_vector()?;
    run_aead_nonce_random_rejected_vector()?;
    Ok(())
}
