//! Media AEAD nonce conformance vectors.
//!
//! Covers the v1 deterministic sender nonce prefix contract from
//! `zh/conformance/encoding.md` section 10.1.

use anyhow::{Result, anyhow, bail};
use arkret_crypto::{
    AEAD_NONCE_AES_GCM_LEN, AEAD_NONCE_EXPORTER_LABEL, AEAD_NONCE_XCHACHA20_POLY1305_LEN,
    AEAD_PROFILE_AES_256_GCM, AEAD_PROFILE_XCHACHA20_POLY1305, AeadNonceContext,
    AeadNonceReplayTracker, Error, aead_sender_nonce_context_bytes, compose_aead_nonce,
    derive_aead_sender_nonce_prefix, verify_aead_nonce_derivation, verify_aead_sender_nonce,
};
use arkret_wire::ProfileId;
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
const DEVICE_ONE: &str = "ak:device:01964137-0000-7000-8000-000000000001";
const DEVICE_TWO: &str = "ak:device:01964137-0000-7000-8000-000000000002";
const PURPOSE_MESSAGE_PAYLOAD: &str = "ak.message.encrypted_payload";
const EXPORTER_SECRET: [u8; 32] = [0x24u8; 32];
/// The one registered known-answer vector for the §10.1 sender nonce prefix.
/// A locally-invented golden would only pin this suite to itself, so the
/// byte-level anchor comes from the Spec fixture instead.
const PRIVATE_KDF_FIXTURE_FILE: &str = "arkret-private-kdf-fixture.json";
const SENDER_NONCE_PREFIX_CASE: &str = "aead_sender_nonce_prefix_aes128gcm";

fn validate_media_aead_nonce_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(MEDIA_AEAD_NONCE_FIXTURE_FILE)?;
    super::validate_profile(&fixture, ProfileId::E2EE_CLIENT_V1)?;
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
            "group_state_ref": "ak:event:01964148-0000-8000-8000-000000000000"
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

/// Byte-level anchor for the §10.1 sender nonce prefix, taken from the one
/// registered known-answer vector in `arkret-private-kdf-fixture.json`.
///
/// The canonical exporter Context is pinned before the prefix so a
/// canonicalization change cannot hide behind a prefix that happens to match
/// over different bytes.
fn check_registered_sender_nonce_prefix_vector() -> Result<()> {
    let fixture = super::load_fixture_value(PRIVATE_KDF_FIXTURE_FILE)?;
    let case = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("private KDF fixture missing cases[]"))?
        .iter()
        .find(|case| case.get("name").and_then(Value::as_str) == Some(SENDER_NONCE_PREFIX_CASE))
        .ok_or_else(|| anyhow!("private KDF fixture missing case {SENDER_NONCE_PREFIX_CASE}"))?;

    let exporter_label = case
        .pointer("/input/exporter_label")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{SENDER_NONCE_PREFIX_CASE} missing input.exporter_label"))?;
    if exporter_label != AEAD_NONCE_EXPORTER_LABEL {
        bail!("registered sender nonce exporter label drifted: {exporter_label}");
    }
    let secret = hex_decode(
        case.pointer("/input/exporter_secret_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!("{SENDER_NONCE_PREFIX_CASE} missing input.exporter_secret_hex")
            })?,
    )?;
    let context: AeadNonceContext = serde_json::from_value(
        case.pointer("/input/context")
            .cloned()
            .ok_or_else(|| anyhow!("{SENDER_NONCE_PREFIX_CASE} missing input.context"))?,
    )
    .map_err(|error| anyhow!("registered nonce context does not decode: {error}"))?;
    let nonce_len = usize::try_from(
        case.pointer("/input/nonce_length_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                anyhow!("{SENDER_NONCE_PREFIX_CASE} missing input.nonce_length_bytes")
            })?,
    )?;
    if nonce_len != AEAD_NONCE_AES_GCM_LEN {
        bail!("registered sender nonce vector is no longer the AES-GCM length");
    }

    let expected_context = case
        .pointer("/expected/context_canonical_json")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow!("{SENDER_NONCE_PREFIX_CASE} missing expected.context_canonical_json")
        })?;
    let actual_context = String::from_utf8(aead_sender_nonce_context_bytes(&context)?)
        .map_err(|error| anyhow!("canonical nonce context is not UTF-8: {error}"))?;
    if actual_context != expected_context {
        bail!("canonical nonce context drifted: expected {expected_context}, got {actual_context}");
    }

    let prefix = derive_aead_sender_nonce_prefix(&secret, &context, nonce_len)?;
    let expected_prefix = case
        .pointer("/expected/sender_nonce_prefix_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow!("{SENDER_NONCE_PREFIX_CASE} missing expected.sender_nonce_prefix_hex")
        })?;
    let actual_prefix = hex_lower(&prefix);
    if actual_prefix != expected_prefix {
        bail!("sender nonce prefix drifted: expected {expected_prefix}, got {actual_prefix}");
    }

    let counter_hex = case
        .pointer("/input/counter_be64_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{SENDER_NONCE_PREFIX_CASE} missing input.counter_be64_hex"))?;
    let counter = u64::from_str_radix(counter_hex, 16)
        .map_err(|error| anyhow!("registered nonce counter is not hex: {error}"))?;
    let expected_nonce = case
        .pointer("/expected/nonce_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{SENDER_NONCE_PREFIX_CASE} missing expected.nonce_hex"))?;
    let actual_nonce = hex_lower(&compose_aead_nonce(&prefix, counter));
    if actual_nonce != expected_nonce {
        bail!("composed nonce drifted: expected {expected_nonce}, got {actual_nonce}");
    }
    Ok(())
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        bail!("hex string has an odd length");
    }
    (0..value.len() / 2)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|error| anyhow!("invalid hex: {error}"))
        })
        .collect()
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

    check_registered_sender_nonce_prefix_vector()?;
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
