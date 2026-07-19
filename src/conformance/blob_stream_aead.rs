//! Blob streaming AEAD conformance vectors.
//!
//! Covers `ak.vector.blob.stream_aead_*` by exercising the SDK codec and the
//! canonical blob encrypted_attachment schema together.

use anyhow::{Result, anyhow, bail};
use arkret::{
    ALG_STREAM_XCHACHA, EncryptedAttachmentEnvelope, KeyRefObject, SCHEME_STREAM,
    StreamDecryptor, StreamEncryptParams, decrypt_stream, encrypt_stream,
};
use serde_json::{Value, json};

use super::schema_validation_fixture::SchemaEnv;

pub const VECTOR_ID_STREAM_AEAD_ROUNDTRIP: &str = "ak.vector.blob.stream_aead_roundtrip.v1";
pub const VECTOR_ID_STREAM_AEAD_TRUNCATION_REJECTED: &str =
    "ak.vector.blob.stream_aead_truncation_rejected.v1";
pub const VECTOR_ID_STREAM_AEAD_REORDER_REJECTED: &str =
    "ak.vector.blob.stream_aead_reorder_rejected.v1";
pub const VECTOR_ID_STREAM_AEAD_SCHEME_CLOSURE: &str =
    "ak.vector.blob.stream_aead_scheme_closure.v1";

pub const ALL_BLOB_STREAM_AEAD_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_STREAM_AEAD_ROUNDTRIP,
    VECTOR_ID_STREAM_AEAD_TRUNCATION_REJECTED,
    VECTOR_ID_STREAM_AEAD_REORDER_REJECTED,
    VECTOR_ID_STREAM_AEAD_SCHEME_CLOSURE,
];

const BLOB_STREAM_AEAD_FIXTURE_FILE: &str = "blob-stream-aead-fixture.json";
const BLOB_STREAM_AEAD_PROFILE: &str = "ak.profile.blob_node.v1";
const BLOB_ENCRYPTED_ATTACHMENT_SCHEMA: &str =
    "schemas/blob.schema.json#/$defs/encrypted_attachment";
const SEGMENT_TAG_LEN: usize = 16;
const CONFORMANCE_SEGMENT_SIZE: u32 = 1024;

fn validate_blob_stream_aead_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(BLOB_STREAM_AEAD_FIXTURE_FILE)?;
    super::validate_profile(&fixture, BLOB_STREAM_AEAD_PROFILE)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("blob stream AEAD fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("blob stream AEAD fixture missing cases[]"))?;

    for vector_id in ALL_BLOB_STREAM_AEAD_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("blob stream AEAD fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("blob stream AEAD fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

fn key() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = index as u8;
    }
    out
}

fn key_ref() -> KeyRefObject {
    KeyRefObject {
        algorithm: "MLS".to_owned(),
        group_state_ref: "ak:event:01964148-0000-7000-8000-000000000000".to_owned(),
    }
}

fn params() -> StreamEncryptParams {
    StreamEncryptParams {
        key_ref: key_ref(),
        epoch: 42,
        media_type: "video/mp4".to_owned(),
        segment_size: CONFORMANCE_SEGMENT_SIZE,
    }
}

fn protocol_reason(error: arkret_crypto::Error) -> Result<String> {
    match error {
        arkret_crypto::Error::Protocol(message) => {
            Ok(message.split(':').next().unwrap_or("").to_owned())
        }
        other => bail!("expected protocol error, got {other:?}"),
    }
}

fn expect_reason(error: arkret_crypto::Error, expected: &str) -> Result<()> {
    let actual = protocol_reason(error)?;
    if actual != expected {
        bail!("expected reason {expected}, got {actual}");
    }
    Ok(())
}

fn split_segments(ciphertext: &[u8], env: &EncryptedAttachmentEnvelope) -> Result<Vec<Vec<u8>>> {
    let segment_size =
        env.segment_size
            .ok_or_else(|| anyhow!("stream envelope missing segment_size"))? as usize;
    let segment_count = env
        .segment_count
        .ok_or_else(|| anyhow!("stream envelope missing segment_count"))?;
    let mut out = Vec::with_capacity(segment_count as usize);
    let mut offset = 0usize;
    for index in 0..segment_count {
        let last_index = segment_count - 1;
        let plaintext_len = if index < last_index {
            segment_size
        } else {
            (env.size_bytes - (segment_size as u64) * (last_index as u64)) as usize
        };
        let ciphertext_len = plaintext_len + SEGMENT_TAG_LEN;
        let end = offset + ciphertext_len;
        if end > ciphertext.len() {
            bail!("segment {index} exceeds ciphertext length");
        }
        out.push(ciphertext[offset..end].to_vec());
        offset = end;
    }
    if offset != ciphertext.len() {
        bail!(
            "split left {} trailing ciphertext bytes",
            ciphertext.len() - offset
        );
    }
    Ok(out)
}

fn schema_ready_envelope_value(env: &EncryptedAttachmentEnvelope) -> Result<Value> {
    let mut value = serde_json::to_value(env)?;
    value["blob_ref"] =
        json!("ak:blob:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    Ok(value)
}

pub fn run_stream_aead_roundtrip_vector() -> Result<()> {
    let key = key();
    let plaintext: Vec<u8> = (0..2050u32).map(|index| (index % 251) as u8).collect();
    let (ciphertext, env) = encrypt_stream(&plaintext, &key, &params())?;

    if env.scheme != SCHEME_STREAM {
        bail!("stream roundtrip produced scheme {}", env.scheme);
    }
    if env.alg != ALG_STREAM_XCHACHA {
        bail!("stream roundtrip produced alg {}", env.alg);
    }
    if env.segment_size != Some(CONFORMANCE_SEGMENT_SIZE) || env.segment_count != Some(3) {
        bail!(
            "expected segment_size={CONFORMANCE_SEGMENT_SIZE} segment_count=3, got {:?}/{:?}",
            env.segment_size,
            env.segment_count
        );
    }
    if env.nonce.is_some() || env.nonce_prefix.is_none() {
        bail!("stream envelope must carry nonce_prefix and no whole-file nonce");
    }

    let recovered = decrypt_stream(&ciphertext, &env, &key)?;
    if recovered != plaintext {
        bail!("one-shot stream decrypt did not recover the original plaintext");
    }

    let segments = split_segments(&ciphertext, &env)?;
    let mut decryptor = StreamDecryptor::new(&env, &key)?;
    let mut incremental = Vec::with_capacity(plaintext.len());
    for (index, segment) in segments.iter().enumerate() {
        incremental.extend(decryptor.push_segment(index as u32, segment)?);
    }
    decryptor.finish()?;
    if incremental != plaintext {
        bail!("incremental stream decrypt did not recover the original plaintext");
    }

    let mut digest_mismatch = env.clone();
    digest_mismatch.ciphertext_digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();
    expect_reason(
        decrypt_stream(&ciphertext, &digest_mismatch, &key).unwrap_err(),
        "digest_mismatch",
    )?;

    Ok(())
}

pub fn run_stream_aead_truncation_rejected_vector() -> Result<()> {
    let key = key();
    let plaintext = vec![7u8; 2500];
    let (ciphertext, env) = encrypt_stream(&plaintext, &key, &params())?;
    let segments = split_segments(&ciphertext, &env)?;

    let mut decryptor = StreamDecryptor::new(&env, &key)?;
    for (index, segment) in segments.iter().enumerate().take(segments.len() - 1) {
        decryptor.push_segment(index as u32, segment)?;
    }
    expect_reason(decryptor.finish().unwrap_err(), "segment_stream_truncated")?;

    let mut count_mismatch = env.clone();
    count_mismatch.segment_count = Some(env.segment_count.unwrap_or_default() + 1);
    let count_mismatch_err = match StreamDecryptor::new(&count_mismatch, &key) {
        Ok(_) => bail!("segment_count mismatch unexpectedly constructed a decryptor"),
        Err(error) => error,
    };
    expect_reason(count_mismatch_err, "segment_stream_truncated")?;

    Ok(())
}

pub fn run_stream_aead_reorder_rejected_vector() -> Result<()> {
    let key = key();
    let plaintext = vec![11u8; 2500];
    let (ciphertext, env) = encrypt_stream(&plaintext, &key, &params())?;
    let segments = split_segments(&ciphertext, &env)?;

    let mut reordered = StreamDecryptor::new(&env, &key)?;
    expect_reason(
        reordered.push_segment(1, &segments[1]).unwrap_err(),
        "segment_sequence_invalid",
    )?;

    let mut replayed = StreamDecryptor::new(&env, &key)?;
    replayed.push_segment(0, &segments[0])?;
    expect_reason(
        replayed.push_segment(0, &segments[0]).unwrap_err(),
        "segment_replay",
    )?;

    Ok(())
}

pub fn run_stream_aead_scheme_closure_vector() -> Result<()> {
    let key = key();
    let plaintext = vec![13u8; 2050];
    let (ciphertext, env) = encrypt_stream(&plaintext, &key, &params())?;

    let mut unknown_scheme = env.clone();
    unknown_scheme.scheme = "ak.blob.stream_aead.v2".to_owned();
    expect_reason(
        decrypt_stream(&ciphertext, &unknown_scheme, &key).unwrap_err(),
        "unsupported_attachment_scheme",
    )?;

    let schema_env = SchemaEnv::load()?;
    let validator = schema_env.compile(BLOB_ENCRYPTED_ATTACHMENT_SCHEMA)?;
    let control = schema_ready_envelope_value(&env)?;
    if !validator.is_valid(&control) {
        let errors = validator
            .iter_errors(&control)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        bail!("valid stream envelope failed blob schema validation: {errors}");
    }

    let mut mixed = control.clone();
    mixed["nonce"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    if validator.is_valid(&mixed) {
        bail!("mixed whole-file nonce plus stream segment fields passed schema oneOf");
    }

    Ok(())
}

pub fn run_blob_stream_aead_fixture_suite() -> Result<()> {
    validate_blob_stream_aead_fixture_metadata()?;
    if ALL_BLOB_STREAM_AEAD_VECTOR_IDS.len() != 4 {
        bail!(
            "expected 4 blob stream AEAD vectors, got {}",
            ALL_BLOB_STREAM_AEAD_VECTOR_IDS.len()
        );
    }

    run_stream_aead_roundtrip_vector()?;
    run_stream_aead_truncation_rejected_vector()?;
    run_stream_aead_reorder_rejected_vector()?;
    run_stream_aead_scheme_closure_vector()?;
    Ok(())
}
