//! Blob streaming AEAD conformance vectors.
//!
//! Covers `ak.vector.blob.stream_aead_*` by exercising the SDK codec and the
//! canonical blob encrypted_attachment schema together.

use anyhow::{Result, anyhow, bail};
use arkret::{
    BlobRef, EncryptedAttachmentGroupStateRef, EncryptedAttachmentKeyAlgorithm,
    EncryptedAttachmentKeyRef, EventId, Hash,
};
use arkret_crypto::blob_aead::{
    ALG_STREAM_XCHACHA, SCHEME_STREAM, StreamDecryptor, StreamEncryptParams, decrypt_stream,
    encrypt_stream, stream_segment_count,
};
use arkret_models_crypto::{EncryptedAttachment, StreamEncryptedAttachment};
use arkret_wire::ProfileId;
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
const BLOB_ENCRYPTED_ATTACHMENT_SCHEMA: &str =
    "schemas/blob.schema.json#/$defs/encrypted_attachment";
const SEGMENT_TAG_LEN: usize = 16;
const CONFORMANCE_SEGMENT_SIZE: u32 = 1024;

fn validate_blob_stream_aead_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(BLOB_STREAM_AEAD_FIXTURE_FILE)?;
    super::validate_profile(&fixture, ProfileId::BLOB_NODE_V1)?;
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

fn key_ref() -> EncryptedAttachmentKeyRef {
    EncryptedAttachmentKeyRef {
        algorithm: EncryptedAttachmentKeyAlgorithm::Mls,
        group_state_ref: EncryptedAttachmentGroupStateRef::Event(
            EventId::new("ak:event:ASIihwq2PrVn-0TWdd_J8voN4PsCP2T40iIDdKrDQaCU".to_owned())
                .unwrap(),
        ),
    }
}

fn params() -> StreamEncryptParams {
    StreamEncryptParams {
        key_ref: key_ref(),
        media_type: "video/mp4".to_owned(),
        segment_bytes: CONFORMANCE_SEGMENT_SIZE,
    }
}

fn winning_epoch(_group_state_ref: &EncryptedAttachmentGroupStateRef) -> Option<u64> {
    Some(42)
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

fn stream_fields(env: &EncryptedAttachment) -> Result<&StreamEncryptedAttachment> {
    match env {
        EncryptedAttachment::Stream(stream) => Ok(stream),
        EncryptedAttachment::WholeFile(_) => {
            bail!("encrypt_stream produced a whole-file envelope")
        }
    }
}

fn split_segments(ciphertext: &[u8], env: &EncryptedAttachment) -> Result<Vec<Vec<u8>>> {
    let stream = stream_fields(env)?;
    let segment_bytes = stream.segment_bytes as usize;
    let segment_count = stream_segment_count(stream.size_bytes, stream.segment_bytes as u32)?;
    let mut out = Vec::with_capacity(segment_count as usize);
    let mut offset = 0usize;
    for index in 0..segment_count {
        let last_index = segment_count - 1;
        let plaintext_len = if index < last_index {
            segment_bytes
        } else {
            (stream.size_bytes - (segment_bytes as u64) * u64::from(last_index)) as usize
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

fn schema_ready_envelope_value(env: &EncryptedAttachment) -> Result<Value> {
    let mut value = serde_json::to_value(env)?;
    value["blob_ref"] =
        json!("ak:blob:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    Ok(value)
}

pub fn run_stream_aead_roundtrip_vector() -> Result<()> {
    let key = key();
    let plaintext: Vec<u8> = (0..2050u32).map(|index| (index % 251) as u8).collect();
    let (ciphertext, env) = encrypt_stream(&plaintext, &key, &params(), &winning_epoch)?;

    let stream = stream_fields(&env)?;
    let raw = serde_json::to_value(&env)?;
    if raw["scheme"].as_str() != Some(SCHEME_STREAM) {
        bail!("stream roundtrip produced scheme {}", raw["scheme"]);
    }
    if raw["encryption_algorithm"].as_str() != Some(ALG_STREAM_XCHACHA) {
        bail!(
            "stream roundtrip produced encryption_algorithm {}",
            raw["encryption_algorithm"]
        );
    }
    if stream.segment_bytes != u64::from(CONFORMANCE_SEGMENT_SIZE)
        || stream_segment_count(stream.size_bytes, stream.segment_bytes as u32)? != 3
    {
        bail!("unexpected stream descriptor bounds");
    }
    if raw.get("nonce").is_some() || raw.get("nonce_prefix").is_none() {
        bail!("stream envelope must carry nonce_prefix and no whole-file nonce");
    }

    let recovered = decrypt_stream(&ciphertext, &env, &key, &winning_epoch)?;
    if recovered != plaintext {
        bail!("one-shot stream decrypt did not recover the original plaintext");
    }

    let segments = split_segments(&ciphertext, &env)?;
    let mut decryptor = StreamDecryptor::new(&env, &key, &winning_epoch)?;
    let mut incremental = Vec::with_capacity(plaintext.len());
    for (index, segment) in segments.iter().enumerate() {
        incremental.extend(decryptor.push_segment(index as u32, segment)?);
    }
    decryptor.finish()?;
    if incremental != plaintext {
        bail!("incremental stream decrypt did not recover the original plaintext");
    }

    // The content-addressed blob ref is the envelope's only ciphertext digest
    // carrier (`conformance/encoding.md` §4.0.1), so a mismatched digest is a
    // mismatched ref.
    let mut digest_mismatch_stream = stream.clone();
    digest_mismatch_stream.blob_ref = BlobRef::new(
        "ak:blob:sha256:0000000000000000000000000000000000000000000000000000000000000000",
    )?;
    let digest_mismatch = EncryptedAttachment::Stream(digest_mismatch_stream);
    expect_reason(
        decrypt_stream(&ciphertext, &digest_mismatch, &key, &winning_epoch).unwrap_err(),
        "digest_mismatch",
    )?;

    let mut proof_params = params();
    proof_params.key_ref.group_state_ref = EncryptedAttachmentGroupStateRef::Digest(Hash::new(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    )?);
    let (proof_ciphertext, proof_envelope) =
        encrypt_stream(&plaintext, &key, &proof_params, &winning_epoch)?;
    if decrypt_stream(&proof_ciphertext, &proof_envelope, &key, &winning_epoch)? != plaintext {
        bail!("proof-hash group state reference failed epoch-derived roundtrip");
    }

    let unresolved = |_group_state_ref: &EncryptedAttachmentGroupStateRef| None;
    expect_reason(
        decrypt_stream(&ciphertext, &env, &key, &unresolved).unwrap_err(),
        "attachment_group_state_unresolved",
    )?;
    let wrong_epoch = |_group_state_ref: &EncryptedAttachmentGroupStateRef| Some(41);
    expect_reason(
        decrypt_stream(&ciphertext, &env, &key, &wrong_epoch).unwrap_err(),
        "segment_aead_failed",
    )?;

    Ok(())
}

pub fn run_stream_aead_truncation_rejected_vector() -> Result<()> {
    let key = key();
    let plaintext = vec![7u8; 2500];
    let (ciphertext, env) = encrypt_stream(&plaintext, &key, &params(), &winning_epoch)?;
    let segments = split_segments(&ciphertext, &env)?;

    let mut decryptor = StreamDecryptor::new(&env, &key, &winning_epoch)?;
    for (index, segment) in segments.iter().enumerate().take(segments.len() - 1) {
        decryptor.push_segment(index as u32, segment)?;
    }
    expect_reason(decryptor.finish().unwrap_err(), "segment_stream_truncated")?;

    Ok(())
}

pub fn run_stream_aead_reorder_rejected_vector() -> Result<()> {
    let key = key();
    let plaintext = vec![11u8; 2500];
    let (ciphertext, env) = encrypt_stream(&plaintext, &key, &params(), &winning_epoch)?;
    let segments = split_segments(&ciphertext, &env)?;

    let mut reordered = StreamDecryptor::new(&env, &key, &winning_epoch)?;
    expect_reason(
        reordered.push_segment(1, &segments[1]).unwrap_err(),
        "segment_sequence_invalid",
    )?;

    let mut replayed = StreamDecryptor::new(&env, &key, &winning_epoch)?;
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
    let (_ciphertext, env) = encrypt_stream(&plaintext, &key, &params(), &winning_epoch)?;

    // The typed envelope enum is closed: an unknown scheme id cannot even
    // deserialize, so no decryptor can be constructed for it.
    let mut unknown_scheme = serde_json::to_value(&env)?;
    unknown_scheme["scheme"] = json!("ak.blob.stream_aead.unregistered.v1");
    if serde_json::from_value::<EncryptedAttachment>(unknown_scheme).is_ok() {
        bail!("unknown attachment scheme survived the closed envelope enum");
    }

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
