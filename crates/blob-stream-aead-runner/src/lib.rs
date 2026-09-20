//! Executable MLS attachment streaming-AEAD conformance vectors.
//!
//! Every case calls the SDK production codec, typed carrier or schema
//! validator. Plaintext enters the consumer sink only after the complete
//! stream, including its content digest, has verified.

use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use arkret_crypto::blob_aead::{
    MAX_SEGMENT_COUNT, MAX_SEGMENT_SIZE, MIN_SEGMENT_SIZE, StreamDecryptor, StreamEncryptParams,
    decrypt_stream, encrypt_stream, stream_segment_count,
};
use arkret_models_crypto::{
    EncryptedAttachment, EncryptedAttachmentGroupStateRef, EncryptedAttachmentKeyAlgorithm,
    EncryptedAttachmentKeyRef, StreamEncryptionAlgorithm,
};
use arkret_schema::{ProtocolSchemaRegistry, SchemaError};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{BlobRef, EventId, Hash};
use serde_json::{Value, json};

pub const BLOB_STREAM_AEAD_ENTRYPOINT: &str = "ak.suite.blob.stream_aead.v1";
pub const FIXTURE: &str = "blob-stream-aead-fixture.json";

pub const VECTOR_ID_STREAM_AEAD_ROUNDTRIP: &str = "ak.vector.blob.stream_aead_roundtrip.v1";
pub const VECTOR_ID_STREAM_AEAD_TRUNCATION_REJECTED: &str =
    "ak.vector.blob.stream_aead_truncation_rejected.v1";
pub const VECTOR_ID_STREAM_AEAD_REORDER_REJECTED: &str =
    "ak.vector.blob.stream_aead_reorder_rejected.v1";
pub const VECTOR_ID_STREAM_AEAD_SCHEME_CLOSURE: &str =
    "ak.vector.blob.stream_aead_scheme_closure.v1";
pub const VECTOR_ID_STREAM_AEAD_BOUNDS_REJECTED: &str =
    "ak.vector.blob.stream_aead_bounds_rejected.v1";

pub const ALL_BLOB_STREAM_AEAD_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_STREAM_AEAD_ROUNDTRIP,
    VECTOR_ID_STREAM_AEAD_TRUNCATION_REJECTED,
    VECTOR_ID_STREAM_AEAD_REORDER_REJECTED,
    VECTOR_ID_STREAM_AEAD_SCHEME_CLOSURE,
    VECTOR_ID_STREAM_AEAD_BOUNDS_REJECTED,
];

const SCHEMA_ID: &str = "cotest:encrypted-attachment";
const SEGMENT_TAG_LEN: usize = 16;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ConsumerState {
    accepted_plaintexts: Vec<Vec<u8>>,
    accepted_blob_refs: Vec<String>,
}

struct AttachmentConsumer {
    state: ConsumerState,
    schemas: ProtocolSchemaRegistry,
}

impl AttachmentConsumer {
    fn new() -> Result<Self> {
        let artifacts = spec_artifacts_root();
        let mut schemas = schema_registry_from_spec_artifacts(&artifacts)
            .context("load the production schema registry")?;
        let blob_schema: Value = serde_json::from_slice(&std::fs::read(
            artifacts.join("schemas").join("blob.schema.json"),
        )?)?;
        schemas.register_fragment(SCHEMA_ID, blob_schema, "#/$defs/encrypted_attachment")?;
        Ok(Self {
            state: ConsumerState::default(),
            schemas,
        })
    }

    fn accept(
        &mut self,
        ciphertext: &[u8],
        envelope: &EncryptedAttachment,
        key: &[u8; 32],
        resolver: &impl arkret_crypto::blob_aead::AttachmentGroupStateEpochResolver,
    ) -> Result<Vec<u8>> {
        let wire = serde_json::to_value(envelope)?;
        self.schemas
            .validate_value(SCHEMA_ID, &wire)
            .context("typed stream envelope failed production schema validation")?;
        let plaintext = decrypt_stream(ciphertext, envelope, key, resolver)?;
        self.state.accepted_plaintexts.push(plaintext.clone());
        self.state.accepted_blob_refs.push(
            wire["blob_ref"]
                .as_str()
                .context("accepted envelope has no blob_ref")?
                .to_owned(),
        );
        Ok(plaintext)
    }

    fn accept_incremental(
        &mut self,
        ciphertext: &[u8],
        envelope: &EncryptedAttachment,
        key: &[u8; 32],
        resolver: &impl arkret_crypto::blob_aead::AttachmentGroupStateEpochResolver,
    ) -> Result<Vec<u8>> {
        let segments = split_segments(ciphertext, envelope)?;
        let mut decryptor = StreamDecryptor::new(envelope, key, resolver)?;
        let mut plaintext = Vec::new();
        for (index, segment) in segments.iter().enumerate() {
            plaintext.extend(decryptor.push_segment(index as u32, segment)?);
        }
        decryptor.finish()?;
        self.state.accepted_plaintexts.push(plaintext.clone());
        self.state.accepted_blob_refs.push(
            envelope_blob_ref(envelope)
                .context("accepted envelope has no stream blob_ref")?
                .to_owned(),
        );
        Ok(plaintext)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub accepted_effects: usize,
    pub rejected_state_unchanged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamAeadExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub accepted_sink_entries: usize,
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("fixtures").is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn load_fixture() -> Result<Value> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

fn fixture_cases(fixture: &Value) -> Result<&Vec<Value>> {
    fixture["cases"]
        .as_array()
        .context("blob stream fixture has no cases[]")
}

fn key() -> [u8; 32] {
    let mut key = [0_u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = index as u8;
    }
    key
}

fn event_key_ref() -> EncryptedAttachmentKeyRef {
    EncryptedAttachmentKeyRef {
        algorithm: EncryptedAttachmentKeyAlgorithm::Mls,
        group_state_ref: EncryptedAttachmentGroupStateRef::Event(
            EventId::new("ak:event:ASIihwq2PrVn-0TWdd_J8voN4PsCP2T40iIDdKrDQaCU".to_owned())
                .expect("fixed event id must be valid"),
        ),
    }
}

fn digest_key_ref() -> EncryptedAttachmentKeyRef {
    EncryptedAttachmentKeyRef {
        algorithm: EncryptedAttachmentKeyAlgorithm::Mls,
        group_state_ref: EncryptedAttachmentGroupStateRef::Digest(
            Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            )
            .expect("fixed proof hash must be valid"),
        ),
    }
}

fn params(key_ref: EncryptedAttachmentKeyRef) -> StreamEncryptParams {
    StreamEncryptParams {
        key_ref,
        media_type: "video/mp4".to_owned(),
        segment_bytes: MIN_SEGMENT_SIZE,
    }
}

fn winning_epoch(_reference: &EncryptedAttachmentGroupStateRef) -> Option<u64> {
    Some(42)
}

fn envelope_blob_ref(envelope: &EncryptedAttachment) -> Option<&str> {
    match envelope {
        EncryptedAttachment::Stream(stream) => Some(stream.blob_ref.as_str()),
        EncryptedAttachment::WholeFile(_) => None,
    }
}

fn split_segments(ciphertext: &[u8], envelope: &EncryptedAttachment) -> Result<Vec<Vec<u8>>> {
    let EncryptedAttachment::Stream(stream) = envelope else {
        bail!("stream codec produced a whole-file envelope");
    };
    let segment_bytes = u32::try_from(stream.segment_bytes)?;
    let count = stream_segment_count(stream.size_bytes, segment_bytes)?;
    let mut offset = 0_usize;
    let mut segments = Vec::with_capacity(count as usize);
    for index in 0..count {
        let plaintext_len = if index + 1 == count {
            (stream.size_bytes - u64::from(segment_bytes) * u64::from(index)) as usize
        } else {
            segment_bytes as usize
        };
        let end = offset + plaintext_len + SEGMENT_TAG_LEN;
        ensure!(
            end <= ciphertext.len(),
            "ciphertext is shorter than its descriptor"
        );
        segments.push(ciphertext[offset..end].to_vec());
        offset = end;
    }
    ensure!(offset == ciphertext.len(), "ciphertext has trailing bytes");
    Ok(segments)
}

fn expect_protocol_error(
    error: arkret_crypto::Error,
    error_code: &str,
    reason_code: &str,
) -> Result<()> {
    let arkret_crypto::Error::Protocol(message) = error else {
        bail!("expected protocol error, got {error:?}");
    };
    ensure!(
        message.starts_with(error_code),
        "expected error code {error_code}, got {message}"
    );
    ensure!(
        message.contains(reason_code),
        "expected reason {reason_code}, got {message}"
    );
    Ok(())
}

fn run_roundtrip(consumer: &mut AttachmentConsumer) -> Result<CaseExecutionResult> {
    let before = consumer.state.clone();
    let plaintext: Vec<u8> = (0..2050_u32).map(|index| (index % 251) as u8).collect();
    let key = key();
    let (ciphertext, envelope) =
        encrypt_stream(&plaintext, &key, &params(event_key_ref()), &winning_epoch)?;
    ensure!(
        consumer.accept(&ciphertext, &envelope, &key, &winning_epoch)? == plaintext,
        "one-shot production decrypt changed plaintext"
    );
    ensure!(
        consumer.accept_incremental(&ciphertext, &envelope, &key, &winning_epoch)? == plaintext,
        "incremental production decrypt changed plaintext"
    );

    let (digest_ciphertext, digest_envelope) =
        encrypt_stream(&plaintext, &key, &params(digest_key_ref()), &winning_epoch)?;
    ensure!(
        consumer.accept(&digest_ciphertext, &digest_envelope, &key, &winning_epoch,)? == plaintext,
        "proof-hash reference did not resolve the same winning epoch"
    );
    ensure!(consumer.state.accepted_plaintexts.len() == before.accepted_plaintexts.len() + 3);

    let accepted = consumer.state.clone();
    let unresolved = |_reference: &EncryptedAttachmentGroupStateRef| None;
    expect_protocol_error(
        decrypt_stream(&ciphertext, &envelope, &key, &unresolved).unwrap_err(),
        "attachment_group_state_unresolved",
        "attachment_group_state_unresolved",
    )?;
    ensure!(consumer.state == accepted);

    let wrong_epoch = |_reference: &EncryptedAttachmentGroupStateRef| Some(41);
    expect_protocol_error(
        decrypt_stream(&ciphertext, &envelope, &key, &wrong_epoch).unwrap_err(),
        "segment_aead_failed",
        "segment_aead_failed",
    )?;
    ensure!(consumer.state == accepted);

    let EncryptedAttachment::Stream(mut digest_mismatch) = envelope.clone() else {
        bail!("stream codec produced a whole-file envelope");
    };
    digest_mismatch.blob_ref = BlobRef::new(
        "ak:blob:sha256:0000000000000000000000000000000000000000000000000000000000000000",
    )?;
    expect_protocol_error(
        decrypt_stream(
            &ciphertext,
            &EncryptedAttachment::Stream(digest_mismatch),
            &key,
            &winning_epoch,
        )
        .unwrap_err(),
        "digest_mismatch",
        "digest_mismatch",
    )?;
    ensure!(consumer.state == accepted);

    Ok(CaseExecutionResult {
        case_id: "stream_aead_roundtrip".to_owned(),
        assertions: 10,
        accepted_effects: 3,
        rejected_state_unchanged: consumer.state == accepted,
    })
}

fn run_truncation(consumer: &mut AttachmentConsumer) -> Result<CaseExecutionResult> {
    let key = key();
    let plaintext = vec![7_u8; 2500];
    let (ciphertext, envelope) =
        encrypt_stream(&plaintext, &key, &params(event_key_ref()), &winning_epoch)?;
    let segments = split_segments(&ciphertext, &envelope)?;
    ensure!(
        segments.len() == 3,
        "truncation control did not create three segments"
    );
    let state = consumer.state.clone();
    let mut decryptor = StreamDecryptor::new(&envelope, &key, &winning_epoch)?;
    for (index, segment) in segments.iter().enumerate().take(segments.len() - 1) {
        decryptor.push_segment(index as u32, segment)?;
    }
    expect_protocol_error(
        decryptor.finish().unwrap_err(),
        "segment_stream_truncated",
        "segment_stream_truncated",
    )?;
    ensure!(consumer.state == state);
    Ok(CaseExecutionResult {
        case_id: "stream_aead_truncation_rejected".to_owned(),
        assertions: 4,
        accepted_effects: 0,
        rejected_state_unchanged: consumer.state == state,
    })
}

fn run_reorder(consumer: &mut AttachmentConsumer) -> Result<CaseExecutionResult> {
    let key = key();
    let plaintext = vec![11_u8; 2500];
    let (ciphertext, envelope) =
        encrypt_stream(&plaintext, &key, &params(event_key_ref()), &winning_epoch)?;
    let segments = split_segments(&ciphertext, &envelope)?;
    let state = consumer.state.clone();

    let mut reordered = StreamDecryptor::new(&envelope, &key, &winning_epoch)?;
    expect_protocol_error(
        reordered.push_segment(1, &segments[1]).unwrap_err(),
        "segment_sequence_invalid",
        "segment_sequence_invalid",
    )?;
    ensure!(consumer.state == state);

    let mut replayed = StreamDecryptor::new(&envelope, &key, &winning_epoch)?;
    replayed.push_segment(0, &segments[0])?;
    expect_protocol_error(
        replayed.push_segment(0, &segments[0]).unwrap_err(),
        "segment_replay",
        "segment_replay",
    )?;
    ensure!(consumer.state == state);
    Ok(CaseExecutionResult {
        case_id: "stream_aead_reorder_rejected".to_owned(),
        assertions: 4,
        accepted_effects: 0,
        rejected_state_unchanged: consumer.state == state,
    })
}

fn run_scheme_closure(consumer: &mut AttachmentConsumer) -> Result<CaseExecutionResult> {
    let key = key();
    let plaintext = vec![13_u8; 2050];
    let (ciphertext, envelope) =
        encrypt_stream(&plaintext, &key, &params(event_key_ref()), &winning_epoch)?;
    let before = consumer.state.clone();
    ensure!(
        consumer.accept(&ciphertext, &envelope, &key, &winning_epoch)? == plaintext,
        "schema-valid stream control did not reach the accepted sink"
    );
    ensure!(consumer.state.accepted_plaintexts.len() == before.accepted_plaintexts.len() + 1);
    let accepted = consumer.state.clone();

    let mut unknown_scheme = serde_json::to_value(&envelope)?;
    unknown_scheme["scheme"] = json!("ak.blob.stream_aead.unregistered.v1");
    ensure!(
        serde_json::from_value::<EncryptedAttachment>(unknown_scheme).is_err(),
        "unknown scheme survived the production typed carrier"
    );
    ensure!(consumer.state == accepted);

    let EncryptedAttachment::Stream(mut aes_envelope) = envelope.clone() else {
        bail!("stream codec produced a whole-file envelope");
    };
    aes_envelope.encryption_algorithm = StreamEncryptionAlgorithm::MlsExporterAeadAes256GcmStream;
    expect_protocol_error(
        decrypt_stream(
            &ciphertext,
            &EncryptedAttachment::Stream(aes_envelope),
            &key,
            &winning_epoch,
        )
        .unwrap_err(),
        "unsupported_attachment_scheme",
        "unsupported_attachment_scheme",
    )?;
    ensure!(consumer.state == accepted);

    let mut mixed = serde_json::to_value(&envelope)?;
    mixed["nonce"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let error = consumer
        .schemas
        .validate_value(SCHEMA_ID, &mixed)
        .expect_err("mixed whole-file and stream envelope passed production schema validation");
    ensure!(matches!(error, SchemaError::Validation(_)));
    ensure!(consumer.state == accepted);

    Ok(CaseExecutionResult {
        case_id: "stream_aead_scheme_closure".to_owned(),
        assertions: 8,
        accepted_effects: 1,
        rejected_state_unchanged: consumer.state == accepted,
    })
}

fn run_bounds(fixture_case: &Value, consumer: &AttachmentConsumer) -> Result<CaseExecutionResult> {
    let state = consumer.state.clone();
    let cases = fixture_case["cases"]
        .as_array()
        .context("bounds case has no nested cases[]")?;
    ensure!(cases.len() == 3, "bounds vector must contain three cases");
    let mut key_derivation_calls = 0_usize;
    let mut segment_downloads = 0_usize;
    for case in cases {
        let segment_bytes = u32::try_from(
            case["declared"]["segment_bytes"]
                .as_u64()
                .context("bounds case has no segment_bytes")?,
        )?;
        let size_bytes = case["declared"]["size_bytes"]
            .as_u64()
            .context("bounds case has no size_bytes")?;
        let error = stream_segment_count(size_bytes, segment_bytes)
            .expect_err("invalid descriptor passed production geometry preflight");
        expect_protocol_error(error, "schema_violation", "segment_bounds_invalid")?;
        ensure!(key_derivation_calls == 0 && segment_downloads == 0);
    }
    ensure!(
        stream_segment_count(
            u64::from(MAX_SEGMENT_COUNT) * u64::from(MAX_SEGMENT_SIZE),
            MAX_SEGMENT_SIZE,
        )? == MAX_SEGMENT_COUNT,
        "maximum legal descriptor was rejected"
    );
    key_derivation_calls += 1;
    segment_downloads += 1;
    ensure!(key_derivation_calls == 1 && segment_downloads == 1);
    ensure!(consumer.state == state);
    Ok(CaseExecutionResult {
        case_id: "stream_aead_bounds_rejected".to_owned(),
        assertions: 11,
        accepted_effects: 0,
        rejected_state_unchanged: consumer.state == state,
    })
}

pub fn run_blob_stream_aead_suite() -> Result<BlobStreamAeadExecution> {
    let fixture = load_fixture()?;
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(BLOB_STREAM_AEAD_ENTRYPOINT),
        "blob stream entrypoint drifted"
    );
    ensure!(fixture["profile"] == "ak.profile.blob_node.v1");
    let cases = fixture_cases(&fixture)?;
    ensure!(cases.len() == ALL_BLOB_STREAM_AEAD_VECTOR_IDS.len());
    for (index, (case, vector_id)) in cases
        .iter()
        .zip(ALL_BLOB_STREAM_AEAD_VECTOR_IDS)
        .enumerate()
    {
        ensure!(
            case["vector_id"].as_str() == Some(*vector_id),
            "blob stream case {index} vector id drifted"
        );
        ensure!(
            case["assertions"]
                .as_array()
                .is_some_and(|value| !value.is_empty()),
            "blob stream case {index} has no assertions"
        );
    }

    let mut consumer = AttachmentConsumer::new()?;
    let results = vec![
        run_roundtrip(&mut consumer)?,
        run_truncation(&mut consumer)?,
        run_reorder(&mut consumer)?,
        run_scheme_closure(&mut consumer)?,
        run_bounds(&cases[4], &consumer)?,
    ];
    for (case, result) in cases.iter().zip(&results) {
        ensure!(case["name"].as_str() == Some(result.case_id.as_str()));
        ensure!(result.assertions > 0);
        ensure!(result.rejected_state_unchanged);
    }
    ensure!(
        consumer.state.accepted_plaintexts.len() == 4,
        "accepted sink effect count drifted"
    );
    Ok(BlobStreamAeadExecution {
        entrypoint: BLOB_STREAM_AEAD_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
        accepted_sink_entries: consumer.state.accepted_plaintexts.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_formal_cases_reach_production_seams() -> Result<()> {
        let execution = run_blob_stream_aead_suite()?;
        assert_eq!(execution.cases.len(), 5);
        assert_eq!(execution.accepted_sink_entries, 4);
        assert!(
            execution
                .cases
                .iter()
                .all(|case| case.assertions > 0 && case.rejected_state_unchanged)
        );
        Ok(())
    }

    #[test]
    fn descriptor_bounds_fail_before_expensive_effects() -> Result<()> {
        for (size, segment) in [
            (274_878_169_088, 262_144),
            (4_092, 1_023),
            (16_777_218, 8_388_609),
        ] {
            expect_protocol_error(
                stream_segment_count(size, segment).unwrap_err(),
                "schema_violation",
                "segment_bounds_invalid",
            )?;
        }
        Ok(())
    }
}
