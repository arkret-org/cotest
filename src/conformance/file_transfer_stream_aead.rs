//! File-transfer streaming AEAD conformance vectors.
//!
//! Unlike the MLS attachment vectors, this suite consumes the authenticated
//! file-transfer record and its file-transfer-specific AAD transcript.

use anyhow::{Result, anyhow, bail};
use arkret_crypto::file_transfer_aead;
use arkret_models_collaboration::objects::productivity::{
    FileTransferKeyDelivery, FileTransferRecord,
};
use arkret_wire::ProfileId;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const VECTOR_ID_FILE_TRANSFER_STREAM_AEAD_BYTE_EXACT: &str =
    "ak.vector.file_transfer.stream_aead_byte_exact.v1";
pub const VECTOR_ID_FILE_TRANSFER_RANGE_BINDING_REJECTED: &str =
    "ak.vector.file_transfer.range_binding_rejected.v1";
pub const VECTOR_ID_FILE_TRANSFER_OVERALL_DIGEST_REJECTED: &str =
    "ak.vector.file_transfer.overall_digest_rejected.v1";

pub const ALL_FILE_TRANSFER_STREAM_AEAD_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_FILE_TRANSFER_STREAM_AEAD_BYTE_EXACT,
    VECTOR_ID_FILE_TRANSFER_RANGE_BINDING_REJECTED,
    VECTOR_ID_FILE_TRANSFER_OVERALL_DIGEST_REJECTED,
];

const FIXTURE_FILE: &str = "file-transfer-stream-aead-fixture.json";
const SUITE: &str = "file_transfer_stream_aead";

#[derive(Debug, Deserialize)]
struct Fixture {
    suite: String,
    covers_vectors: Vec<String>,
    vectors: Vec<FixtureVector>,
    kat: Kat,
}

#[derive(Debug, Deserialize)]
struct FixtureVector {
    vector_id: String,
    assertions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Kat {
    plaintext: PlaintextGenerator,
    content_key_b64u: String,
    #[serde(rename = "record_json", deserialize_with = "deserialize_record_json")]
    record: FileTransferRecord,
    ciphertext_b64u: String,
    segments: Vec<ExpectedSegment>,
    invalid_content_ranges: Vec<String>,
    invalid_overall_digest: String,
}

fn deserialize_record_json<'de, D>(
    deserializer: D,
) -> std::result::Result<FileTransferRecord, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    serde_json::from_str(&raw).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
struct PlaintextGenerator {
    generator: String,
    length: usize,
    modulus: usize,
}

#[derive(Debug, Deserialize)]
struct ExpectedSegment {
    index: u32,
    last_segment_flag: u8,
    nonce_b64u: String,
    aad_utf8: String,
    ciphertext_b64u: String,
    range: String,
    content_range: String,
}

fn load_fixture() -> Result<Fixture> {
    let raw = super::load_fixture_value(FIXTURE_FILE)?;
    super::validate_profile(&raw, ProfileId::FILE_TRANSFER_V1)?;
    let fixture: Fixture = super::parse_fixture_value(FIXTURE_FILE, raw)?;
    if fixture.suite != SUITE {
        bail!("file-transfer stream AEAD suite name drifted");
    }
    for vector_id in ALL_FILE_TRANSFER_STREAM_AEAD_VECTOR_IDS {
        if !fixture
            .covers_vectors
            .iter()
            .any(|covered| covered == vector_id)
        {
            bail!("file-transfer stream fixture does not cover {vector_id}");
        }
        let Some(vector) = fixture
            .vectors
            .iter()
            .find(|vector| vector.vector_id == *vector_id)
        else {
            bail!("file-transfer stream fixture has no definition for {vector_id}");
        };
        if vector.assertions.is_empty() {
            bail!("file-transfer stream vector {vector_id} has no assertions");
        }
    }
    Ok(fixture)
}

fn decode(value: &str, label: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| anyhow!("invalid {label} base64url: {error}"))
}

fn content_key(kat: &Kat) -> Result<[u8; 32]> {
    let bytes = decode(&kat.content_key_b64u, "content key")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("file-transfer KAT content key must be 32 bytes"))?;
    match &kat.record.encryption.key_delivery {
        FileTransferKeyDelivery::AccountDataWrappedKey { content_key }
            if content_key == &kat.content_key_b64u => {}
        _ => bail!("file-transfer KAT key delivery does not bind the fixed content key"),
    }
    Ok(key)
}

fn plaintext(generator: &PlaintextGenerator) -> Result<Vec<u8>> {
    if generator.generator != "byte_index_modulo"
        || generator.modulus == 0
        || generator.modulus > 256
    {
        bail!("unsupported file-transfer plaintext generator");
    }
    Ok((0..generator.length)
        .map(|index| (index % generator.modulus) as u8)
        .collect())
}

fn derive_nonce(record: &FileTransferRecord, segment: &ExpectedSegment) -> Result<[u8; 24]> {
    let prefix = record
        .encryption
        .nonce_prefix
        .as_deref()
        .ok_or_else(|| anyhow!("stream KAT record is missing nonce_prefix"))?;
    let prefix = decode(prefix, "nonce prefix")?;
    if prefix.len() != 19 || segment.last_segment_flag > 1 {
        bail!("invalid file-transfer segment nonce inputs");
    }
    let mut nonce = [0_u8; 24];
    nonce[..19].copy_from_slice(&prefix);
    nonce[19..23].copy_from_slice(&segment.index.to_be_bytes());
    nonce[23] = segment.last_segment_flag;
    if URL_SAFE_NO_PAD.encode(nonce) != segment.nonce_b64u {
        bail!("segment {} nonce bytes drifted", segment.index);
    }
    Ok(nonce)
}

fn validate_aad_fields(
    record: &FileTransferRecord,
    expected_count: u32,
    segment: &ExpectedSegment,
) -> Result<()> {
    let value: Value = serde_json::from_str(&segment.aad_utf8)?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("segment AAD must be a JSON object"))?;
    let expected_keys = [
        "created_at",
        "last_segment_flag",
        "media_type",
        "nonce_prefix",
        "origin_device_id",
        "purpose",
        "schema",
        "scheme",
        "segment_count",
        "segment_index",
        "size_bytes",
        "transfer_id",
    ];
    if object.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !object.contains_key(*key))
    {
        bail!(
            "segment {} AAD is not the closed file-transfer transcript",
            segment.index
        );
    }
    let nonce_prefix = record.encryption.nonce_prefix.as_deref();
    if object.get("schema").and_then(Value::as_str) != Some(record.encryption.aad.schema.as_str())
        || object.get("purpose").and_then(Value::as_str)
            != Some(record.encryption.aad.purpose.as_str())
        || object.get("transfer_id").and_then(Value::as_str) != Some(record.transfer_id.as_str())
        || object.get("origin_device_id").and_then(Value::as_str)
            != Some(record.origin_device_id.as_str())
        || object.get("created_at").and_then(Value::as_str) != Some(record.created_at.as_str())
        || object.get("scheme").and_then(Value::as_str) != Some(record.encryption.scheme.as_str())
        || object.get("nonce_prefix").and_then(Value::as_str) != nonce_prefix
        || object.get("segment_index").and_then(Value::as_u64) != Some(u64::from(segment.index))
        || object.get("last_segment_flag").and_then(Value::as_u64)
            != Some(u64::from(segment.last_segment_flag))
        || object.get("segment_count").and_then(Value::as_u64) != Some(u64::from(expected_count))
        || object.get("media_type").and_then(Value::as_str) != Some(record.media_type.as_str())
        || object.get("size_bytes").and_then(Value::as_u64) != Some(record.plaintext_size_bytes)
    {
        bail!(
            "segment {} AAD fields drifted from the record",
            segment.index
        );
    }
    if serde_json::to_string(&value)? != segment.aad_utf8 {
        bail!(
            "segment {} AAD is not compact canonical JSON",
            segment.index
        );
    }
    Ok(())
}

fn validate_content_range(
    value: &str,
    expected_start: u64,
    expected_end: u64,
    expected_total: u64,
) -> Result<()> {
    let body = value
        .strip_prefix("bytes ")
        .ok_or_else(|| anyhow!("Content-Range unit is not bytes"))?;
    let (span, total) = body
        .split_once('/')
        .ok_or_else(|| anyhow!("Content-Range is missing total length"))?;
    let (start, end) = span
        .split_once('-')
        .ok_or_else(|| anyhow!("Content-Range is missing byte span"))?;
    let start: u64 = start.parse()?;
    let end: u64 = end.parse()?;
    let total: u64 = total.parse()?;
    if start != expected_start || end != expected_end || total != expected_total {
        bail!("Content-Range does not match authenticated segment geometry");
    }
    Ok(())
}

pub fn run_file_transfer_stream_aead_byte_exact_vector() -> Result<()> {
    let fixture = load_fixture()?;
    let kat = fixture.kat;
    kat.record.validate()?;
    let plaintext = plaintext(&kat.plaintext)?;
    let key = content_key(&kat)?;
    let expected_ciphertext = decode(&kat.ciphertext_b64u, "ciphertext")?;
    let count = file_transfer_aead::segment_count(&kat.record)?;
    if count as usize != kat.segments.len()
        || plaintext.len() as u64 != kat.record.plaintext_size_bytes
    {
        bail!("file-transfer KAT segment or plaintext count drifted");
    }

    let sdk_ciphertext = file_transfer_aead::encrypt(
        &kat.record.encryption,
        &kat.record.media_type,
        &plaintext,
        &key,
    )?;
    if sdk_ciphertext != expected_ciphertext {
        bail!("SDK did not reproduce the byte-exact file-transfer ciphertext");
    }

    let independent_cipher = XChaCha20Poly1305::new((&key).into());
    let mut independently_sealed = Vec::with_capacity(expected_ciphertext.len());
    let mut independently_opened = Vec::with_capacity(plaintext.len());
    for (position, segment) in kat.segments.iter().enumerate() {
        if segment.index as usize != position
            || segment.last_segment_flag != u8::from(position + 1 == kat.segments.len())
        {
            bail!("file-transfer KAT segments are not in exact order");
        }
        let plan = file_transfer_aead::segment(&kat.record, segment.index)?;
        validate_aad_fields(&kat.record, count, segment)?;
        let nonce = derive_nonce(&kat.record, segment)?;
        let expected_segment = decode(&segment.ciphertext_b64u, "segment ciphertext")?;
        let plaintext_start = usize::try_from(
            u64::from(segment.index)
                * u64::from(
                    kat.record
                        .encryption
                        .segment_bytes
                        .ok_or_else(|| anyhow!("stream KAT is missing segment_bytes"))?,
                ),
        )?;
        let plaintext_end = plaintext_start + plan.plaintext_len;
        let sealed = independent_cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext[plaintext_start..plaintext_end],
                    aad: segment.aad_utf8.as_bytes(),
                },
            )
            .map_err(|error| anyhow!("independent segment seal failed: {error}"))?;
        if sealed != expected_segment {
            bail!(
                "independent AEAD consumer did not reproduce segment {}",
                segment.index
            );
        }
        let opened = independent_cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &expected_segment,
                    aad: segment.aad_utf8.as_bytes(),
                },
            )
            .map_err(|error| anyhow!("independent segment open failed: {error}"))?;
        if opened != plaintext[plaintext_start..plaintext_end] {
            bail!(
                "independent AEAD consumer did not recover segment {}",
                segment.index
            );
        }
        let sdk_opened = file_transfer_aead::decrypt_segment(
            &kat.record,
            segment.index,
            &expected_segment,
            &key,
        )?;
        if sdk_opened != opened {
            bail!("SDK segment open differs from independent consumer");
        }
        independently_sealed.extend_from_slice(&sealed);
        independently_opened.extend_from_slice(&opened);
    }
    if independently_sealed != expected_ciphertext || independently_opened != plaintext {
        bail!("file-transfer segment concatenation drifted");
    }
    if file_transfer_aead::decrypt(&kat.record, &expected_ciphertext, &key)? != plaintext {
        bail!("SDK whole-object open did not recover the KAT plaintext");
    }
    Ok(())
}

pub fn run_file_transfer_range_binding_rejected_vector() -> Result<()> {
    let fixture = load_fixture()?;
    let kat = fixture.kat;
    let key = content_key(&kat)?;
    let ciphertext = decode(&kat.ciphertext_b64u, "ciphertext")?;

    for segment in &kat.segments {
        let plan = file_transfer_aead::segment(&kat.record, segment.index)?;
        if segment.range != format!("bytes={}-{}", plan.ciphertext_start, plan.ciphertext_end) {
            bail!("segment {} Range header drifted", segment.index);
        }
        validate_content_range(
            &segment.content_range,
            plan.ciphertext_start,
            plan.ciphertext_end,
            kat.record.blob_size_bytes,
        )?;
        let start = usize::try_from(plan.ciphertext_start)?;
        let end = usize::try_from(plan.ciphertext_end + 1)?;
        let exact = &ciphertext[start..end];
        file_transfer_aead::decrypt_segment(&kat.record, segment.index, exact, &key)?;

        let mut tampered = exact.to_vec();
        tampered[0] ^= 1;
        if file_transfer_aead::decrypt_segment(&kat.record, segment.index, &tampered, &key).is_ok()
        {
            bail!("tampered segment {} was accepted", segment.index);
        }
        if file_transfer_aead::decrypt_segment(
            &kat.record,
            segment.index,
            &exact[..exact.len() - 1],
            &key,
        )
        .is_ok()
        {
            bail!("truncated segment {} was accepted", segment.index);
        }
    }

    let first = file_transfer_aead::segment(&kat.record, 0)?;
    for invalid in &kat.invalid_content_ranges {
        if validate_content_range(
            invalid,
            first.ciphertext_start,
            first.ciphertext_end,
            kat.record.blob_size_bytes,
        )
        .is_ok()
        {
            bail!("invalid Content-Range was accepted: {invalid}");
        }
    }
    Ok(())
}

pub fn run_file_transfer_overall_digest_rejected_vector() -> Result<()> {
    let fixture = load_fixture()?;
    let kat = fixture.kat;
    let key = content_key(&kat)?;
    let ciphertext = decode(&kat.ciphertext_b64u, "ciphertext")?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&ciphertext)));
    if digest != kat.record.content_digest
        || kat.record.blob_ref != format!("ak:blob:{digest}")
        || ciphertext.len() as u64 != kat.record.blob_size_bytes
    {
        bail!("file-transfer KAT overall ciphertext digest drifted");
    }

    for segment in &kat.segments {
        let plan = file_transfer_aead::segment(&kat.record, segment.index)?;
        let start = usize::try_from(plan.ciphertext_start)?;
        let end = usize::try_from(plan.ciphertext_end + 1)?;
        file_transfer_aead::decrypt_segment(
            &kat.record,
            segment.index,
            &ciphertext[start..end],
            &key,
        )?;
    }

    let mut wrong_digest_record = kat.record.clone();
    wrong_digest_record.content_digest = kat.invalid_overall_digest.clone();
    wrong_digest_record.blob_ref = format!("ak:blob:{}", kat.invalid_overall_digest);
    if file_transfer_aead::decrypt(&wrong_digest_record, &ciphertext, &key).is_ok() {
        bail!("file-transfer output was accepted with a mismatched overall digest");
    }
    Ok(())
}

pub fn run_file_transfer_stream_aead_fixture_suite() -> Result<()> {
    run_file_transfer_stream_aead_byte_exact_vector()?;
    run_file_transfer_range_binding_rejected_vector()?;
    run_file_transfer_overall_digest_rejected_vector()?;
    Ok(())
}
