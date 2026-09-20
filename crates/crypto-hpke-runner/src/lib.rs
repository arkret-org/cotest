//! Executable RFC 9180 HPKE known-answer and fail-closed vectors.
//!
//! Positive cases drive the production `hpke-rs` provider and, for Arkret's
//! default suite, the SDK's production framed-value opener. Negative cases
//! prove authentication and wire-suite registry rejection before sink change.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, ensure};
use arkret_canonical::base64url::base64url_encode;
use arkret_wire::{HPKE_SUITES, HpkeSuiteId};
use hpke_rs::{Hpke, HpkePrivateKey, Mode};
use hpke_rs_crypto::HpkeCrypto;
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use serde_json::Value;

pub const CRYPTO_HPKE_ENTRYPOINT: &str = "ak.suite.crypto.hpke.v1";
pub const FIXTURE: &str = "hpke-suite-fixture.json";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub accepted_effects: usize,
    pub rejected_zero_effect: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoHpkeExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub accepted_effects: usize,
    pub rejected_zero_effects: usize,
}

#[derive(Clone, Copy)]
struct Algorithms {
    kem: KemAlgorithm,
    aead: AeadAlgorithm,
    kem_id: u16,
    aead_id: u16,
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

fn fixture() -> Result<Value> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read artifact {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse artifact {}", path.display()))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .with_context(|| format!("HPKE case has no string {field}"))
}

fn bytes(value: &Value, field: &str) -> Result<Vec<u8>> {
    hex::decode(text(value, field)?)
        .with_context(|| format!("HPKE case has invalid lowercase hex {field}"))
}

fn algorithms(vector: &Value) -> Result<Algorithms> {
    let kem = match text(vector, "kem")? {
        "dhkem_x25519_hkdf_sha256" => KemAlgorithm::DhKem25519,
        "dhkem_p256_hkdf_sha256" => KemAlgorithm::DhKemP256,
        other => return Err(anyhow!("unsupported fixture KEM {other}")),
    };
    let aead = match text(vector, "aead")? {
        "chacha20_poly1305" => AeadAlgorithm::ChaCha20Poly1305,
        "aes_256_gcm" => AeadAlgorithm::Aes256Gcm,
        other => return Err(anyhow!("unsupported fixture AEAD {other}")),
    };
    Ok(Algorithms {
        kem,
        aead,
        kem_id: kem as u16,
        aead_id: aead as u16,
    })
}

fn active_suite(suite: &str) -> bool {
    HPKE_SUITES
        .iter()
        .any(|row| row.canonical_id == suite && row.status == "active")
}

fn labeled_extract(salt: &[u8], suite_id: &[u8], label: &[u8], ikm: &[u8]) -> Result<Vec<u8>> {
    let mut labeled_ikm = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    HpkeRustCrypto::kdf_extract(KdfAlgorithm::HkdfSha256, salt, &labeled_ikm)
        .map_err(|error| anyhow!("production HPKE KDF extract failed: {error}"))
}

fn labeled_expand(
    prk: &[u8],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let length = u16::try_from(length).context("HPKE KDF output length exceeds u16")?;
    let mut labeled_info = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&length.to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    HpkeRustCrypto::kdf_expand(
        KdfAlgorithm::HkdfSha256,
        prk,
        &labeled_info,
        usize::from(length),
    )
    .map_err(|error| anyhow!("production HPKE KDF expand failed: {error}"))
}

fn key_schedule_intermediates(
    algorithms: Algorithms,
    info: &[u8],
    shared_secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut suite_id = b"HPKE".to_vec();
    suite_id.extend_from_slice(&algorithms.kem_id.to_be_bytes());
    suite_id.extend_from_slice(&(KdfAlgorithm::HkdfSha256 as u16).to_be_bytes());
    suite_id.extend_from_slice(&algorithms.aead_id.to_be_bytes());
    let psk_id_hash = labeled_extract(&[], &suite_id, b"psk_id_hash", &[])?;
    let info_hash = labeled_extract(&[], &suite_id, b"info_hash", info)?;
    let mut context = vec![Mode::Base as u8];
    context.extend_from_slice(&psk_id_hash);
    context.extend_from_slice(&info_hash);
    let secret = labeled_extract(shared_secret, &suite_id, b"secret", &[])?;
    Ok((context, secret))
}

fn shared_secret(
    algorithms: Algorithms,
    private_key: &[u8],
    recipient_public_key: &[u8],
    enc: &[u8],
) -> Result<Vec<u8>> {
    let dh = HpkeRustCrypto::dh(algorithms.kem, enc, private_key)
        .map_err(|error| anyhow!("production HPKE DH failed: {error}"))?;
    let mut suite_id = b"KEM".to_vec();
    suite_id.extend_from_slice(&algorithms.kem_id.to_be_bytes());
    let eae_prk = labeled_extract(&[], &suite_id, b"eae_prk", &dh)?;
    let mut kem_context = enc.to_vec();
    kem_context.extend_from_slice(recipient_public_key);
    labeled_expand(
        &eae_prk,
        &suite_id,
        b"shared_secret",
        &kem_context,
        algorithms.kem.shared_secret_len(),
    )
}

fn expected_nonce(base_nonce: &[u8], sequence: u64) -> Vec<u8> {
    let mut nonce = base_nonce.to_vec();
    for (offset, byte) in sequence.to_be_bytes().iter().rev().enumerate() {
        let index = nonce.len() - 1 - offset;
        nonce[index] ^= byte;
    }
    nonce
}

fn run_positive(
    vector: &Value,
    accepted_sink: &mut BTreeMap<String, Value>,
) -> Result<CaseExecutionResult> {
    let case_id = text(vector, "vector_id")?;
    let suite = text(vector, "suite")?;
    ensure!(
        active_suite(suite),
        "{case_id} names an inactive HPKE suite"
    );
    ensure!(
        HpkeSuiteId::from_wire(suite).is_some(),
        "{case_id} suite is absent from the production wire enum"
    );
    ensure!(
        text(vector, "mode")? == "base",
        "{case_id} is not base mode"
    );

    let algorithms = algorithms(vector)?;
    let info = bytes(vector, "info_hex")?;
    let ikm_r = bytes(vector, "ikmR_hex")?;
    let ikm_e = bytes(vector, "ikmE_hex")?;
    let sk_r = bytes(vector, "skRm_hex")?;
    let pk_r = bytes(vector, "pkRm_hex")?;
    let expected_enc = bytes(vector, "enc_hex")?;
    let mut hpke = Hpke::<HpkeRustCrypto>::new(
        Mode::Base,
        algorithms.kem,
        KdfAlgorithm::HkdfSha256,
        algorithms.aead,
    );
    let receiver_pair = hpke.derive_key_pair(&ikm_r)?;
    ensure!(
        receiver_pair.private_key().as_slice() == sk_r,
        "{case_id} receiver private key KAT differs"
    );
    ensure!(
        receiver_pair.public_key().as_slice() == pk_r,
        "{case_id} receiver public key KAT differs"
    );
    let ephemeral_pair = hpke.derive_key_pair(&ikm_e)?;
    ensure!(
        ephemeral_pair.private_key().as_slice() == bytes(vector, "skEm_hex")?,
        "{case_id} ephemeral private key KAT differs"
    );
    ensure!(
        ephemeral_pair.public_key().as_slice() == bytes(vector, "pkEm_hex")?,
        "{case_id} ephemeral public key KAT differs"
    );

    hpke.seed(&ikm_e)?;
    let (enc, mut sender) =
        hpke.setup_sender(receiver_pair.public_key(), &info, None, None, None)?;
    ensure!(enc == expected_enc, "{case_id} encapsulated key differs");
    let shared_secret = shared_secret(algorithms, &sk_r, &pk_r, &enc)
        .with_context(|| format!("{case_id} production decapsulation failed"))?;
    ensure!(
        shared_secret == bytes(vector, "shared_secret_hex")?,
        "{case_id} shared secret differs"
    );
    let (key_schedule_context, secret) =
        key_schedule_intermediates(algorithms, &info, &shared_secret)?;
    ensure!(
        key_schedule_context == bytes(vector, "key_schedule_context_hex")?,
        "{case_id} key schedule context differs"
    );
    ensure!(
        secret == bytes(vector, "secret_hex")?,
        "{case_id} key schedule secret differs"
    );
    ensure!(
        sender.key() == bytes(vector, "key_hex")?,
        "{case_id} AEAD key differs"
    );
    ensure!(
        sender.nonce() == bytes(vector, "base_nonce_hex")?,
        "{case_id} base nonce differs"
    );
    ensure!(
        sender.exporter_secret() == bytes(vector, "exporter_secret_hex")?,
        "{case_id} exporter secret differs"
    );

    let mut receiver = hpke.setup_receiver(
        &enc,
        &HpkePrivateKey::new(sk_r.clone()),
        &info,
        None,
        None,
        None,
    )?;
    let encryptions = vector["encryptions"]
        .as_array()
        .context("HPKE vector has no encryptions")?;
    for encryption in encryptions {
        let sequence = encryption["sequence_number"]
            .as_u64()
            .context("HPKE encryption has no sequence_number")?;
        ensure!(
            sender.sequence_number() == sequence,
            "{case_id} sender sequence drifted"
        );
        let aad = bytes(encryption, "aad_hex")?;
        let plaintext = bytes(encryption, "pt_hex")?;
        let ciphertext = bytes(encryption, "ct_hex")?;
        ensure!(
            expected_nonce(sender.nonce(), sequence) == bytes(encryption, "nonce_hex")?,
            "{case_id} per-message nonce differs"
        );
        ensure!(
            sender.seal(&aad, &plaintext)? == ciphertext,
            "{case_id} ciphertext differs"
        );
        ensure!(
            receiver.open(&aad, &ciphertext)? == plaintext,
            "{case_id} receiver plaintext differs"
        );
    }
    let exports = vector["exports"]
        .as_array()
        .context("HPKE vector has no exports")?;
    for export in exports {
        let context = bytes(export, "exporter_context_hex")?;
        let length = export["length"]
            .as_u64()
            .context("HPKE export has no length")? as usize;
        ensure!(
            sender.export(&context, length)? == bytes(export, "exported_value_hex")?,
            "{case_id} exported value differs"
        );
    }

    if suite == HpkeSuiteId::X25519AeadChacha20poly1305V1.as_str() {
        let first = &encryptions[0];
        let mut framed = enc.clone();
        framed.extend_from_slice(&bytes(first, "ct_hex")?);
        let opened = arkret_crypto::hpke::open_x25519_chacha20poly1305(
            &sk_r,
            &base64url_encode(framed),
            &info,
            &bytes(first, "aad_hex")?,
        )?;
        ensure!(
            opened == bytes(first, "pt_hex")?,
            "{case_id} Arkret framed opener differs"
        );
    }

    ensure!(
        accepted_sink
            .insert(case_id.to_owned(), vector.clone())
            .is_none()
    );
    Ok(CaseExecutionResult {
        case_id: case_id.to_owned(),
        assertions: 14 + encryptions.len() * 4 + exports.len(),
        accepted_effects: 1,
        rejected_zero_effect: false,
    })
}

fn expected_aead(suite: HpkeSuiteId) -> &'static str {
    match suite {
        HpkeSuiteId::P256AeadAes256gcmV1 | HpkeSuiteId::X25519AeadAes256gcmV1 => "aes_256_gcm",
        HpkeSuiteId::X25519AeadChacha20poly1305V1 | HpkeSuiteId::XwingAeadChacha20poly1305V1 => {
            "chacha20_poly1305"
        }
    }
}

fn run_negative(
    case: &Value,
    vectors: &[Value],
    accepted_sink: &mut BTreeMap<String, Value>,
) -> Result<CaseExecutionResult> {
    let case_id = text(case, "name")?;
    let before = accepted_sink.clone();
    ensure!(case["expected"]["decision"] == "reject");
    let assertions = 1 + match case_id {
        "reject_tampered_ciphertext" => {
            let base_id = text(case, "base_vector")?;
            let vector = vectors
                .iter()
                .find(|vector| vector["vector_id"] == base_id)
                .context("tamper case base vector is absent")?;
            let algorithms = algorithms(vector)?;
            let hpke = Hpke::<HpkeRustCrypto>::new(
                Mode::Base,
                algorithms.kem,
                KdfAlgorithm::HkdfSha256,
                algorithms.aead,
            );
            let mut receiver = hpke.setup_receiver(
                &bytes(vector, "enc_hex")?,
                &HpkePrivateKey::new(bytes(vector, "skRm_hex")?),
                &bytes(vector, "info_hex")?,
                None,
                None,
                None,
            )?;
            let aad = bytes(&vector["encryptions"][0], "aad_hex")?;
            ensure!(
                receiver
                    .open(&aad, &bytes(case, "tampered_ct_hex")?)
                    .is_err(),
                "tampered HPKE ciphertext was accepted"
            );
            2
        }
        "reject_unregistered_suite_id" => {
            let suite = text(case, "hpke_suite")?;
            ensure!(!active_suite(suite), "inactive HPKE suite was accepted");
            ensure!(
                HpkeSuiteId::from_wire(suite).is_none(),
                "unregistered HPKE suite unexpectedly has a production wire id"
            );
            ensure!(case["expected"]["error_code"] == "unsupported_hpke_suite");
            3
        }
        "reject_reserved_suite_on_wire" => {
            let suite = text(case, "hpke_suite")?;
            ensure!(!active_suite(suite), "reserved HPKE suite was accepted");
            ensure!(
                HpkeSuiteId::from_wire(suite).is_some(),
                "reserved HPKE suite is absent from the production wire enum"
            );
            ensure!(
                HPKE_SUITES
                    .iter()
                    .any(|row| row.canonical_id == suite && row.status == "reserved"),
                "reserved HPKE suite is absent from the production registry"
            );
            ensure!(case["expected"]["error_code"] == "unsupported_hpke_suite");
            4
        }
        "reject_selector_aead_mismatch" => {
            let suite_name = text(case, "hpke_suite")?;
            ensure!(
                active_suite(suite_name),
                "mismatch case suite is not active"
            );
            let suite = HpkeSuiteId::from_wire(suite_name)
                .context("mismatch case suite is not a production wire id")?;
            ensure!(
                text(case, "aead")? != expected_aead(suite),
                "mismatched AEAD was accepted"
            );
            ensure!(case["expected"]["error_code"] == "schema_violation");
            3
        }
        other => return Err(anyhow!("unknown HPKE negative case {other}")),
    };
    ensure!(
        *accepted_sink == before,
        "{case_id} changed the accepted application sink"
    );
    Ok(CaseExecutionResult {
        case_id: case_id.to_owned(),
        assertions: assertions + 1,
        accepted_effects: 0,
        rejected_zero_effect: true,
    })
}

pub fn run_crypto_hpke_suite() -> Result<CryptoHpkeExecution> {
    let fixture = fixture()?;
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(CRYPTO_HPKE_ENTRYPOINT),
        "HPKE fixture entrypoint drifted"
    );
    let vectors = fixture["vectors"]
        .as_array()
        .context("HPKE fixture has no vectors")?;
    let negative_cases = fixture["negative_cases"]
        .as_array()
        .context("HPKE fixture has no negative_cases")?;
    let mut accepted_sink = BTreeMap::new();
    let mut cases = Vec::with_capacity(vectors.len() + negative_cases.len());
    for vector in vectors {
        cases.push(run_positive(vector, &mut accepted_sink)?);
    }
    for case in negative_cases {
        cases.push(run_negative(case, vectors, &mut accepted_sink)?);
    }
    Ok(CryptoHpkeExecution {
        entrypoint: CRYPTO_HPKE_ENTRYPOINT,
        fixture: FIXTURE,
        accepted_effects: cases.iter().map(|case| case.accepted_effects).sum(),
        rejected_zero_effects: cases
            .iter()
            .filter(|case| case.rejected_zero_effect)
            .count(),
        cases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_all_positive_and_negative_cases_through_production_crypto() -> Result<()> {
        let execution = run_crypto_hpke_suite()?;
        assert_eq!(execution.cases.len(), 7);
        assert_eq!(execution.accepted_effects, 3);
        assert_eq!(execution.rejected_zero_effects, 4);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
        Ok(())
    }
}
