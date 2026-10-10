//! Offline cryptographic known-answer checks for the published KeyBackup fixture.
//! A valid signature here does not authorize this public test key at a Station.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, ensure};
use arkret_identity::test_material::{
    PublicKeyFingerprintInput, enforce_formal_test_material_policy,
};
use arkret_models_crypto::{KeyBackup, KeyBackupUnlockProof};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const FIXTURE: &str = "key-backup-hardening-fixture.json";

fn fixture_path() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root).join("fixtures").join(FIXTURE);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
        .join("fixtures")
        .join(FIXTURE)
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {name}"))
}

fn decode(value: &Value, name: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(field(value, name)?)
        .with_context(|| format!("invalid base64url {name}"))
}

fn verify_signature(key: &VerifyingKey, bytes: &[u8], encoded: &str) -> Result<()> {
    let raw = URL_SAFE_NO_PAD.decode(encoded)?;
    let signature = Signature::from_slice(&raw)?;
    key.verify_strict(bytes, &signature)?;
    Ok(())
}

/// Execute the fixture's AEAD and both Ed25519 transcripts with real crypto.
/// This deliberately proves only the offline KAT, not a live unlock outcome.
pub fn run_unlock_proof_crypto_kat() -> Result<()> {
    let fixture: Value = serde_json::from_slice(&std::fs::read(fixture_path())?)?;
    ensure!(
        fixture["version"] == "2026-09-24.4",
        "fixture version drifted"
    );
    let case = fixture["cases"]
        .as_array()
        .context("fixture cases missing")?
        .iter()
        .find(|case| case["name"] == "unlock_proof")
        .context("unlock_proof case missing")?;
    ensure!(
        case["expected"]["valid_unlock"] == "test_signing_material_denied",
        "published key live expectation drifted"
    );
    let transcript = &case["crypto_transcript"];
    ensure!(field(transcript, "aead")? == "chacha20_poly1305");

    let key = decode(transcript, "key_b64u")?;
    let nonce = decode(transcript, "nonce_b64u")?;
    ensure!(
        key.len() == 32 && nonce.len() == 12,
        "AEAD key/nonce size drifted"
    );
    let nonce = Nonce::try_from(nonce.as_slice()).context("AEAD nonce size drifted")?;
    let ciphertext = decode(transcript, "ciphertext_b64u")?;
    let tag = decode(transcript, "tag_b64u")?;
    ensure!(tag.len() == 16 && transcript["tag_length_bytes"] == 16);
    let combined = decode(transcript, "ciphertext_and_tag_b64u")?;
    ensure!(combined == [ciphertext.as_slice(), tag.as_slice()].concat());
    ensure!(combined == decode(&case["envelope"], "ciphertext")?);
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&combined)));
    ensure!(digest == field(transcript, "ciphertext_digest")?);
    ensure!(digest == field(&case["envelope"], "ciphertext_digest")?);
    ensure!(digest == field(&case["proof"], "ciphertext_digest")?);

    let aad = field(transcript, "aad_canonical_json")?.as_bytes();
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("invalid AEAD key"))?;
    let opened = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &combined,
                aad,
            },
        )
        .map_err(|_| anyhow!("fixture AEAD open failed"))?;
    ensure!(opened == field(transcript, "plaintext_canonical_json")?.as_bytes());
    let opened_value: Value = serde_json::from_slice(&opened)?;
    ensure!(opened_value == case["plaintext"]);
    ensure!(arkret_canonical::canonical_json_bytes(&opened_value)? == opened);
    let mut bad_tag = combined.clone();
    *bad_tag.last_mut().context("empty AEAD ciphertext")? ^= 1;
    ensure!(
        cipher
            .decrypt(&nonce, Payload { msg: &bad_tag, aad })
            .is_err(),
        "mutated AEAD tag opened"
    );

    let public_key = decode(&case["test_key"], "public_key")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow!("public key size"))?;
    let verifying = VerifyingKey::from_bytes(&public_key)?;
    let envelope: KeyBackup = serde_json::from_value(case["envelope"].clone())?;
    let proof: KeyBackupUnlockProof = serde_json::from_value(case["proof"].clone())?;
    ensure!(
        arkret_crypto::backup::key_backup_aead_aad(&envelope)? == aad,
        "fixture AAD differs from the production envelope derivation"
    );
    let seed = decode(&case["test_key"], "private_key_seed")?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| anyhow!("test seed size"))?;
    ensure!(SigningKey::from_bytes(&seed).verifying_key() == verifying);
    let envelope_bytes = envelope.signing_payload_bytes()?;
    let proof_bytes = proof.signing_payload_bytes()?;
    ensure!(envelope_bytes == field(transcript, "envelope_signing_jcs")?.as_bytes());
    ensure!(proof_bytes == field(transcript, "proof_signing_jcs")?.as_bytes());
    verify_signature(
        &verifying,
        &envelope_bytes,
        envelope.auth_data.signature.as_str(),
    )?;
    verify_signature(&verifying, &proof_bytes, proof.auth_data.signature.as_str())?;
    let mut changed_proof = proof_bytes.clone();
    changed_proof.push(b' ');
    ensure!(
        verify_signature(
            &verifying,
            &changed_proof,
            proof.auth_data.signature.as_str()
        )
        .is_err(),
        "mutated proof transcript retained a valid signature"
    );
    ensure!(
        enforce_formal_test_material_policy(
            Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(&public_key)),
            None,
            None,
            None,
        )
        .is_err(),
        "published test key escaped the shared admission guard"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn published_unlock_proof_crypto_transcript_is_valid_offline() {
        super::run_unlock_proof_crypto_kat().unwrap();
    }
}
