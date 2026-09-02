//! Key-backup encryption and recovery-bridge / restore-workflow wire-model
//! conformance vectors, including the recovery-ticket state machine.

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use serde_json::{Value, json};

use super::{emit_vector, expected_outcome, expected_reason, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

const ARGON2ID_MEMORY_KIB: u32 = 65_536;
const ARGON2ID_ITERATIONS: u32 = 3;
const ARGON2ID_PARALLELISM: u32 = 1;

/// D4 — key backup encryption: Argon2id + XChaCha20-Poly1305 round-trip.
///
/// Spec: `crypto-media/encryption-and-audit.md` + `key-backup.schema.json`.
/// Validator runs a real Argon2id derivation with the fixture's salt + spec
/// floor checks, then XChaCha20-Poly1305 round-trips a small
/// payload to confirm encrypt/decrypt with the correct key succeeds and
/// decrypt with a wrong key fails (auth-tag rejection).
pub fn run_key_backup_encryption_fixture_suite() -> Result<()> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

    let fixture = load_local_fixture("key_backup_encryption_fixture.json")?;
    validate_profile(&fixture, "ak.profile.key_backup_encryption_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("key_backup_encryption fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "key_backup_encryption fixture has {} vectors, expected >= 4",
            vectors.len()
        );
    }

    // Drive a real Argon2id + XChaCha20-Poly1305 round-trip to validate the
    // primitive set the spec mandates is callable from this harness.
    let salt_b64 = "AAECAwQFBgcICQoLDA0ODw";
    let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(salt_b64)
        .map_err(|e| anyhow!("decode salt: {e}"))?;
    let master_key = derive_argon2id_key(b"correct-passphrase", &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&master_key)
        .map_err(|e| anyhow!("XChaCha20-Poly1305 key init: {e}"))?;
    let nonce_bytes = [0u8; 24];
    let nonce = XNonce::from(nonce_bytes);
    let plaintext = b"session_keys_blob";
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| anyhow!("XChaCha20-Poly1305 encrypt: {e}"))?;
    let decrypted = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| anyhow!("XChaCha20-Poly1305 decrypt: {e}"))?;
    if decrypted != plaintext {
        bail!("XChaCha20-Poly1305 round-trip mismatch");
    }
    // Wrong-key decrypt must fail (forward-only AEAD).
    let wrong = derive_argon2id_key(b"wrong-passphrase", &salt)?;
    let wrong_cipher = XChaCha20Poly1305::new_from_slice(&wrong)
        .map_err(|e| anyhow!("XChaCha20-Poly1305 wrong-key init: {e}"))?;
    if wrong_cipher.decrypt(&nonce, ciphertext.as_ref()).is_ok() {
        bail!("wrong-key decrypt succeeded — AEAD broken");
    }

    // Rotation invariants: round-trip with new salt produces a different
    // master_key (forward-secret), and the old ciphertext must NOT decrypt
    // with the new key.
    let new_salt_b64 = "EBESExQVFhcYGRobHB0eHw";
    let new_salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(new_salt_b64)
        .map_err(|e| anyhow!("decode new salt: {e}"))?;
    let master_key_v2 = derive_argon2id_key(b"correct-passphrase", &new_salt)?;
    if master_key == master_key_v2 {
        bail!("rotation salt change must produce different master key");
    }
    let cipher_v2 = XChaCha20Poly1305::new_from_slice(&master_key_v2)
        .map_err(|e| anyhow!("XChaCha20-Poly1305 rotation key init: {e}"))?;
    if cipher_v2.decrypt(&nonce, ciphertext.as_ref()).is_ok() {
        bail!("post-rotation cipher decrypted pre-rotation ciphertext — rotation invariant broken");
    }

    // 05-1 — assert the SDK's authoritative `KeyBackupEncryption` validator is
    // actually wired and fails closed on malformed `passphrase_kdf` envelopes,
    // rather than relying only on this harness's structural serde_json checks.
    assert_sdk_rejects_malformed_passphrase_kdf_envelopes()?;

    let mut saw_kdf = false;
    let mut saw_opaque = false;
    let mut saw_restore = false;
    let mut saw_rotation_vector = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        if outcome != "accept" {
            bail!("vector {name} outcome must be accept");
        }
        match name {
            "client_side_passphrase_derives_master_key" => {
                let kdf = v
                    .get("kdf")
                    .ok_or_else(|| anyhow!("vector {name} missing kdf"))?;
                validate_argon2id_kdf_floor(name, kdf)?;
                let key_len = v
                    .get("master_key_length_bytes")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing master_key_length_bytes"))?;
                if key_len != 32 {
                    bail!("vector {name} master_key_length_bytes must be 32");
                }
                let pp_uploaded = v
                    .pointer("/expected/passphrase_uploaded")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("vector {name} missing passphrase_uploaded"))?;
                if pp_uploaded {
                    bail!("vector {name} passphrase_uploaded MUST be false (zero-knowledge)");
                }
                // 05-1 — converge onto the SDK's authoritative validator: the
                // `passphrase_kdf` envelope this vector implies must deserialize
                // into `arkret_models_crypto::KeyBackupEncryption` (running its
                // recipient-method `validate()` shim) and pass.
                let salt_b64 = required_str(v, "salt_b64")?;
                assert_passphrase_kdf_envelope_valid_via_sdk(name, kdf, salt_b64)?;
                saw_kdf = true;
            }
            "server_side_blob_storage_opaque" => {
                let opaque = v
                    .pointer("/expected/server_seen_plaintext")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("vector {name} missing server_seen_plaintext"))?;
                if opaque {
                    bail!("vector {name} server_seen_plaintext MUST be false");
                }
                saw_opaque = true;
            }
            "restore_path_redrives_key_and_decrypts" => {
                let kdf = v
                    .get("kdf")
                    .ok_or_else(|| anyhow!("vector {name} missing kdf"))?;
                validate_argon2id_kdf_floor(name, kdf)?;
                let succeeded = v
                    .pointer("/expected/decryption_succeeded")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let auth_verified = v
                    .pointer("/expected/auth_tag_verified")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !(succeeded && auth_verified) {
                    bail!(
                        "vector {name} restore must assert decryption_succeeded + auth_tag_verified"
                    );
                }
                // 05-1 — same SDK-authoritative convergence on the restore path:
                // the re-derived envelope must remain a legal SDK
                // `KeyBackupEncryption`.
                let salt_b64 = required_str(v, "salt_b64")?;
                assert_passphrase_kdf_envelope_valid_via_sdk(name, kdf, salt_b64)?;
                saw_restore = true;
            }
            "rotation_mints_new_version_and_reencrypts" => {
                let new_kdf = v
                    .get("new_kdf")
                    .ok_or_else(|| anyhow!("vector {name} missing new_kdf"))?;
                validate_argon2id_kdf_floor(name, new_kdf)?;
                let old = required_str(v, "old_version_id")?;
                let new = required_str(v, "new_version_id")?;
                if old == new {
                    bail!("vector {name} rotation must mint a different version_id");
                }
                let new_uploaded = v
                    .pointer("/expected/new_version_uploaded")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !new_uploaded {
                    bail!("vector {name} rotation must upload new_version");
                }
                // 05-1 — the freshly-minted rotation envelope must also be a
                // legal SDK `KeyBackupEncryption` under the new KDF + salt.
                let new_salt_b64 = required_str(v, "new_salt_b64")?;
                assert_passphrase_kdf_envelope_valid_via_sdk(name, new_kdf, new_salt_b64)?;
                saw_rotation_vector = true;
            }
            other => bail!("vector unexpected name {other}"),
        }
        emit_vector(
            "key_backup_encryption.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }
    if !(saw_kdf && saw_opaque && saw_restore && saw_rotation_vector) {
        bail!("key_backup_encryption fixture missing coverage");
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("key_backup_encryption fixture missing negative_vectors[]"))?;
    let mut saw_low_iter = false;
    let mut saw_wrong_pp = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let reason =
            expected_reason(v).ok_or_else(|| anyhow!("negative {name} missing reason_code"))?;
        match reason {
            "kdf_argon2id_params_too_weak" => {
                let kdf = v
                    .get("kdf")
                    .ok_or_else(|| anyhow!("negative {name} missing kdf"))?;
                if argon2id_kdf_meets_floor(kdf)? {
                    bail!("negative {name} declares weak Argon2id params but meets the floor");
                }
                saw_low_iter = true;
            }
            "key_backup_decrypt_auth_failed" => {
                let correct = v
                    .get("passphrase_correct")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                if correct {
                    bail!("negative {name} declares auth fail but passphrase_correct=true");
                }
                saw_wrong_pp = true;
            }
            other => bail!("negative {name} unknown reason_code {other}"),
        }
    }
    if !(saw_low_iter && saw_wrong_pp) {
        bail!("key_backup_encryption negatives must cover low_iter + wrong_passphrase");
    }

    Ok(())
}
/// Standalone — exercise the spec's mandated AEAD primitive
/// (XChaCha20-Poly1305 + Argon2id) end-to-end. Decoupled from the
/// fixture so an environment without the fixture file still exercises the
/// crypto round-trip used by D4 key backup encryption.
pub fn run_key_backup_aead_round_trip_check() -> Result<()> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

    let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode("AAECAwQFBgcICQoLDA0ODw")
        .map_err(|e| anyhow!("decode salt: {e}"))?;
    let key = derive_argon2id_key(b"correct-passphrase", &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("XChaCha20-Poly1305 key init: {e}"))?;
    let nonce = XNonce::from([0u8; 24]);
    let plaintext = b"key_backup_aead_round_trip_round_26";
    let ct = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| anyhow!("encrypt failed: {e}"))?;
    let pt = cipher
        .decrypt(&nonce, ct.as_ref())
        .map_err(|e| anyhow!("decrypt failed: {e}"))?;
    if pt != plaintext {
        bail!("AEAD round-trip mismatch");
    }
    let wrong = derive_argon2id_key(b"wrong-passphrase", &salt)?;
    let wrong_cipher = XChaCha20Poly1305::new_from_slice(&wrong)
        .map_err(|e| anyhow!("XChaCha20-Poly1305 wrong-key init: {e}"))?;
    if wrong_cipher.decrypt(&nonce, ct.as_ref()).is_ok() {
        bail!("wrong-key decrypt succeeded — AEAD invariant broken");
    }
    Ok(())
}

/// 05-1 — build the `passphrase_kdf` `encryption` envelope implied by a fixture
/// vector and deserialize it into the SDK's authoritative
/// [`arkret_models_crypto::KeyBackupEncryption`], which runs its recipient-method
/// `validate()` shim (`key-backup.schema.json` `encryption.allOf[].if/then`:
/// passphrase_kdf REQUIRES `kdf` + `aead.nonce` + `aead.nonce_salt` and FORBIDS
/// `hpke_suite`). Replaces a bespoke `serde_json::Value` re-derivation of those
/// rules with the SDK's single source of truth.
fn assert_passphrase_kdf_envelope_valid_via_sdk(
    name: &str,
    kdf: &Value,
    salt_b64: &str,
) -> Result<()> {
    let memory_kib = kdf
        .get("memory_kib")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("vector {name} kdf missing memory_kib"))?;
    let iterations = kdf
        .get("iterations")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("vector {name} kdf missing iterations"))?;
    let parallelism = kdf
        .get("parallelism")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("vector {name} kdf missing parallelism"))?;
    let encryption_json = json!({
        "recipient_method": "passphrase_kdf",
        "kdf": {
            "name": "argon2id",
            "salt": salt_b64,
            "params": {
                "memory_kib": memory_kib,
                "iterations": iterations,
                "parallelism": parallelism,
            },
        },
        "aead": {
            "name": "xchacha20_poly1305",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "nonce_salt": salt_b64,
        },
    });
    let encryption: arkret_models_crypto::KeyBackupEncryption =
        serde_json::from_value(encryption_json).map_err(|e| {
            anyhow!(
                "vector {name} passphrase_kdf envelope must deserialize into SDK \
                 KeyBackupEncryption (runs authoritative validate()): {e}"
            )
        })?;
    // Re-run the authoritative validator explicitly (idempotent with the
    // deserialize `try_from` shim) to pin cotest onto the SDK's rules.
    encryption.validate().map_err(|e| {
        anyhow!(
            "vector {name} SDK KeyBackupEncryption::validate() rejected a well-formed envelope: {e}"
        )
    })?;
    if encryption.recipient_method != arkret_models_crypto::KeyBackupRecipientMethod::PassphraseKdf
    {
        bail!("vector {name} SDK parsed recipient_method != passphrase_kdf");
    }
    Ok(())
}

/// 05-1 — prove the SDK validator fails closed: two malformed `passphrase_kdf`
/// envelopes (missing `aead.nonce_salt`; carrying a `recovery_public_key`-only
/// `hpke_suite`) MUST be rejected by `arkret_models_crypto::KeyBackupEncryption`'s
/// deserialize/validate shim. Guards against the SDK validator silently going
/// permissive underneath cotest's positive assertions.
fn assert_sdk_rejects_malformed_passphrase_kdf_envelopes() -> Result<()> {
    let missing_nonce_salt = json!({
        "recipient_method": "passphrase_kdf",
        "kdf": {"name": "argon2id", "salt": "AAAA",
                "params": {"memory_kib": 65536, "iterations": 3, "parallelism": 1}},
        "aead": {"name": "xchacha20_poly1305", "nonce": "AAAA"},
    });
    if serde_json::from_value::<arkret_models_crypto::KeyBackupEncryption>(missing_nonce_salt)
        .is_ok()
    {
        bail!("SDK KeyBackupEncryption accepted a passphrase_kdf envelope missing aead.nonce_salt");
    }
    let stray_hpke_suite = json!({
        "recipient_method": "passphrase_kdf",
        "kdf": {"name": "argon2id", "salt": "AAAA",
                "params": {"memory_kib": 65536, "iterations": 3, "parallelism": 1}},
        "aead": {"name": "xchacha20_poly1305", "nonce": "AAAA", "nonce_salt": "AAAAAAAAAAAAAAAA"},
        "hpke_suite": "ak.hpke_x25519_aead_chacha20poly1305.v1",
    });
    if serde_json::from_value::<arkret_models_crypto::KeyBackupEncryption>(stray_hpke_suite).is_ok()
    {
        bail!("SDK KeyBackupEncryption accepted a passphrase_kdf envelope carrying hpke_suite");
    }
    Ok(())
}

fn derive_argon2id_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(
        ARGON2ID_MEMORY_KIB,
        ARGON2ID_ITERATIONS,
        ARGON2ID_PARALLELISM,
        Some(32),
    )
    .map_err(|e| anyhow!("Argon2id params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| anyhow!("Argon2id derive: {e}"))?;
    Ok(key)
}

fn validate_argon2id_kdf_floor(label: &str, kdf: &Value) -> Result<()> {
    let name = required_str(kdf, "name")?;
    if name != "argon2id" {
        bail!("{label} kdf.name must be argon2id, got {name}");
    }
    if !argon2id_kdf_meets_floor(kdf)? {
        bail!(
            "{label} Argon2id params must be at least memory_kib={}, iterations={}, parallelism={}",
            ARGON2ID_MEMORY_KIB,
            ARGON2ID_ITERATIONS,
            ARGON2ID_PARALLELISM
        );
    }
    Ok(())
}

fn argon2id_kdf_meets_floor(kdf: &Value) -> Result<bool> {
    let memory = kdf
        .get("memory_kib")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Argon2id kdf missing memory_kib"))?;
    let iterations = kdf
        .get("iterations")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Argon2id kdf missing iterations"))?;
    let parallelism = kdf
        .get("parallelism")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Argon2id kdf missing parallelism"))?;
    Ok(memory >= u64::from(ARGON2ID_MEMORY_KIB)
        && iterations >= u64::from(ARGON2ID_ITERATIONS)
        && parallelism >= u64::from(ARGON2ID_PARALLELISM))
}
/// F-1 — recovery bridge full-chain state-machine legality.
///
/// Spec: services/coauth-recovery.md + services/soland-recovery-ticket.md +
/// services/restore-executor.md. The chain has 5 ordered steps:
/// principal_cache_lookup → recovery_action_proof → recovery_ticket_mint →
/// restore_execute → final_state_observe. Each vector pins one step's
/// transition; this validator asserts each step's invariants and that the
/// state-machine transitions on the ticket are legal: issued → executing →
/// executed (or issued → expired / cancelled).
pub fn run_recovery_bridge_full_chain_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("recovery_bridge_full_chain_fixture.json")?;
    validate_profile(&fixture, "ak.profile.recovery_bridge_full_chain_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("recovery_bridge_full_chain fixture missing vectors[]"))?;
    if vectors.len() < 3 {
        bail!(
            "recovery_bridge_full_chain fixture has {} vectors, expected >= 3",
            vectors.len()
        );
    }

    let valid_steps = [
        "principal_cache_lookup",
        "recovery_action_proof",
        "recovery_ticket_mint",
        "restore_execute",
        "final_state_observe",
    ];
    let valid_actions = [
        "recover_session_grants",
        "restore_key_backup",
        "rotate_recovery_key",
    ];

    let mut covered_steps = std::collections::BTreeSet::<String>::new();
    for v in vectors {
        let name = required_str(v, "name")?;
        let step = required_str(v, "step")?;
        if !valid_steps.contains(&step) {
            bail!("vector {name} unknown step {step}");
        }
        let outcome = expected_outcome(v, name)?;
        if outcome != "accept" {
            bail!("positive vector {name} outcome must be accept");
        }
        match step {
            "principal_cache_lookup" => {
                let _ = required_str(v, "account_did")?;
                let _ = v
                    .pointer("/expected/principal_realm_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing principal_realm_id"))?;
            }
            "recovery_action_proof" => {
                let kind = required_str(v, "action_kind")?;
                if !valid_actions.contains(&kind) {
                    bail!("vector {name} action_kind {kind} not supported");
                }
                let required = v
                    .get("approvals_required")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing approvals_required"))?;
                let received = v
                    .get("approvals_received")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing approvals_received"))?;
                if received < required {
                    bail!("vector {name} approvals_received {received} < required {required}");
                }
            }
            "recovery_ticket_mint" => {
                let state = required_str(v, "ticket_state")?;
                if state != "issued" {
                    bail!("vector {name} ticket_state must start at issued");
                }
                let ttl = v
                    .pointer("/expected/ttl_seconds")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing ttl_seconds"))?;
                if ttl == 0 || ttl > 86_400 {
                    bail!("vector {name} ttl_seconds {ttl} out of bounds (1..=86400)");
                }
                let consume_once = v
                    .pointer("/expected/consume_once")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !consume_once {
                    bail!("vector {name} ticket must be consume_once");
                }
            }
            "restore_execute" => {
                let transitions: Vec<&str> = v
                    .get("ticket_state_transitions")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if !validate_ticket_state_transitions(&transitions) {
                    bail!(
                        "vector {name} ticket transitions {transitions:?} not legal per state-machine"
                    );
                }
                let after = v
                    .pointer("/expected/ticket_state_after")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing ticket_state_after"))?;
                if after != "executed" {
                    bail!("vector {name} ticket_state_after must be executed");
                }
            }
            "final_state_observe" => {
                let _ = required_str(v, "realm_id")?;
                let _ = v
                    .pointer("/expected/audit_log_emitted")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("vector {name} missing audit_log_emitted"))?;
            }
            _ => unreachable!(),
        }
        covered_steps.insert(step.to_owned());
        emit_vector(
            "recovery_bridge_full_chain.step",
            v,
            json!({"name": name, "step": step, "outcome": outcome}),
        );
    }
    if covered_steps.len() < 3 {
        bail!(
            "recovery_bridge_full_chain must cover at least 3 chain steps; got {}",
            covered_steps.len()
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("recovery_bridge_full_chain fixture missing negative_vectors[]"))?;
    let mut saw_expired = false;
    let mut saw_double_consume = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let reason =
            expected_reason(v).ok_or_else(|| anyhow!("negative {name} missing reason_code"))?;
        match reason {
            "recovery_proof_expired" => {
                let in_past = v
                    .get("proof_exp_in_past")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !in_past {
                    bail!("negative {name} expired must declare proof_exp_in_past=true");
                }
                saw_expired = true;
            }
            "ticket_already_consumed" => {
                let before = required_str(v, "ticket_state_before")?;
                if before != "executed" {
                    bail!("negative {name} double-consume ticket_state_before must be executed");
                }
                let outcome = expected_outcome(v, name)?;
                if outcome != "idempotent_replay" {
                    bail!(
                        "negative {name} double-consume must outcome idempotent_replay (consume-once invariant)"
                    );
                }
                saw_double_consume = true;
            }
            other => bail!("negative {name} unknown reason_code {other}"),
        }
    }
    if !(saw_expired && saw_double_consume) {
        bail!("recovery_bridge_full_chain negatives must cover expired_proof + double_consume");
    }

    Ok(())
}
/// Standalone — recovery-ticket state-machine legality.
pub fn run_recovery_ticket_state_machine_check() -> Result<()> {
    let legal_paths: &[&[&str]] = &[
        &["issued", "executing", "executed"],
        &["issued", "executing", "failed"],
        &["issued", "executing", "cancelled"],
        &["issued", "cancelled"],
        &["issued", "expired"],
    ];
    for path in legal_paths {
        if !validate_ticket_state_transitions(path) {
            bail!("legal path {path:?} rejected as illegal");
        }
    }
    let illegal_paths: &[&[&str]] = &[
        &["executing", "executed"],          // missing issued
        &["issued", "executed"],             // skip executing
        &["issued", "executing", "issued"],  // backward
        &["issued", "expired", "executing"], // post-terminal
    ];
    for path in illegal_paths {
        if validate_ticket_state_transitions(path) {
            bail!("illegal path {path:?} accepted as legal");
        }
    }
    Ok(())
}
/// F-2 — restore approval/executor/artifact full workflows.
pub fn run_restore_full_workflows_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("restore_full_workflows_fixture.json")?;
    validate_profile(&fixture, "ak.profile.restore_full_workflows_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("restore_full_workflows missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "restore_full_workflows requires >= 4 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_two_of_two_approval = false;
    let mut saw_duplicate_approver = false;
    let mut saw_executor_restart = false;
    let mut saw_artifact_round_trip = false;
    let mut saw_integrity_mismatch = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = expected_outcome(v, name)?;
        let _ = required_str(v, "ticket_id")?;
        match name {
            "two_of_two_multi_admin_approval_unblocks_restore" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let req = v
                    .get("required_approvals")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("vector {name} missing required_approvals"))?;
                if req < 2 {
                    bail!("vector {name} multi-admin approval requires >= 2");
                }
                let seq = v
                    .get("approval_sequence")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing approval_sequence"))?;
                let mut distinct = std::collections::BTreeSet::<&str>::new();
                for a in seq {
                    distinct.insert(required_str(a, "admin_did")?);
                }
                if (distinct.len() as u64) < req {
                    bail!(
                        "vector {name} positive strand needs >= {req} distinct admin_dids; got {}",
                        distinct.len()
                    );
                }
                let after_first = v
                    .pointer("/expected/stage_after_first_approval")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing stage_after_first_approval"))?;
                let after_second = v
                    .pointer("/expected/stage_after_second_approval")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing stage_after_second_approval"))?;
                if after_first != "approving" || after_second != "approved" {
                    bail!("vector {name} multi-admin gate must transition approving → approved");
                }
                saw_two_of_two_approval = true;
            }
            "two_of_two_duplicate_admin_approval_does_not_count_twice" => {
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject (dedup)");
                }
                if expected_reason(v) != Some("duplicate_approver") {
                    bail!("vector {name} reason_code must be duplicate_approver");
                }
                saw_duplicate_approver = true;
            }
            "executor_restart_survival_resumes_from_persisted_stage" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                if !v
                    .get("crash_simulated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    bail!("vector {name} crash_simulated must be true");
                }
                let resumes = v
                    .pointer("/expected/resumes_from_persisted_progress")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !resumes {
                    bail!("vector {name} executor must resume from persisted progress");
                }
                let chunks_before = v
                    .pointer("/executor_progress_before_crash/chunks_done")
                    .and_then(Value::as_u64);
                let chunks_after = v
                    .pointer("/expected/executor_progress_after_restart/chunks_done")
                    .and_then(Value::as_u64);
                if chunks_before != chunks_after {
                    bail!(
                        "vector {name} chunks_done before crash != after restart (would mean re-do)"
                    );
                }
                saw_executor_restart = true;
            }
            "artifact_upload_verify_then_download_round_trip" => {
                if outcome != "accept" {
                    bail!("vector {name} outcome must be accept");
                }
                let events: Vec<&str> = v
                    .get("lifecycle_events")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|e| e.get("event").and_then(Value::as_str))
                            .collect()
                    })
                    .unwrap_or_default();
                let required_seq = [
                    "upload_complete",
                    "integrity_verified",
                    "download_initiated",
                    "download_complete",
                ];
                if events != required_seq {
                    bail!(
                        "vector {name} lifecycle events must be {required_seq:?}, got {events:?}"
                    );
                }
                let final_state = v
                    .pointer("/expected/final_artifact_state")
                    .and_then(Value::as_str);
                if final_state != Some("downloaded") {
                    bail!("vector {name} final_artifact_state must be downloaded");
                }
                let integrity = v
                    .pointer("/expected/integrity_check_passed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !integrity {
                    bail!("vector {name} integrity_check_passed must be true");
                }
                saw_artifact_round_trip = true;
            }
            "artifact_integrity_mismatch_blocks_download" => {
                if outcome != "reject" {
                    bail!("vector {name} outcome must be reject");
                }
                if expected_reason(v) != Some("artifact_integrity_mismatch") {
                    bail!("vector {name} reason_code must be artifact_integrity_mismatch");
                }
                let expected_hash = v
                    .pointer("/artifact/expected_sha256")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing expected_sha256"))?;
                let actual_hash = v
                    .pointer("/artifact/actual_sha256")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing actual_sha256"))?;
                if expected_hash == actual_hash {
                    bail!(
                        "vector {name} integrity-mismatch negative requires actual != expected hash"
                    );
                }
                if v.pointer("/expected/ticket_state_after")
                    .and_then(Value::as_str)
                    != Some("failed")
                {
                    bail!("vector {name} ticket_state_after must be failed on integrity mismatch");
                }
                saw_integrity_mismatch = true;
            }
            other => bail!("restore_full_workflows unexpected vector {other}"),
        }
        emit_vector(
            "restore_full_workflows.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }
    if !(saw_two_of_two_approval
        && saw_duplicate_approver
        && saw_executor_restart
        && saw_artifact_round_trip
        && saw_integrity_mismatch)
    {
        bail!(
            "restore_full_workflows must cover two_of_two + duplicate_approver + restart_survival + artifact_round_trip + integrity_mismatch"
        );
    }
    Ok(())
}
/// Recovery-ticket state-machine: legal transitions are issued → executing →
/// executed (success path) or issued → cancelled / expired (terminal).
fn validate_ticket_state_transitions(transitions: &[&str]) -> bool {
    if transitions.is_empty() {
        return false;
    }
    if transitions[0] != "issued" {
        return false;
    }
    for window in transitions.windows(2) {
        let legal = matches!(
            (window[0], window[1]),
            ("issued", "executing")
                | ("issued", "cancelled")
                | ("issued", "expired")
                | ("executing", "executed")
                | ("executing", "failed")
                | ("executing", "cancelled")
        );
        if !legal {
            return false;
        }
    }
    true
}
