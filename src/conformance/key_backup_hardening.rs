//! Key-backup KDF floor and unlock-proof conformance vectors.

use anyhow::{Result, anyhow, bail};
use cokret_core::error::{
    REASON_RECOVERY_EVIDENCE_UNBOUND, ERROR_CODE_SCHEMA_VIOLATION, ERROR_CODE_UNAUTHENTICATED,
};
use cokret_core::{BackupClass, KeyBackupPlaintext, KeyBackupUnlockProof};
use serde_json::Value;

use super::schema_validation_fixture::SchemaEnv;

pub const VECTOR_ID_KEY_BACKUP_KDF_FLOOR_REJECTED: &str =
    "ck.vector.key_backup.kdf_floor_rejected.v1";
pub const VECTOR_ID_KEY_BACKUP_UNLOCK_PROOF: &str = "ck.vector.key_backup.unlock_proof.v1";

pub const ALL_KEY_BACKUP_HARDENING_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_KEY_BACKUP_KDF_FLOOR_REJECTED,
    VECTOR_ID_KEY_BACKUP_UNLOCK_PROOF,
];

const KEY_BACKUP_HARDENING_FIXTURE_FILE: &str = "key-backup-hardening-fixture.json";
const KEY_BACKUP_HARDENING_PROFILE: &str = "ck.profile.e2ee_client.v1";
const KEY_BACKUP_ENCRYPTION_SCHEMA: &str = "schemas/key-backup.schema.json#/properties/encryption";
const KEY_BACKUP_UNLOCK_REQUEST_SCHEMA: &str =
    "schemas/keys-operations.schema.json#/$defs/keys_backups_unlock_request_body";
const KEY_BACKUP_PLAINTEXT_SCHEMA: &str = "schemas/key-backup-plaintext.schema.json";
const ERROR_CODE_FORBIDDEN: &str = "forbidden";

fn key_backup_hardening_fixture() -> Result<Value> {
    let fixture = super::load_fixture_value(KEY_BACKUP_HARDENING_FIXTURE_FILE)?;
    super::validate_profile(&fixture, KEY_BACKUP_HARDENING_PROFILE)?;
    validate_key_backup_hardening_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_key_backup_hardening_fixture_metadata(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some("key_backup_hardening") {
        bail!("key backup hardening fixture suite drifted");
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("key backup hardening fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("key backup hardening fixture missing cases[]"))?;

    for vector_id in ALL_KEY_BACKUP_HARDENING_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("key backup hardening fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("key backup hardening fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

fn case<'a>(fixture: &'a Value, vector_id: &str) -> Result<&'a Value> {
    fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
        })
        .ok_or_else(|| anyhow!("key backup hardening fixture missing case {vector_id}"))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("case missing string field {field}"))
}

fn expected_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .pointer(&format!("/expected/{field}"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("case missing expected.{field}"))
}

fn expected_bool(value: &Value, field: &str) -> Result<bool> {
    value
        .pointer(&format!("/expected/{field}"))
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("case missing bool expected.{field}"))
}

fn schema_validator(schema_ref: &str) -> Result<jsonschema::Validator> {
    let env = SchemaEnv::load()?;
    env.compile(schema_ref)
}

fn schema_valid(schema_ref: &str, value: &Value) -> Result<()> {
    let validator = schema_validator(schema_ref)?;
    if !validator.is_valid(value) {
        let errors = validator
            .iter_errors(value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        bail!("value failed schema {schema_ref}: {errors}");
    }
    Ok(())
}

fn schema_rejects(schema_ref: &str, value: &Value) -> Result<bool> {
    Ok(!schema_validator(schema_ref)?.is_valid(value))
}

fn encryption_sample(value: &Value) -> Value {
    let mut sample = value.clone();
    if let Some(object) = sample.as_object_mut() {
        object.remove("label");
    }
    sample
}

struct RecoverySessionState {
    recovery_session_id: String,
    principal_id: String,
    requesting_device_id: String,
    proof_digest: String,
    fresh_device_proof: bool,
}

struct BackupEnvelopeState {
    backup_id: String,
    actor_id: String,
    backup_class: String,
    series_id: String,
    series_seq: u64,
    ciphertext_digest: String,
}

fn recovery_session_state(value: &Value) -> Result<RecoverySessionState> {
    Ok(RecoverySessionState {
        recovery_session_id: required_str(value, "recovery_session_id")?.to_owned(),
        principal_id: required_str(value, "principal_id")?.to_owned(),
        requesting_device_id: required_str(value, "requesting_device_id")?.to_owned(),
        proof_digest: required_str(value, "proof_digest")?.to_owned(),
        fresh_device_proof: value
            .get("fresh_device_proof")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("session missing fresh_device_proof"))?,
    })
}

fn backup_envelope_state(value: &Value) -> Result<BackupEnvelopeState> {
    Ok(BackupEnvelopeState {
        backup_id: required_str(value, "backup_id")?.to_owned(),
        actor_id: required_str(value, "actor_id")?.to_owned(),
        backup_class: required_str(value, "backup_class")?.to_owned(),
        series_id: required_str(value, "series_id")?.to_owned(),
        series_seq: value
            .get("series_seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("envelope missing series_seq"))?,
        ciphertext_digest: required_str(value, "ciphertext_digest")?.to_owned(),
    })
}

fn proof_digest_str(proof: &KeyBackupUnlockProof) -> Result<&str> {
    proof
        .proof_digest
        .as_str()
        .ok_or_else(|| anyhow!("proof_digest must be a string hash"))
}

fn backup_class_str(backup_class: BackupClass) -> &'static str {
    match backup_class {
        BackupClass::DidRecovery => "did_recovery",
        BackupClass::SecretStorage => "secret_storage",
        BackupClass::MlsHistory => "mls_history",
    }
}

fn authorize_unlock(
    path_backup_id: &str,
    caller: &str,
    proof: Option<&KeyBackupUnlockProof>,
    session: &RecoverySessionState,
    envelope: &BackupEnvelopeState,
) -> std::result::Result<(), &'static str> {
    if !session.fresh_device_proof {
        return Err(ERROR_CODE_UNAUTHENTICATED);
    }
    if caller != envelope.actor_id {
        return Err(ERROR_CODE_FORBIDDEN);
    }
    let Some(proof) = proof else {
        return Err(ERROR_CODE_UNAUTHENTICATED);
    };
    if path_backup_id != proof.backup_id.as_str()
        || path_backup_id != envelope.backup_id
        || proof.recovery_session_id.as_str() != session.recovery_session_id
        || proof.principal_id.as_str() != session.principal_id
        || proof.requesting_device_id != session.requesting_device_id
        || backup_class_str(proof.backup_class) != envelope.backup_class
        || proof.series_id.as_str() != envelope.series_id
        || proof.ciphertext_digest.as_str() != envelope.ciphertext_digest
        || proof_digest_str(proof).map_err(|_| REASON_RECOVERY_EVIDENCE_UNBOUND)?
            != session.proof_digest
    {
        return Err(REASON_RECOVERY_EVIDENCE_UNBOUND);
    }
    Ok(())
}

fn parse_unlock_request(value: Value) -> Result<KeyBackupUnlockProof> {
    schema_valid(KEY_BACKUP_UNLOCK_REQUEST_SCHEMA, &value)?;
    serde_json::from_value(
        value
            .get("proof")
            .cloned()
            .ok_or_else(|| anyhow!("unlock request missing proof"))?,
    )
    .map_err(Into::into)
}

pub fn run_key_backup_kdf_floor_rejected_vector() -> Result<()> {
    let fixture = key_backup_hardening_fixture()?;
    let vector = case(&fixture, VECTOR_ID_KEY_BACKUP_KDF_FLOOR_REJECTED)?;
    let positives = vector
        .get("positive_encryption")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("kdf floor vector missing positive_encryption[]"))?;
    for positive in positives {
        schema_valid(KEY_BACKUP_ENCRYPTION_SCHEMA, &encryption_sample(positive))?;
    }

    let negatives = vector
        .get("negative_encryption")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("kdf floor vector missing negative_encryption[]"))?;
    for negative in negatives {
        if !schema_rejects(KEY_BACKUP_ENCRYPTION_SCHEMA, &encryption_sample(negative))? {
            bail!("negative KDF floor case passed schema validation");
        }
    }

    let mut unknown_kdf = encryption_sample(
        positives
            .first()
            .ok_or_else(|| anyhow!("kdf floor vector missing positive control"))?,
    );
    unknown_kdf["kdf"]["name"] = Value::String("scrypt".to_owned());
    if !schema_rejects(KEY_BACKUP_ENCRYPTION_SCHEMA, &unknown_kdf)? {
        bail!("unknown KDF name did not fail closed");
    }
    if expected_str(vector, "negative_reason")? != ERROR_CODE_SCHEMA_VIOLATION
        || expected_str(vector, "unknown_kdf_reason")? != ERROR_CODE_SCHEMA_VIOLATION
    {
        bail!("KDF floor expected schema_violation reason drifted");
    }
    Ok(())
}

pub fn run_key_backup_unlock_proof_vector() -> Result<()> {
    let fixture = key_backup_hardening_fixture()?;
    let vector = case(&fixture, VECTOR_ID_KEY_BACKUP_UNLOCK_PROOF)?;
    let session = recovery_session_state(
        vector
            .get("session")
            .ok_or_else(|| anyhow!("unlock vector missing session"))?,
    )?;
    let envelope = backup_envelope_state(
        vector
            .get("envelope")
            .ok_or_else(|| anyhow!("unlock vector missing envelope"))?,
    )?;
    let proof_value = vector
        .get("proof")
        .cloned()
        .ok_or_else(|| anyhow!("unlock vector missing proof"))?;
    let request_value = serde_json::json!({ "proof": proof_value });
    let proof = parse_unlock_request(request_value)?;
    authorize_unlock(
        &envelope.backup_id,
        &envelope.actor_id,
        Some(&proof),
        &session,
        &envelope,
    )
    .map_err(|reason| anyhow!("valid unlock proof rejected: {reason}"))?;
    if expected_str(vector, "valid_unlock")? != "accepted" {
        bail!("valid unlock expectation drifted");
    }

    let mut mismatched_value = vector
        .get("proof")
        .cloned()
        .ok_or_else(|| anyhow!("unlock vector missing proof"))?;
    mismatched_value["ciphertext_digest"] = Value::String(
        "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
    );
    let mismatched_proof = parse_unlock_request(serde_json::json!({ "proof": mismatched_value }))?;
    if authorize_unlock(
        &envelope.backup_id,
        &envelope.actor_id,
        Some(&mismatched_proof),
        &session,
        &envelope,
    )
    .err()
        != Some(expected_str(vector, "binding_mismatch_reason")?)
    {
        bail!("ciphertext-bound unlock proof mismatch was not rejected");
    }

    let mut bearer_session = RecoverySessionState {
        recovery_session_id: session.recovery_session_id.clone(),
        principal_id: session.principal_id.clone(),
        requesting_device_id: session.requesting_device_id.clone(),
        proof_digest: session.proof_digest.clone(),
        fresh_device_proof: false,
    };
    if authorize_unlock(
        &envelope.backup_id,
        &envelope.actor_id,
        Some(&proof),
        &bearer_session,
        &envelope,
    )
    .err()
        != Some(expected_str(vector, "bearer_only_reason")?)
    {
        bail!("bearer-only key backup unlock was not rejected");
    }
    bearer_session.fresh_device_proof = true;
    if authorize_unlock(
        &envelope.backup_id,
        "did:web:bob.example",
        Some(&proof),
        &bearer_session,
        &envelope,
    )
    .err()
        != Some(expected_str(vector, "cross_actor_reason")?)
    {
        bail!("cross-actor key backup unlock did not fail closed");
    }

    let plaintext_value = vector
        .get("plaintext")
        .cloned()
        .ok_or_else(|| anyhow!("unlock vector missing plaintext"))?;
    schema_valid(KEY_BACKUP_PLAINTEXT_SCHEMA, &plaintext_value)?;
    let plaintext: KeyBackupPlaintext = serde_json::from_value(plaintext_value)?;
    if expected_bool(vector, "plaintext_metadata_matches_envelope")?
        && (plaintext.backup_id.as_str() != envelope.backup_id
            || backup_class_str(plaintext.backup_class) != envelope.backup_class
            || plaintext.series_id.as_str() != envelope.series_id
            || plaintext.series_seq != envelope.series_seq)
    {
        bail!("key backup plaintext metadata does not match the envelope");
    }
    if plaintext
        .items
        .iter()
        .any(|item| item.secret_b64u.trim().is_empty())
    {
        bail!("plaintext keybag item carried an empty secret");
    }
    Ok(())
}

pub fn run_key_backup_hardening_fixture_suite() -> Result<()> {
    validate_key_backup_hardening_fixture_metadata(&key_backup_hardening_fixture()?)?;
    if ALL_KEY_BACKUP_HARDENING_VECTOR_IDS.len() != 2 {
        bail!(
            "expected 2 key backup hardening vector ids, got {}",
            ALL_KEY_BACKUP_HARDENING_VECTOR_IDS.len()
        );
    }

    run_key_backup_kdf_floor_rejected_vector()?;
    run_key_backup_unlock_proof_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_backup_hardening_vectors_run_clean() {
        run_key_backup_hardening_fixture_suite().unwrap();
    }
}
