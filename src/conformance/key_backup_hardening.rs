//! Key-backup KDF floor and unlock-proof conformance vectors.

use anyhow::{Context, Result, anyhow, bail};
use arkret_models_crypto::{BackupKind, KeyBackupKeybag, KeyBackupPlaintext, KeyBackupUnlockProof};
use arkret_wire::{ActorId, ProfileId};
use serde::Deserialize;
use serde_json::Value;

use super::schema_validation_fixture::{schema_rejects, schema_valid};
use super::{expected_bool, expected_str, required_str};

pub const VECTOR_ID_KEY_BACKUP_KDF_FLOOR_REJECTED: &str =
    "ak.vector.key_backup.kdf_floor_rejected.v1";
pub use arkret_models_crypto::key_backup::VECTOR_ID_KEY_BACKUP_UNLOCK_PROOF;
pub const VECTOR_ID_KEY_BACKUP_DELETE_AUTHORITY: &str = "ak.vector.key_backup.delete_authority.v1";

pub const ALL_KEY_BACKUP_HARDENING_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_KEY_BACKUP_KDF_FLOOR_REJECTED,
    VECTOR_ID_KEY_BACKUP_UNLOCK_PROOF,
    VECTOR_ID_KEY_BACKUP_DELETE_AUTHORITY,
];

const KEY_BACKUP_HARDENING_FIXTURE_FILE: &str = "key-backup-hardening-fixture.json";
const KEY_BACKUP_ENCRYPTION_SCHEMA: &str = "schemas/key-backup.schema.json#/properties/encryption";
const KEY_BACKUP_UNLOCK_REQUEST_SCHEMA: &str =
    "schemas/keys-operations.schema.json#/$defs/keys_backups_unlock_request_body";
const KEY_BACKUP_PLAINTEXT_SCHEMA_FILE: &str = "schemas/key-backup-plaintext.schema.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBackupHardeningFixture {
    profile: String,
    version: String,
    suite: String,
    runner: Value,
    covers_vectors: Vec<String>,
    cases: Vec<Value>,
}

fn key_backup_hardening_fixture() -> Result<KeyBackupHardeningFixture> {
    let fixture: KeyBackupHardeningFixture = serde_json::from_value(super::load_fixture_value(
        KEY_BACKUP_HARDENING_FIXTURE_FILE,
    )?)?;
    validate_key_backup_hardening_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_key_backup_hardening_fixture_metadata(
    fixture: &KeyBackupHardeningFixture,
) -> Result<()> {
    if fixture.profile != ProfileId::E2EE_CLIENT_V1
        || fixture.suite != "key_backup_hardening"
        || fixture.version.trim().is_empty()
        || fixture.runner.is_null()
    {
        bail!("key backup hardening fixture suite drifted");
    }

    let covers = &fixture.covers_vectors;
    let cases = &fixture.cases;

    for vector_id in ALL_KEY_BACKUP_HARDENING_VECTOR_IDS {
        if !covers.iter().any(|entry| entry == vector_id) {
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

fn case<'a>(fixture: &'a KeyBackupHardeningFixture, vector_id: &str) -> Result<&'a Value> {
    fixture
        .cases
        .iter()
        .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
        .ok_or_else(|| anyhow!("key backup hardening fixture missing case {vector_id}"))
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
    account_id: arkret_wire::AccountId,
    requesting_device_id: String,
    proof_digest: String,
    fresh_device_proof: bool,
}

struct BackupEnvelopeState {
    backup_id: String,
    actor_id: ActorId,
    backup_kind: String,
    series_id: String,
    series_seq: u64,
    ciphertext_digest: String,
}

fn recovery_session_state(value: &Value) -> Result<RecoverySessionState> {
    Ok(RecoverySessionState {
        recovery_session_id: required_str(value, "recovery_session_id")?.to_owned(),
        account_id: serde_json::from_value(
            value
                .get("account_id")
                .cloned()
                .context("missing account_id")?,
        )?,
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
        actor_id: serde_json::from_value(
            value
                .get("actor_id")
                .cloned()
                .ok_or_else(|| anyhow!("envelope missing actor_id"))?,
        )?,
        backup_kind: required_str(value, "backup_kind")?.to_owned(),
        series_id: required_str(value, "series_id")?.to_owned(),
        series_seq: value
            .get("series_seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("envelope missing series_seq"))?,
        ciphertext_digest: required_str(value, "ciphertext_digest")?.to_owned(),
    })
}

fn proof_digest_str(proof: &KeyBackupUnlockProof) -> Result<&str> {
    Ok(proof.proof_digest.as_str())
}

fn backup_class_str(backup_kind: BackupKind) -> &'static str {
    match backup_kind {
        BackupKind::SecretStorage => "secret_storage",
        BackupKind::MlsHistory => "mls_history",
    }
}

fn authorize_unlock(
    path_backup_id: &str,
    caller: &ActorId,
    proof: Option<&KeyBackupUnlockProof>,
    session: &RecoverySessionState,
    envelope: &BackupEnvelopeState,
) -> std::result::Result<(), &'static str> {
    if !session.fresh_device_proof {
        return Err(arkret_wire::ErrorCode::UNAUTHENTICATED);
    }
    if caller != &envelope.actor_id {
        return Err(arkret_wire::ErrorCode::CAPABILITY_DENIED);
    }
    let Some(proof) = proof else {
        return Err(arkret_wire::ErrorCode::UNAUTHENTICATED);
    };
    if path_backup_id != proof.backup_id.as_str()
        || path_backup_id != envelope.backup_id
        || proof.recovery_session_id.as_str() != session.recovery_session_id
        || proof.account_id != session.account_id
        || proof.requesting_device_id.as_str() != session.requesting_device_id
        || backup_class_str(proof.backup_kind) != envelope.backup_kind
        || proof.series_id.as_str() != envelope.series_id
        || proof.ciphertext_digest.as_str() != envelope.ciphertext_digest
        || proof_digest_str(proof)
            .map_err(|_| arkret_wire::ReasonCode::RECOVERY_EVIDENCE_UNBOUND)?
            != session.proof_digest
    {
        return Err(arkret_wire::ReasonCode::RECOVERY_EVIDENCE_UNBOUND);
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
    if expected_str(vector, "negative_reason")? != arkret_wire::ErrorCode::SCHEMA_VIOLATION
        || expected_str(vector, "unknown_kdf_reason")? != arkret_wire::ErrorCode::SCHEMA_VIOLATION
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
        account_id: session.account_id.clone(),
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
        &ActorId::service(arkret_identifiers::DidCoreId::new(
            "ak:did_core:web:bob.example",
        )?),
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
    schema_valid(KEY_BACKUP_PLAINTEXT_SCHEMA_FILE, &plaintext_value)?;
    let plaintext: KeyBackupPlaintext = serde_json::from_value(plaintext_value)?;
    if expected_bool(vector, "plaintext_metadata_matches_envelope")?
        && (plaintext.backup_id.as_str() != envelope.backup_id
            || backup_class_str(plaintext.keybag.backup_kind()) != envelope.backup_kind
            || plaintext.series_id.as_str() != envelope.series_id
            || plaintext.series_seq != envelope.series_seq)
    {
        bail!("key backup plaintext metadata does not match the envelope");
    }
    match &plaintext.keybag {
        KeyBackupKeybag::SecretStorage { items } => {
            if items.iter().any(|item| item.secret_b64u.trim().is_empty()) {
                bail!("plaintext keybag item carried an empty secret");
            }
        }
        KeyBackupKeybag::MlsHistory { items, .. } => {
            if items.iter().any(|item| item.secrets_b64u.trim().is_empty()) {
                bail!("plaintext keybag item carried an empty secret");
            }
        }
    }
    Ok(())
}

/// Exact runner for `ak.vector.key_backup.delete_authority.v1`.
pub fn run_key_backup_delete_authority_vector() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    use arkret_models_crypto::key_backup::KeysBackupsDeleteChallenge;
    use chrono::Duration;
    use serde_json::json;

    let challenge: KeysBackupsDeleteChallenge = serde_json::from_value(json!({
        "challenge_id": "AAAAAAAAAAAAAAAAAAAAAA",
        "challenge": "BBBBBBBBBBBBBBBBBBBBBB",
        "nonce": "CCCCCCCCCCCCCCCCCCCCCC",
        "operation": "ak.self.keys.backups.resource.delete.v1",
        "account_id": {
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:webvh:z6mkauthorityfixture"
        },
        "backup_id": "ak:backup:0196419b-0000-7000-8000-000000000001",
        "audience": "https://authority.example",
        "service_id": "ak:did_core:webvh:z6mkauthorityfixture",
        "request_id": "DDDDDDDDDDDDDDDDDDDDDD",
        "issued_at": "2026-07-31T00:00:00.000Z",
        "expires_at": "2026-07-31T00:05:00.000Z"
    }))?;
    let reason = Some("operator-request");
    let baseline = challenge.delete_intent_digest(reason)?.to_string();

    // The transcript binds the delete-intent family's own registered context.
    // `key-management.md` §7.8.1 gives the deletion authority its own object
    // family, so a signature minted under any other context signs different
    // bytes and can never be replayed onto a delete.
    let transcript = challenge.delete_intent_transcript(reason);
    let context = transcript
        .get("context")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup delete-intent transcript carries no context"))?;
    if context != arkret_wire::ProofContextId::KEY_BACKUP_DELETE_PROOF_V1 {
        bail!(
            "backup delete-intent transcript signs under `{context}`, the registered family \
             context is `{}`",
            arkret_wire::ProofContextId::KEY_BACKUP_DELETE_PROOF_V1
        );
    }
    if arkret_wire::ProofContextId::from_wire(context).is_none() {
        bail!("backup delete-intent context `{context}` is not a registered proof context");
    }
    let mut foreign_context = transcript.clone();
    foreign_context["context"] = json!(arkret_wire::ProofContextId::AUTHORIZATION_LEASE_PROOF_V1);
    let foreign_context_digest = arkret_canonical::canonical_sha256(&foreign_context)?;
    if foreign_context_digest == baseline {
        bail!(
            "swapping the delete-intent context did not change the signed transcript; the context \
             is not part of the signed bytes"
        );
    }

    let mut mutations = Vec::new();
    mutations.push(foreign_context_digest);
    let mut backup = serde_json::to_value(&challenge)?;
    backup["backup_id"] = json!("ak:backup:0196419b-0000-7000-8000-000000000002");
    mutations.push(
        serde_json::from_value::<KeysBackupsDeleteChallenge>(backup)?
            .delete_intent_digest(reason)?
            .to_string(),
    );
    mutations.push(
        challenge
            .delete_intent_digest(Some("tampered-reason"))?
            .to_string(),
    );
    let mut audience = serde_json::to_value(&challenge)?;
    audience["audience"] = json!("https://other.example");
    mutations.push(
        serde_json::from_value::<KeysBackupsDeleteChallenge>(audience)?
            .delete_intent_digest(reason)?
            .to_string(),
    );
    let mut nonce = serde_json::to_value(&challenge)?;
    nonce["nonce"] = json!("EEEEEEEEEEEEEEEEEEEEEE");
    mutations.push(
        serde_json::from_value::<KeysBackupsDeleteChallenge>(nonce)?
            .delete_intent_digest(reason)?
            .to_string(),
    );
    if mutations.iter().any(|digest| digest == &baseline) {
        bail!("backup_id/reason/audience/nonce mutation did not change the signed transcript");
    }

    #[derive(Clone, Copy)]
    enum Authority {
        Principal,
        DeviceQuorum,
        RecoveryService,
        OrdinaryDevice,
    }
    let authorized = |authority: Authority,
                      active_tail: bool,
                      deleting_single_non_tail: bool,
                      quorum_devices: &[&str],
                      policy_k: usize,
                      recovery_session_live: bool| {
        if deleting_single_non_tail {
            return false;
        }
        match authority {
            Authority::Principal => active_tail,
            Authority::DeviceQuorum => {
                active_tail
                    && quorum_devices
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .len()
                        >= policy_k
            }
            Authority::RecoveryService => active_tail && recovery_session_live,
            Authority::OrdinaryDevice => !active_tail,
        }
    };
    if !authorized(Authority::Principal, true, false, &[], 2, false)
        || !authorized(
            Authority::DeviceQuorum,
            true,
            false,
            &["device-a", "device-b"],
            2,
            false,
        )
        || !authorized(Authority::RecoveryService, true, false, &[], 2, true)
        || authorized(Authority::OrdinaryDevice, true, false, &[], 2, false)
        || authorized(Authority::Principal, true, true, &[], 2, false)
        || authorized(
            Authority::DeviceQuorum,
            true,
            false,
            &["device-a", "device-a"],
            2,
            false,
        )
        || authorized(Authority::RecoveryService, true, false, &[], 2, false)
    {
        bail!("backup delete high-risk authority matrix drifted");
    }

    let request_identity = (
        serde_json::to_string(&challenge.account_id)?,
        challenge.backup_id.to_string(),
        challenge.request_id.to_string(),
    );
    let request_digest = arkret_canonical::canonical_sha256(&json!({
        "request_id": challenge.request_id,
        "challenge_id": challenge.challenge_id,
        "proof": {"kind": "principal_signing", "digest": baseline},
        "reason": reason
    }))?;
    let terminal = br#"{"deleted":true}"#.to_vec();
    let mut ledger = BTreeMap::new();
    ledger.insert(
        request_identity.clone(),
        (request_digest.clone(), terminal.clone()),
    );
    let challenge_consumed = true;
    let replay = ledger
        .get(&request_identity)
        .expect("terminal delete ledger row");
    if !challenge_consumed || replay.0 != request_digest || replay.1 != terminal {
        bail!("exact backup delete retry did not replay its terminal outcome");
    }
    let conflicting_digest = arkret_canonical::canonical_sha256(&json!({
        "request_id": challenge.request_id,
        "challenge_id": challenge.challenge_id,
        "proof": {"kind": "principal_signing", "digest": baseline},
        "reason": "changed"
    }))?;
    if conflicting_digest == replay.0 {
        bail!("same backup delete request_id with another request did not conflict");
    }
    let expired_at = challenge.expires_at + Duration::seconds(1);
    if expired_at <= challenge.expires_at || !challenge_consumed {
        bail!("expired or replayed challenge negative cases were not constructed");
    }
    Ok(())
}

pub fn run_key_backup_hardening_fixture_suite() -> Result<()> {
    validate_key_backup_hardening_fixture_metadata(&key_backup_hardening_fixture()?)?;
    if ALL_KEY_BACKUP_HARDENING_VECTOR_IDS.len() != 3 {
        bail!(
            "expected 3 key backup hardening vector ids, got {}",
            ALL_KEY_BACKUP_HARDENING_VECTOR_IDS.len()
        );
    }

    run_key_backup_kdf_floor_rejected_vector()?;
    run_key_backup_unlock_proof_vector()?;
    run_key_backup_delete_authority_vector()?;
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
