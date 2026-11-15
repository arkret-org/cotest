//! Opaque issuer-record reference vectors. These deterministic fixture checks
//! do not replace real Account Authority issuance or native holder admission.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use arkret_models_identity::{CanonicalSessionPublicJwk, SessionGrantMetadata};
use arkret_wire::{SessionGrantRef, SessionGrantSecret};
use serde_json::Value;

use super::load_fixture_value;

const SESSION_FIXTURE: &str = "session-grant-issuance-fixture.json";
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string {key}"))
}

/// Check canonical public metadata, independent opaque entropy, and the exact
/// issuer-qualified record identity without deriving identity from the secret.
pub fn run_session_grant_issuance_kat_suite() -> Result<()> {
    let fixture = load_fixture_value(SESSION_FIXTURE)?;
    let vectors = fixture["accepted_vectors"]
        .as_array()
        .context("accepted_vectors")?;
    ensure!(
        vectors.len() >= 6,
        "opaque issuer-record KAT coverage regressed"
    );
    let mut refs = BTreeMap::new();
    for vector in vectors {
        let name = text(vector, "name")?;
        let metadata: SessionGrantMetadata = serde_json::from_value(vector["metadata"].clone())?;
        metadata.validate()?;
        let bytes = arkret_canonical::canonical_json_bytes(&metadata)?;
        ensure!(
            bytes == text(vector, "canonical_metadata_utf8")?.as_bytes(),
            "canonical metadata drifted: {name}"
        );
        let entropy: [u8; 32] = hex::decode(text(vector, "random_bytes_hex")?)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("fixture entropy must be 32 bytes"))?;
        let secret = SessionGrantSecret::from_bytes(entropy);
        ensure!(secret.as_str() == text(vector, "session_grant")?);
        ensure!(SessionGrantSecret::new(secret.as_str())? == secret);
        ensure!(
            arkret_canonical::sha256_digest(secret.as_str().as_bytes())
                == text(vector, "credential_digest")?
        );
        ensure!(
            arkret_canonical::base64url_encode(arkret_canonical::sha256_bytes(
                secret.as_str().as_bytes()
            )) == text(vector, "dpop_ath")?
        );
        let reference: SessionGrantRef =
            serde_json::from_value(vector["session_grant_ref"].clone())?;
        ensure!(metadata.grant_ref() == reference);
        refs.insert(name, reference);
    }
    ensure!(
        refs["issuer_a_standard"].id == refs["issuer_b_same_record_id"].id
            && refs["issuer_a_standard"] != refs["issuer_b_same_record_id"],
        "equal local ids must remain isolated by issuer"
    );
    for input in fixture["equivalent_non_canonical_jwk_inputs"]
        .as_array()
        .context("JWK inputs")?
    {
        ensure!(
            CanonicalSessionPublicJwk::new(input.as_str().context("JWK string")?)?.as_str()
                == text(&fixture, "canonical_public_jwk")?
        );
    }
    for negative in fixture["credential_binding_negative_cases"]
        .as_array()
        .context("credential binding negatives")?
    {
        let base = vectors
            .iter()
            .find(|vector| vector["name"] == negative["base_vector"])
            .context("negative base vector")?;
        let mut metadata = base["metadata"].clone();
        for field in negative
            .get("omit")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            metadata
                .as_object_mut()
                .context("metadata object")?
                .remove(field.as_str().context("omitted field")?);
        }
        for (field, value) in negative
            .get("set")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            metadata[field] = value.clone();
        }
        ensure!(
            serde_json::from_value::<SessionGrantMetadata>(metadata).is_err(),
            "binding negative accepted: {}",
            text(negative, "name")?
        );
    }
    Ok(())
}

#[derive(Clone)]
struct ReferenceOperation {
    intent: Vec<u8>,
    outcome: Option<Vec<u8>>,
    result: String,
}

#[derive(Clone)]
struct ReferenceRecord {
    vector: Value,
    state: &'static str,
}

fn record_key(vector: &Value) -> Result<String> {
    Ok(String::from_utf8(arkret_canonical::canonical_json_bytes(
        &vector["session_grant_ref"],
    )?)?)
}

/// Execute the published deterministic replay model. The maps below are only
/// test state; crash persistence and HTTP concurrency remain live obligations.
pub fn run_session_grant_issuer_ledger_reference_model_suite() -> Result<()> {
    let fixture = load_fixture_value(SESSION_FIXTURE)?;
    let vectors = fixture["accepted_vectors"]
        .as_array()
        .context("accepted vectors")?;
    let cases = fixture["ledger_cases"].as_array().context("ledger cases")?;
    ensure!(cases.len() >= 12, "issuer-record replay coverage regressed");
    for case in cases {
        let mut records: BTreeMap<String, ReferenceRecord> = BTreeMap::new();
        let mut operations: BTreeMap<(String, String, String), ReferenceOperation> =
            BTreeMap::new();
        let mut outcomes: Vec<Option<Vec<u8>>> = Vec::new();
        let mut draws = 0;
        for step in case["steps"].as_array().context("ledger steps")? {
            let operation = text(step, "op")?;
            if operation == "restart" {
                records = records.clone();
                operations = operations.clone();
                outcomes.push(None);
                continue;
            }
            if operation == "forget_outcome" {
                let key = (
                    text(step, "issuer_id")?.to_owned(),
                    "issue".to_owned(),
                    text(step, "request_id")?.to_owned(),
                );
                operations.get_mut(&key).context("known operation")?.outcome = None;
                outcomes.push(None);
                continue;
            }
            let vector = vectors
                .iter()
                .find(|vector| vector["name"] == step["vector"])
                .context("step vector")?;
            let metadata: SessionGrantMetadata =
                serde_json::from_value(vector["metadata"].clone())?;
            let record = record_key(vector)?;
            let mut outcome = None;
            let status = match operation {
                "issue" | "refresh" => {
                    let intent = arkret_canonical::canonical_json_bytes(&step["intent"])?;
                    let now = chrono::DateTime::parse_from_rfc3339(text(step, "now")?)?
                        .with_timezone(&chrono::Utc);
                    let predecessor = if operation == "refresh" {
                        Some(
                            vectors
                                .iter()
                                .find(|vector| vector["name"] == step["predecessor"])
                                .context("predecessor vector")?,
                        )
                    } else {
                        None
                    };
                    let operation_identity = match predecessor {
                        Some(prior) => record_key(prior)?,
                        None => text(step, "request_id")?.to_owned(),
                    };
                    let key = (
                        metadata.issuer_id.to_string(),
                        operation.to_owned(),
                        operation_identity,
                    );
                    if step["holder_current"] != true {
                        "unauthenticated"
                    } else if let Some(prior) = operations.get(&key) {
                        let result = records.get(&prior.result).context("retained result")?;
                        let result_metadata: SessionGrantMetadata =
                            serde_json::from_value(result.vector["metadata"].clone())?;
                        if prior.intent != intent {
                            if operation == "refresh" {
                                "predecessor_terminal"
                            } else {
                                "duplicate_conflict"
                            }
                        } else if now >= result_metadata.expires_at {
                            "session_grant_replay_expired"
                        } else if result.state != "active" {
                            "session_grant_replay_terminal"
                        } else if let Some(original) = &prior.outcome {
                            outcome = Some(original.clone());
                            "success"
                        } else {
                            "session_grant_replay_indeterminate"
                        }
                    } else if predecessor.is_some_and(|prior| {
                        prior["metadata"]["credential_class"] == "recovery_session"
                    }) {
                        "recovery_refresh_forbidden"
                    } else if predecessor
                        .map(record_key)
                        .transpose()?
                        .as_ref()
                        .is_some_and(|prior| {
                            records
                                .get(prior)
                                .is_none_or(|prior| prior.state != "active")
                        })
                    {
                        "predecessor_terminal"
                    } else {
                        if let Some(prior) = predecessor {
                            records
                                .get_mut(&record_key(prior)?)
                                .context("active predecessor")?
                                .state = "superseded";
                        }
                        let canonical = arkret_canonical::canonical_json_bytes(vector)?;
                        records.insert(
                            record.clone(),
                            ReferenceRecord {
                                vector: vector.clone(),
                                state: "active",
                            },
                        );
                        operations.insert(
                            key,
                            ReferenceOperation {
                                intent,
                                outcome: Some(canonical.clone()),
                                result: record,
                            },
                        );
                        outcome = Some(canonical);
                        draws += 1;
                        "success"
                    }
                }
                "revoke" => {
                    records.get_mut(&record).context("issued record")?.state = "revoked";
                    "success"
                }
                "introspect" => {
                    let issuer = step
                        .get("issuer_id")
                        .and_then(Value::as_str)
                        .unwrap_or(metadata.issuer_id.as_str());
                    let found = records.values().find(|record| {
                        record.vector["metadata"]["issuer_id"] == issuer
                            && record.vector["session_grant"] == vector["session_grant"]
                    });
                    if let Some(record) = found {
                        if step.get("audience_id").is_some_and(|audience| {
                            audience != &record.vector["metadata"]["audience_id"]
                        }) {
                            "audience_mismatch"
                        } else {
                            record.state
                        }
                    } else {
                        "not_found"
                    }
                }
                other => bail!("unhandled issuer-record operation {other}"),
            };
            ensure!(
                status == text(step, "expect")?,
                "{}: {operation} returned {status}",
                text(case, "name")?
            );
            if let Some(expected) = step.get("expect_records").and_then(Value::as_u64) {
                ensure!(records.len() as u64 == expected);
            }
            if let Some(expected) = step.get("expect_draws").and_then(Value::as_u64) {
                ensure!(draws == expected);
            }
            if let Some(index) = step.get("same_outcome_as").and_then(Value::as_u64) {
                ensure!(
                    outcome.is_some() && outcome == outcomes[index as usize],
                    "exact replay changed its original"
                );
            }
            outcomes.push(outcome);
        }
    }
    Ok(())
}

pub fn run_session_grant_issuer_ledger_suite() -> Result<()> {
    run_session_grant_issuance_kat_suite().context("opaque SessionGrant metadata KAT")?;
    run_session_grant_issuer_ledger_reference_model_suite().context("issuer-record reference model")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issuer_ledger_vectors_run_clean() {
        run_session_grant_issuer_ledger_suite().unwrap();
    }
}
