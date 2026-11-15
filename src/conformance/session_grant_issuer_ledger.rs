//! Cross-service conformance for issuer-ledger SessionGrants. SessionGrants deliberately never
//! enter the Event/lattice reducer: the issuer record and its canonical outcome are the
//! replay authority.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use arkret_models_identity::{CanonicalSessionPublicJwk, SessionGrantMetadata};
use serde_json::Value;

use super::load_fixture_value;

const SESSION_FIXTURE: &str = "session-grant-issuance-fixture.json";
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string {key}"))
}

/// Verify official opaque entropy, portable references and immutable metadata.
pub fn run_session_grant_issuance_kat_suite() -> Result<()> {
    let fixture = load_fixture_value(SESSION_FIXTURE)?;
    let vectors = fixture["accepted_vectors"]
        .as_array()
        .context("accepted vectors")?;
    ensure!(vectors.len() >= 6, "opaque issuer KAT coverage regressed");
    let mut references = BTreeMap::new();
    for vector in vectors {
        let name = text(vector, "name")?;
        let metadata: SessionGrantMetadata = serde_json::from_value(vector["metadata"].clone())?;
        metadata.validate()?;
        ensure!(
            arkret_canonical::canonical_json_bytes(&metadata)?
                == text(vector, "canonical_metadata_utf8")?.as_bytes()
        );
        let entropy = hex::decode(text(vector, "random_bytes_hex")?)?;
        ensure!(entropy.len() == 32);
        let encoded = arkret_canonical::base64url_encode(&entropy);
        ensure!(encoded == text(vector, "session_grant")?);
        let secret = arkret_wire::SessionGrantSecret::new(encoded)?;
        let digest = arkret_canonical::sha256_bytes(secret.as_str().as_bytes());
        ensure!(format!("sha256:{}", hex::encode(digest)) == text(vector, "credential_digest")?);
        ensure!(arkret_canonical::base64url_encode(digest) == text(vector, "dpop_ath")?);
        ensure!(serde_json::to_value(metadata.grant_ref())? == vector["session_grant_ref"]);
        references.insert(name.to_owned(), metadata.grant_ref());
        metadata.validate_request_binding(
            &metadata.grant_ref(),
            &metadata.account_id,
            &metadata.audience_id,
            metadata.not_before,
        )?;
        ensure!(
            metadata
                .validate_request_binding(
                    &metadata.grant_ref(),
                    &metadata.account_id,
                    &metadata.audience_id,
                    metadata.expires_at
                )
                .is_err()
        );
    }
    let first = &references["issuer_a_standard"];
    let second = &references["issuer_b_same_record_id"];
    ensure!(
        first.id == second.id && first != second,
        "issuer scoping must not collapse equal local UUIDs"
    );
    let canonical_jwk = text(&fixture, "canonical_public_jwk")?;
    for value in fixture["equivalent_non_canonical_jwk_inputs"]
        .as_array()
        .context("JWK inputs")?
    {
        ensure!(
            CanonicalSessionPublicJwk::new(value.as_str().context("JWK string")?)?.as_str()
                == canonical_jwk
        );
    }
    for negative in fixture["credential_binding_negative_cases"]
        .as_array()
        .context("binding negatives")?
    {
        let base = vectors
            .iter()
            .find(|v| v["name"] == negative["base_vector"])
            .context("negative base vector")?;
        let mut metadata = base["metadata"].clone();
        let object = metadata.as_object_mut().context("metadata object")?;
        if let Some(fields) = negative["omit"].as_array() {
            for field in fields {
                object.remove(field.as_str().context("omitted member")?);
            }
        }
        if let Some(fields) = negative["set"].as_object() {
            for (key, value) in fields {
                object.insert(key.clone(), value.clone());
            }
        }
        ensure!(
            serde_json::from_value::<SessionGrantMetadata>(metadata).is_err(),
            "binding negative {} accepted",
            text(negative, "name")?
        );
    }
    for invalid in [
        String::new(),
        "A".repeat(42),
        "B".repeat(43),
        format!("{}=", "A".repeat(43)),
        "header.payload.signature".into(),
    ] {
        ensure!(arkret_wire::SessionGrantSecret::new(invalid).is_err());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantState {
    Active,
    Revoked,
    Superseded,
}

#[derive(Clone, Debug)]
struct GrantRecord {
    intent: Vec<u8>,
    outcome: Vec<u8>,
    expires_at: i64,
    state: GrantState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LedgerResult {
    Outcome(Vec<u8>),
    Conflict,
    Expired,
    Terminal(GrantState),
}

#[derive(Clone, Default)]
struct MiniIssuerLedger {
    operations: BTreeMap<String, GrantRecord>,
}

impl MiniIssuerLedger {
    fn issue(&mut self, key: &str, intent: &[u8], outcome: &[u8], expires_at: i64) -> LedgerResult {
        if let Some(record) = self.operations.get(key) {
            return if record.intent != intent {
                LedgerResult::Conflict
            } else {
                LedgerResult::Outcome(record.outcome.clone())
            };
        }
        self.operations.insert(
            key.to_owned(),
            GrantRecord {
                intent: intent.to_vec(),
                outcome: outcome.to_vec(),
                expires_at,
                state: GrantState::Active,
            },
        );
        LedgerResult::Outcome(outcome.to_vec())
    }

    fn replay(&self, key: &str, intent: &[u8], now: i64) -> LedgerResult {
        let record = &self.operations[key];
        if record.intent != intent {
            LedgerResult::Conflict
        } else if now >= record.expires_at {
            LedgerResult::Expired
        } else if record.state != GrantState::Active {
            LedgerResult::Terminal(record.state)
        } else {
            LedgerResult::Outcome(record.outcome.clone())
        }
    }

    fn refresh_atomic(&mut self, key: &str, successor: GrantRecord, fail_before_commit: bool) {
        if fail_before_commit {
            return;
        }
        self.operations.get_mut(key).unwrap().state = GrantState::Superseded;
        self.operations
            .insert(format!("{key}:successor"), successor);
    }

    fn revoke(&mut self, key: &str) {
        self.operations.get_mut(key).unwrap().state = GrantState::Revoked;
    }
}

/// Pure deterministic reference model for issuer-ledger replay transitions.
/// Live crash/restart and concurrent HTTP delivery are covered by Cotest's
/// service harness, not by this in-memory KAT.
pub fn run_session_grant_issuer_ledger_reference_model_suite() -> Result<()> {
    let fixture = load_fixture_value(SESSION_FIXTURE)?;
    let cases = fixture["ledger_cases"].as_array().context("ledger cases")?;
    for required in [
        "issue_response_loss_restart_exact_replay",
        "same_identity_different_intent",
        "replay_after_expiry",
        "refresh_response_loss_restart_exact_replay",
        "cross_issuer_same_id_isolated",
    ] {
        ensure!(
            cases
                .iter()
                .any(|case| case["name"].as_str() == Some(required)),
            "missing ledger case {required}"
        );
    }
    let intent = br#"{"audience":"did:web:service.example","request":"same"}"#;
    let outcome =
        br#"{"session_grant_id":"ak:session_grant:019a0000-0000-7000-8000-000000000011","session_grant":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#;
    let mut ledger = MiniIssuerLedger::default();
    ensure!(
        ledger.issue("proof-1", intent, outcome, 100) == LedgerResult::Outcome(outcome.to_vec())
    );
    let writes = ledger.operations.len();
    ensure!(
        ledger.issue("proof-1", intent, b"must-not-win", 100)
            == LedgerResult::Outcome(outcome.to_vec())
    );
    ensure!(
        ledger.operations.len() == writes,
        "exact replay wrote a second grant"
    );
    ensure!(ledger.issue("proof-1", b"different", b"new", 100) == LedgerResult::Conflict);
    ensure!(
        ledger.operations.len() == writes,
        "conflict changed issuer state"
    );

    // Reference snapshot reload only: cloning models reloading durable rows;
    // the live harness owns actual process-kill/restart coverage.
    let restarted = ledger.clone();
    ensure!(restarted.replay("proof-1", intent, 50) == LedgerResult::Outcome(outcome.to_vec()));
    ensure!(restarted.replay("proof-1", intent, 100) == LedgerResult::Expired);

    let successor = GrantRecord {
        intent: b"refresh".to_vec(),
        outcome: b"successor".to_vec(),
        expires_at: 200,
        state: GrantState::Active,
    };
    ledger.refresh_atomic("proof-1", successor.clone(), true);
    ensure!(ledger.operations["proof-1"].state == GrantState::Active);
    ensure!(!ledger.operations.contains_key("proof-1:successor"));
    ledger.refresh_atomic("proof-1", successor, false);
    ensure!(ledger.replay("proof-1", intent, 50) == LedgerResult::Terminal(GrantState::Superseded));
    ensure!(ledger.operations["proof-1:successor"].state == GrantState::Active);
    ledger.revoke("proof-1:successor");
    ensure!(ledger.operations["proof-1:successor"].state == GrantState::Revoked);
    Ok(())
}

pub fn run_session_grant_issuer_ledger_suite() -> Result<()> {
    run_session_grant_issuance_kat_suite().context("session-grant issuance KAT")?;
    run_session_grant_issuer_ledger_reference_model_suite()
        .context("session-grant issuer-ledger reference model")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_ledger_vectors_run_clean() {
        run_session_grant_issuer_ledger_suite().unwrap();
    }
}
