//! Cross-service conformance for issuer-ledger SessionGrants. SessionGrants deliberately never
//! enter the Event/lattice reducer: the issuer record and its canonical outcome are the
//! replay authority.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use arkret_models_identity::{
    CanonicalSessionPublicJwk, SessionGrantIssuancePreimage, SignedSessionGrantClaims,
};
use serde_json::{Value, json};

use super::load_fixture_value;

const SESSION_FIXTURE: &str = "session-grant-issuance-fixture.json";
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string {key}"))
}

fn materialize_issuance_preimage(vectors: &[Value], vector: &Value) -> Result<Value> {
    if let Some(canonical_preimage) = vector
        .get("canonical_preimage_utf8")
        .and_then(Value::as_str)
    {
        return serde_json::from_str(canonical_preimage)
            .context("parse canonical issuance preimage fixture");
    }

    let mut preimage = if !vector["issuance_preimage"].is_null() {
        vector["issuance_preimage"].clone()
    } else {
        let inherited = text(vector, "inherits")?;
        let base = vectors
            .iter()
            .find(|candidate| candidate["name"].as_str() == Some(inherited))
            .with_context(|| format!("unknown inherited issuance vector {inherited}"))?;
        materialize_issuance_preimage(vectors, base)?
    };
    if let Some(overrides) = vector["override"].as_object() {
        let object = preimage
            .as_object_mut()
            .context("issuance preimage object")?;
        for (field, value) in overrides {
            object.insert(field.clone(), value.clone());
        }
    }
    if let Some(omitted) = vector["omit"].as_array() {
        let object = preimage
            .as_object_mut()
            .context("issuance preimage object")?;
        for field in omitted {
            object.remove(field.as_str().context("omitted field must be a string")?);
        }
    }
    Ok(preimage)
}

/// Pin issuer domain separation, the closed preimage and the suite-tagged ID.
pub fn run_session_grant_issuance_kat_suite() -> Result<()> {
    let fixture = load_fixture_value(SESSION_FIXTURE)?;
    let vectors = fixture["accepted_vectors"]
        .as_array()
        .context("accepted_vectors must be an array")?;
    ensure!(vectors.len() >= 3, "session-grant KAT coverage regressed");
    for required in [
        "issuer_a_closed_preimage",
        "issuer_b_domain_separation",
        "absent_optional_is_omitted",
    ] {
        ensure!(
            vectors
                .iter()
                .any(|vector| vector["name"].as_str() == Some(required)),
            "session-grant KAT is missing required vector {required}"
        );
    }

    let mut derived_ids = BTreeMap::new();
    for vector in vectors {
        let name = text(vector, "name")?;
        let preimage: SessionGrantIssuancePreimage =
            serde_json::from_value(materialize_issuance_preimage(vectors, vector)?)
                .with_context(|| format!("parse issuance preimage {name}"))?;
        let bytes = preimage.canonical_bytes()?;
        ensure!(
            bytes == text(vector, "canonical_preimage_utf8")?.as_bytes(),
            "canonical issuance bytes drifted for {name}"
        );
        ensure!(
            hex::encode(preimage.issuance_digest()?) == text(vector, "sha256_digest_hex")?,
            "issuance digest drifted for {name}"
        );
        let grant_id = preimage.grant_id()?;
        ensure!(grant_id.as_str() == text(vector, "session_grant_id")?);
        ensure!(grant_id.as_str() == text(vector, "jwt_jti")?);
        derived_ids.insert(name.to_owned(), grant_id.to_string());

        // A signed claim is the preimage plus kind+jti, never an Event envelope.
        let mut claims = materialize_issuance_preimage(vectors, vector)?;
        claims
            .as_object_mut()
            .context("preimage object")?
            .remove("schema");
        claims["kind"] = json!("ak.session.grant");
        claims["jti"] = json!(grant_id.as_str());
        let claims: arkret_models_identity::SignedSessionGrantClaims =
            serde_json::from_value(claims).with_context(|| format!("parse claims {name}"))?;
        claims.validate()?;
        ensure!(claims.recomputed_grant_id()? == grant_id);
    }
    ensure!(
        derived_ids["issuer_a_closed_preimage"] != derived_ids["issuer_b_domain_separation"],
        "issuer DID must domain-separate otherwise identical grants"
    );
    let canonical_jwk = text(&fixture["jwk_canonicalization"], "all_inputs_normalize_to")?;
    for wire in fixture["equivalent_non_canonical_jwk_inputs"]
        .as_array()
        .context("equivalent JWK inputs")?
    {
        ensure!(CanonicalSessionPublicJwk::new(wire.as_str().unwrap())?.as_str() == canonical_jwk);
    }

    let vector_by_name = |name: &str| -> Result<&Value> {
        vectors
            .iter()
            .find(|vector| vector["name"].as_str() == Some(name))
            .with_context(|| format!("unknown accepted vector {name}"))
    };
    let claims_value = |vector: &Value| -> Result<Value> {
        let mut claims = materialize_issuance_preimage(vectors, vector)?;
        claims
            .as_object_mut()
            .context("preimage object")?
            .remove("schema");
        claims["kind"] = json!("ak.session.grant");
        claims["jti"] = vector["session_grant_id"].clone();
        Ok(claims)
    };
    for tamper in fixture["tamper_cases"]
        .as_array()
        .context("tamper_cases must be an array")?
    {
        let base = vector_by_name(
            tamper["base_vector"]
                .as_str()
                .unwrap_or("issuer_a_closed_preimage"),
        )?;
        let mut claims = claims_value(base)?;
        match text(tamper, "mutate")? {
            "issuance_nonce" => {
                claims["issuance_nonce"] = json!("/////////////////////wAAAAAAAAAAAAAAAAAAAAA")
            }
            "audience" => claims["audience"] = json!("did:webvh:z6mkfixture:other.example"),
            "holder_binding.device_binding" => {
                claims["holder_binding"]["device_binding"] =
                    json!("ak:device:019a0000-0000-7000-8000-000000000099")
            }
            "session_public_key_member_order_or_whitespace" => {
                claims["session_public_key"] = json!(
                    "{ \"kty\": \"OKP\", \"crv\": \"Ed25519\", \"x\": \"11qYAYdk9Jc1iP4Z9Qv7XKpM6Jw8LmN0RsTuVwXyZaB\" }"
                )
            }
            "session_id" => claims["session_id"] = base["session_grant_id"].clone(),
            other => bail!("unhandled SessionGrant tamper vector {other}"),
        }
        let rejected = serde_json::from_value::<SignedSessionGrantClaims>(claims)
            .map_or(true, |claims| claims.validate().is_err());
        ensure!(
            rejected,
            "tamper vector {} was accepted",
            text(tamper, "name")?
        );
    }

    for negative in fixture["credential_binding_negative_cases"]
        .as_array()
        .context("credential binding negatives")?
    {
        let base = vector_by_name(text(negative, "base_vector")?)?;
        let mut claims = claims_value(base)?;
        if let Some(fields) = negative["omit"].as_array() {
            for field in fields {
                claims
                    .as_object_mut()
                    .unwrap()
                    .remove(field.as_str().unwrap());
            }
        }
        if let Some(add) = negative.get("add_from_vector") {
            let field = text(add, "field")?;
            let source = vector_by_name(text(add, "vector")?)?;
            claims[field] = materialize_issuance_preimage(vectors, source)?[field].clone();
        }
        let rejected = serde_json::from_value::<SignedSessionGrantClaims>(claims)
            .map_or(true, |claims| claims.validate().is_err());
        ensure!(
            rejected,
            "binding negative {} was accepted",
            text(negative, "name")?
        );
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
    let replay_names: Vec<&str> = fixture["replay_cases"]
        .as_array()
        .context("replay cases")?
        .iter()
        .map(|case| case["name"].as_str().unwrap())
        .collect();
    ensure!(
        replay_names
            == [
                "same_request_exact_replay",
                "same_key_different_intent",
                "replay_after_expiry",
                "replay_after_supersede"
            ]
    );
    let intent = br#"{"audience":"did:web:service.example","request":"same"}"#;
    let outcome =
        br#"{"session_grant_id":"ak:session_grant:fixture","session_grant":"jwt.fixture"}"#;
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
