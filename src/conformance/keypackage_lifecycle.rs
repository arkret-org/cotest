//! MLS KeyPackage lifecycle conformance vectors.
//!
//! Covers single-use claim limits, last-resort KeyPackage semantics, and MLS
//! Welcome digest binding against the spec artifact fixture.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, anyhow, bail};
use arkret_identifiers::{DeviceId, DidCoreId, RealmId};
use arkret_models_collaboration::device_messages::RecipientDelivery;
use arkret_models_crypto::{KeyPackagesClaimOutcome, KeyPackagesUploadOutcome, MlsKeyPackageState};
use arkret_wire::{DidUrl, MlsWelcomeDelivery, ProfileId};
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Digest as _;

use super::schema_validation_fixture::{schema_invalid, schema_valid};
use super::{expected_bool, expected_str, expected_u64, required_str, required_u64};

pub const VECTOR_ID_KEYPACKAGE_EXHAUSTION_CLAIM_LIMITS: &str =
    "ak.vector.keypackage.exhaustion_claim_limits.v1";
pub const VECTOR_ID_KEYPACKAGE_LAST_RESORT_CLAIM_AND_REUSE: &str =
    "ak.vector.keypackage.last_resort_claim_and_reuse.v1";
pub const VECTOR_ID_KEYPACKAGE_LAST_RESORT_FORCED_ROTATION: &str =
    "ak.vector.keypackage.last_resort_forced_rotation.v1";
pub const VECTOR_ID_KEYPACKAGE_LAST_RESORT_AFFINITY_AND_OPTIONALITY: &str =
    "ak.vector.keypackage.last_resort_affinity_and_optionality.v1";
pub const VECTOR_ID_MLS_WELCOME_KEYPACKAGE_HASH: &str = "ak.vector.mls.welcome_keypackage_hash.v1";
pub const VECTOR_ID_KEYPACKAGE_SELF_CLAIM_AUTHORIZATION_IDEMPOTENCY: &str =
    "ak.vector.keypackage.self_claim_authorization_idempotency.v1";
pub const VECTOR_ID_KEYPACKAGE_PEER_CLAIM_ATOMIC_IDEMPOTENCY: &str =
    "ak.vector.keypackage.peer_claim_atomic_idempotency.v1";
pub const VECTOR_ID_KEYPACKAGE_PEER_CLAIM_DOUBLE_AUTHORIZATION_PRIVACY: &str =
    "ak.vector.keypackage.peer_claim_double_authorization_privacy.v1";
pub const VECTOR_ID_KEYPACKAGE_GROUP_CAPABILITY_FLOOR: &str =
    "ak.vector.keypackage.group_capability_floor.v1";
pub const VECTOR_ID_MLS_KEYPACKAGE_ACTOR_AND_CIPHERSUITE_CLOSURE: &str =
    "ak.vector.mls.keypackage_actor_and_ciphersuite_closure.v1";
pub const KEYPACKAGE_LIFECYCLE_ENTRYPOINT: &str = "ak.suite.crypto.keypackage_lifecycle.v1";

pub const ALL_KEYPACKAGE_LIFECYCLE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_KEYPACKAGE_EXHAUSTION_CLAIM_LIMITS,
    VECTOR_ID_KEYPACKAGE_LAST_RESORT_CLAIM_AND_REUSE,
    VECTOR_ID_KEYPACKAGE_LAST_RESORT_FORCED_ROTATION,
    VECTOR_ID_KEYPACKAGE_LAST_RESORT_AFFINITY_AND_OPTIONALITY,
    VECTOR_ID_KEYPACKAGE_PEER_CLAIM_ATOMIC_IDEMPOTENCY,
    VECTOR_ID_KEYPACKAGE_PEER_CLAIM_DOUBLE_AUTHORIZATION_PRIVACY,
    VECTOR_ID_KEYPACKAGE_SELF_CLAIM_AUTHORIZATION_IDEMPOTENCY,
    VECTOR_ID_MLS_WELCOME_KEYPACKAGE_HASH,
    VECTOR_ID_KEYPACKAGE_GROUP_CAPABILITY_FLOOR,
    VECTOR_ID_MLS_KEYPACKAGE_ACTOR_AND_CIPHERSUITE_CLOSURE,
];

#[path = "keypackage_lifecycle_cases.rs"]
mod cases;

pub use cases::run_keypackage_lifecycle_suite;

/// Executed assertions of one fixture case. A case result counts only checks
/// that ran and held; the first failing one aborts the case.
#[derive(Debug, Default)]
pub(crate) struct Tally(usize);

impl Tally {
    pub(crate) fn check(&mut self, holds: bool, message: impl FnOnce() -> String) -> Result<()> {
        if !holds {
            bail!(message());
        }
        self.0 += 1;
        Ok(())
    }

    pub(crate) fn count(&self) -> usize {
        self.0
    }
}

const KEYPACKAGE_LIFECYCLE_FIXTURE_FILE: &str = "keypackage-lifecycle-fixture.json";
const KEY_PACKAGES_UPLOAD_OUTCOME_SCHEMA: &str =
    "schemas/keypackage-operations.schema.json#/$defs/keypackages_upload_outcome";
const KEY_PACKAGES_CLAIM_OUTCOME_SCHEMA: &str =
    "schemas/keypackage-operations.schema.json#/$defs/keypackages_claim_outcome";
const MLS_WELCOME_DELIVERY_SCHEMA: &str = "schemas/mls-welcome-delivery.schema.json";
const LAST_RESORT_FEATURE: &str = "ak.feature.mls_last_resort_keypackage.v1";
const EXPIRY_SECURITY_CASE_NAME: &str = "last_resort_expiry_blocks_new_claim_not_old_decryption";
const EXPIRY_SECURITY_CASE_KIND: &str = "last_resort_expiry_security";
/// `normative-clause-registry.json` names the runner that owns the HPKE half of
/// this case. It is not cotest: judging the captured GroupSecrets layer means
/// re-implementing the decryption, and a second implementation of an evidence
/// block is exactly what a shared fixture exists to avoid.
const EXPIRY_SECURITY_EVIDENCE_RUNNER: &str = "python -m tools.test_residual_simplification";
const X25519_PRIVATE_KEY_LEN: usize = 32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeypackageLifecycleFixture {
    profile: String,
    version: String,
    suite: String,
    runner: Value,
    /// Free-form protocol instances validated by their referenced JSON Schemas.
    schema_validation_cases: Vec<Value>,
    covers_vectors: Vec<String>,
    security_evidence: Vec<super::SecurityEvidenceRow>,
    unsigned_selector_transcripts: Vec<Value>,
    cases: Vec<Value>,
    expiry_security_case: ExpirySecurityCase,
}

/// The captured-Welcome evidence block of
/// `last_resort_expiry_blocks_new_claim_not_old_decryption`.
///
/// The same case is published twice on purpose: once in `cases` as the Station
/// claim verdict cotest executes, and once here as the HPKE material the
/// registered Python runner executes. Declaring it as a typed
/// `deny_unknown_fields` struct rather than a `Value` is the point — the block
/// has a fixed shape, and a member added or renamed upstream has to be
/// followed here rather than silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpirySecurityCase {
    evidence_scope: String,
    created_day: u64,
    welcome_day: u64,
    expires_day: u64,
    compromise_day: u64,
    recipient_private_key_hex: String,
    ephemeral_private_key_hex: String,
    encrypt_context_hex: String,
    group_secrets_hex: String,
    captured_ciphertext_hex: String,
    expected: ExpirySecurityExpectation,
    runner: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpirySecurityExpectation {
    new_claim_at_or_after_expiry: String,
    matching_private_key_recovers_captured_group_secrets: bool,
    expiry_revokes_historical_decryption: bool,
    future_epoch_recovery: String,
    historical_confidentiality_restored: bool,
}

fn keypackage_fixture() -> Result<KeypackageLifecycleFixture> {
    let raw = super::load_fixture_value(KEYPACKAGE_LIFECYCLE_FIXTURE_FILE)?;
    let fixture: KeypackageLifecycleFixture = serde_json::from_value(raw.clone())?;
    validate_keypackage_lifecycle_fixture_metadata(&fixture)?;
    super::verify_security_evidence(
        KEYPACKAGE_LIFECYCLE_FIXTURE_FILE,
        &raw,
        &fixture.security_evidence,
        &fixture.covers_vectors,
    )?;
    Ok(fixture)
}

fn validate_keypackage_lifecycle_fixture_metadata(
    fixture: &KeypackageLifecycleFixture,
) -> Result<()> {
    if fixture.profile != ProfileId::E2EE_CLIENT_V1
        || fixture.suite != "keypackage_lifecycle"
        || fixture.version.trim().is_empty()
        || fixture.runner.is_null()
    {
        bail!("keypackage lifecycle fixture suite drifted");
    }

    let covers = &fixture.covers_vectors;
    let cases = &fixture.cases;

    for vector_id in ALL_KEYPACKAGE_LIFECYCLE_VECTOR_IDS {
        if !covers.iter().any(|entry| entry == vector_id) {
            bail!("keypackage lifecycle fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("keypackage lifecycle fixture missing asserted case {vector_id}");
        }
    }

    for op in [
        arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
        arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
        arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
        arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE_V1,
    ] {
        if !op.starts_with("ak.self.keys.keypackages.") {
            bail!("keypackage operation id namespace drifted: {op}");
        }
    }

    Ok(())
}

fn case_named<'a>(fixture: &'a KeypackageLifecycleFixture, name: &str) -> Result<&'a Value> {
    fixture
        .cases
        .iter()
        .find(|case| case.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| anyhow!("keypackage lifecycle fixture missing case {name}"))
}

/// Run one named fixture case on its own, for the vector-level entry points.
fn run_single_case(
    name: &str,
    run: impl FnOnce(&KeypackageLifecycleFixture, &Value, &mut Tally) -> Result<()>,
) -> Result<()> {
    let fixture = keypackage_fixture()?;
    run(&fixture, case_named(&fixture, name)?, &mut Tally::default())
}

fn required_account_principal<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(|account| account.get("principal_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("case missing {field}.principal_id"))
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    Ok(arkret_canonical::parse_timestamp_canonical(value)?)
}

fn require_model_generation_ref(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .filter(|generation| *generation > 0)
        .ok_or_else(|| anyhow!("{field} must be a positive PCR-local generation"))
}

fn core_did(value: &str) -> Result<DidCoreId> {
    DidCoreId::new(value.to_owned()).map_err(Into::into)
}

fn verification_method(value: &str) -> Result<DidUrl> {
    DidUrl::new(value.to_owned()).map_err(|error| anyhow!(error))
}

fn device(value: &str) -> Result<DeviceId> {
    DeviceId::new(value.to_owned()).map_err(Into::into)
}

fn realm(value: &str) -> Result<RealmId> {
    RealmId::new(value.to_owned()).map_err(Into::into)
}

struct ClaimRecordInput<'a> {
    claim_id: &'a str,
    keypackage_ref: &'a str,
    principal_id: &'a DidCoreId,
    device_id: &'a DeviceId,
    device_authorize_event_id: &'a str,
    last_resort: bool,
    expires_at: DateTime<Utc>,
}

fn claim_record_value(input: ClaimRecordInput<'_>) -> Value {
    let ClaimRecordInput {
        claim_id,
        keypackage_ref,
        principal_id,
        device_id,
        device_authorize_event_id,
        last_resort,
        expires_at,
    } = input;
    let mut value = json!({
        "claim_id": claim_id,
        "keypackage_ref": keypackage_ref,
        "actor_id": {
            "kind": "account",
            "account_id": {
                "principal_id": principal_id.as_str(),
                "station_id": "ak:did_core:webvh:z6mkfixtureservice"
            }
        },
        "principal_id": principal_id.as_str(),
        "device_id": device_id.as_str(),
        "keypackage": "AQID",
        "capabilities": ["ak.content.v1"],
        "device_authorize_event_id": device_authorize_event_id,
        "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
        "revocation_status": "active"
    });
    if last_resort {
        value["last_resort"] = json!(true);
    }
    value
}

fn claim_receipt_value(claims: &[Value]) -> Value {
    let target_device_id = claims
        .first()
        .and_then(|claim| claim.get("device_id"))
        .and_then(Value::as_str)
        .expect("fixture claim record must carry its exact target device id");
    let request = json!({
        "claim_request_id": "AAAAAAAAAAAAAAAAAAAAAA",
        "target_account_id": {
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:webvh:z6mkfixtureservice"
        },
        "intended_realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "requester_account_id": {
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:webvh:z6mkfixtureservice"
        },
        "mls_group_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "claim_purpose": "realm_membership",
        "required_capabilities": ["ak.content.v1"],
        "expires_at": "2026-01-01T00:05:00.000Z",
        "target_device_ids": [target_device_id]
    });
    let request_digest = arkret_canonical::canonical_sha256(&request)
        .expect("fixture claim request must be canonicalizable");
    let claims_digest = arkret_canonical::canonical_sha256(&claims)
        .expect("fixture claim records must be canonicalizable");
    json!({
        "claim_request_id": "AAAAAAAAAAAAAAAAAAAAAA",
        "request_digest": request_digest,
        "claims_digest": claims_digest,
        "source_id": "ak:did_core:webvh:z6mkfixtureservice",
        "destination_id": "ak:did_core:webvh:z6mkfixtureservice",
        "request": request,
        "claimed_at": "2026-01-01T00:00:00.000Z",
        "expires_at": "2026-01-01T00:05:00.000Z",
        "signature": {
            "kid": "did:webvh:z6mkfixtureservice:service.example#key-1",
            "signature_algorithm": "Ed25519",
            "sig": "c2ln"
        }
    })
}

fn claim_outcome_value(record: Value) -> Value {
    let claims = vec![record];
    let claim_receipt = claim_receipt_value(&claims);
    json!({
        "claim_request_id": "AAAAAAAAAAAAAAAAAAAAAA",
        "claims": claims,
        "claim_receipt": claim_receipt
    })
}

fn claim_failure_outcome_value() -> Value {
    json!({
        "error": {
            "code": "claim_failed",
            "message": "KeyPackage claim failed"
        }
    })
}

fn assert_claim_failed(value: &Value) -> Result<()> {
    if value.pointer("/error/code").and_then(Value::as_str) != Some("claim_failed")
        || value.pointer("/error/message").and_then(Value::as_str)
            != Some("KeyPackage claim failed")
        || value
            .pointer("/error")
            .and_then(Value::as_object)
            .map(|row| row.len())
            != Some(2)
    {
        bail!("target-private failure did not use the fixed claim_failed envelope");
    }
    Ok(())
}

fn parse_claim_outcome(value: Value) -> Result<KeyPackagesClaimOutcome> {
    schema_valid(KEY_PACKAGES_CLAIM_OUTCOME_SCHEMA, &value)?;
    serde_json::from_value(value).map_err(Into::into)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MiniKeypackageState {
    Published,
    Claimed,
    Consumed,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum MiniConsumeDecision {
    Consumed(String),
    Rejected(String),
}

impl MiniKeypackageState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Claimed => "claimed",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LastResortAuditRecord {
    claim_id: String,
    keypackage_ref: String,
    keypackage_digest: String,
    intended_realm_id: RealmId,
    last_resort: bool,
}

#[derive(Clone, Debug)]
struct MiniKeypackage {
    keypackage_ref: String,
    keypackage_digest: String,
    principal_id: DidCoreId,
    verification_method: DidUrl,
    device_id: DeviceId,
    intended_realm_id: RealmId,
    last_resort: bool,
    state: MiniKeypackageState,
    expires_at: DateTime<Utc>,
    claim_ids: Vec<String>,
    audit_records: Vec<LastResortAuditRecord>,
    joined_groups: Vec<String>,
}

impl MiniKeypackage {
    fn new_normal(
        keypackage_ref: impl Into<String>,
        keypackage_digest: impl Into<String>,
        principal_id: DidCoreId,
        verification_method: DidUrl,
        device_id: DeviceId,
        intended_realm_id: RealmId,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            keypackage_ref: keypackage_ref.into(),
            keypackage_digest: keypackage_digest.into(),
            principal_id,
            verification_method,
            device_id,
            intended_realm_id,
            last_resort: false,
            state: MiniKeypackageState::Published,
            expires_at,
            claim_ids: Vec::new(),
            audit_records: Vec::new(),
            joined_groups: Vec::new(),
        }
    }

    fn new_last_resort(
        keypackage_ref: impl Into<String>,
        keypackage_digest: impl Into<String>,
        principal_id: DidCoreId,
        verification_method: DidUrl,
        device_id: DeviceId,
        intended_realm_id: RealmId,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let mut package = Self::new_normal(
            keypackage_ref,
            keypackage_digest,
            principal_id,
            verification_method,
            device_id,
            intended_realm_id,
            expires_at,
        );
        package.last_resort = true;
        package
    }

    fn claim_record(&mut self, claim_id: &str) -> Value {
        self.claim_ids.push(claim_id.to_owned());
        if !self.last_resort {
            self.state = MiniKeypackageState::Claimed;
        }
        claim_record_value(ClaimRecordInput {
            claim_id,
            keypackage_ref: &self.keypackage_ref,
            principal_id: &self.principal_id,
            device_id: &self.device_id,
            device_authorize_event_id: "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
            last_resort: self.last_resort,
            expires_at: self.expires_at,
        })
    }

    fn consume(
        &mut self,
        claim_id: &str,
        realm_id: &RealmId,
        now: DateTime<Utc>,
    ) -> Result<MiniConsumeDecision> {
        if self.last_resort && &self.intended_realm_id != realm_id {
            return Ok(MiniConsumeDecision::Rejected(
                arkret_wire::ReasonCode::LAST_RESORT_REALM_AFFINITY_VIOLATION.to_owned(),
            ));
        }
        if !self.last_resort && now > self.expires_at {
            self.state = MiniKeypackageState::Revoked;
            return Ok(MiniConsumeDecision::Rejected(
                arkret_wire::ErrorCode::KEYPACKAGE_UNKNOWN.to_owned(),
            ));
        }
        match (self.last_resort, self.state) {
            (true, MiniKeypackageState::Published | MiniKeypackageState::Claimed) => {
                self.audit_records.push(LastResortAuditRecord {
                    claim_id: claim_id.to_owned(),
                    keypackage_ref: self.keypackage_ref.clone(),
                    keypackage_digest: self.keypackage_digest.clone(),
                    intended_realm_id: realm_id.clone(),
                    last_resort: true,
                });
                Ok(MiniConsumeDecision::Consumed(self.keypackage_ref.clone()))
            }
            (false, MiniKeypackageState::Claimed) => {
                self.state = MiniKeypackageState::Consumed;
                Ok(MiniConsumeDecision::Consumed(self.keypackage_ref.clone()))
            }
            (false, MiniKeypackageState::Consumed) => Ok(MiniConsumeDecision::Rejected(
                arkret_wire::ErrorCode::KEYPACKAGE_ALREADY_CONSUMED.to_owned(),
            )),
            (_, MiniKeypackageState::Revoked | MiniKeypackageState::Consumed) => {
                Ok(MiniConsumeDecision::Rejected(
                    arkret_wire::ErrorCode::KEYPACKAGE_UNKNOWN.to_owned(),
                ))
            }
            (false, MiniKeypackageState::Published) => Ok(MiniConsumeDecision::Rejected(
                arkret_wire::ErrorCode::KEYPACKAGE_UNKNOWN.to_owned(),
            )),
        }
    }

    /// Retire the package at its own `expires_at`.
    ///
    /// Expiry revokes the *distributable* package and nothing else. It cannot
    /// reach backwards into a Welcome an attacker already captured, which is
    /// why the returned reason is a claim-side reason code and the transition
    /// touches no audit record.
    fn expire(&mut self, now: DateTime<Utc>) -> Option<&'static str> {
        if now < self.expires_at {
            return None;
        }
        self.state = MiniKeypackageState::Revoked;
        Some(arkret_wire::ReasonCode::KEYPACKAGE_EXPIRED)
    }
}

fn claim_from_pool(
    pool: &mut [MiniKeypackage],
    realm_id: &RealmId,
    claim_id: &str,
    feature_supported: bool,
    explicit_last_resort_fallback: bool,
) -> Result<Value> {
    if let Some(package) = pool.iter_mut().find(|package| {
        !package.last_resort
            && package.state == MiniKeypackageState::Published
            && &package.intended_realm_id == realm_id
    }) {
        return Ok(claim_outcome_value(package.claim_record(claim_id)));
    }

    if explicit_last_resort_fallback && !feature_supported {
        return Ok(claim_failure_outcome_value());
    }

    if feature_supported
        && let Some(package) = pool.iter_mut().find(|package| {
            package.last_resort
                && package.state == MiniKeypackageState::Published
                && &package.intended_realm_id == realm_id
        })
    {
        return Ok(claim_outcome_value(package.claim_record(claim_id)));
    }

    Ok(claim_failure_outcome_value())
}

fn rotate_last_resort(
    pool: &mut Vec<MiniKeypackage>,
    old_ref: &str,
    new_ref: &str,
) -> Result<Vec<String>> {
    let old = pool
        .iter_mut()
        .find(|package| package.keypackage_ref == old_ref)
        .ok_or_else(|| anyhow!("old last-resort package not found"))?;
    if !old.last_resort {
        bail!("rotation target is not last-resort");
    }
    old.state = MiniKeypackageState::Revoked;
    let commits = old
        .joined_groups
        .iter()
        .map(|group| format!("mls_self_update:{group}"))
        .collect::<Vec<_>>();
    let replacement = MiniKeypackage::new_last_resort(
        new_ref,
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        old.principal_id.clone(),
        old.verification_method.clone(),
        old.device_id.clone(),
        old.intended_realm_id.clone(),
        old.expires_at,
    );
    pool.push(replacement);
    Ok(commits)
}

fn exhaustion_claim_limits_case(vector: &Value, tally: &mut Tally) -> Result<()> {
    let min_available = vector
        .get("keypackage_min_available")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("exhaustion vector missing keypackage_min_available"))?;
    let local_usable_count = vector
        .get("local_usable_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("exhaustion vector missing local_usable_count"))?;
    tally.check(local_usable_count < min_available, || {
        "exhaustion vector must start below keypackage_min_available".to_owned()
    })?;
    let refill_count = min_available - local_usable_count;
    tally.check(
        !(vector
            .pointer("/expected/bounded_refill_count")
            .and_then(Value::as_u64)
            != Some(refill_count)),
        || "local KeyPackage refill must equal the startup deficit".to_owned(),
    )?;

    let upload_value = json!({
        "accepted": refill_count,
        "keypackage_refs": ["sha256:5555555555555555555555555555555555555555555555555555555555555555"]
    });
    schema_valid(KEY_PACKAGES_UPLOAD_OUTCOME_SCHEMA, &upload_value)?;
    let _: KeyPackagesUploadOutcome = serde_json::from_value(upload_value)?;

    let limit = vector
        .pointer("/claim_rate_limit/max_claims")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("exhaustion vector missing claim_rate_limit.max_claims"))?;
    let attempt = vector
        .pointer("/claim_rate_limit/attempt")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("exhaustion vector missing claim_rate_limit.attempt"))?;
    tally.check(attempt > limit, || {
        "rate-limit control must exceed the allowed claim count".to_owned()
    })?;
    let rate_limited = claim_failure_outcome_value();
    assert_claim_failed(&rate_limited)?;
    tally.check(
        expected_str(vector, "rate_limit_audit_reason")? == "keypackage_claim_rate_limited",
        || "keypackage claim rate-limit audit reason drifted".to_owned(),
    )?;
    tally.check(
        expected_str(vector, "rate_limit_external_failure")? == "anti_enumeration",
        || "rate-limit external failure semantics drifted".to_owned(),
    )?;

    let principal = core_did(required_account_principal(vector, "target_account_id")?)?;
    let signer = verification_method(
        "did:webvh:z6mkfixture:alice.example#ak:device:0196419b-0000-7000-8000-000000000001",
    )?;
    let device = device(required_str(vector, "device_id")?)?;
    let realm = realm(required_str(vector, "intended_realm_id")?)?;
    let expired = vector
        .get("expired_claim")
        .ok_or_else(|| anyhow!("exhaustion vector missing expired_claim"))?;
    let mut package = MiniKeypackage::new_normal(
        required_str(expired, "keypackage_ref")?,
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        principal,
        signer,
        device,
        realm.clone(),
        parse_time(required_str(expired, "expires_at")?)?,
    );
    package.state = MiniKeypackageState::Claimed;
    let consume = package.consume(
        required_str(expired, "claim_id")?,
        &realm,
        parse_time(required_str(expired, "consume_at")?)?,
    )?;
    tally.check(
        package.state.as_str() == expected_str(vector, "expired_status")?,
        || "expired claimed keypackage did not become revoked".to_owned(),
    )?;
    tally.check(
        !(consume
            != MiniConsumeDecision::Rejected(
                expected_str(vector, "expired_external_reason")?.to_owned(),
            )),
        || "expired keypackage consume did not reject with expected reason".to_owned(),
    )?;
    validate_wire_state_cases(vector, tally)?;
    Ok(())
}

fn validate_wire_state_cases(vector: &Value, tally: &mut Tally) -> Result<()> {
    let cases = vector
        .get("wire_state_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("keypackage vector missing wire_state_cases[]"))?;
    let mut seen = BTreeSet::new();
    for case in cases {
        let from = required_str(case, "from")?;
        let to = required_str(case, "to")?;
        tally.check(seen.insert((from, to)), || {
            format!("duplicate keypackage wire transition {from}->{to}")
        })?;
        tally.check(from == "published", || {
            "wire-state fixture currently requires a published source state".to_owned()
        })?;
        tally.check(
            !(to == "revoked" && MiniKeypackageState::Revoked.as_str() != to),
            || "mini lifecycle model does not expose the revoked wire state".to_owned(),
        )?;
        // KeyPackage lifecycle state is no longer an Event payload; the closed
        // wire state set (device-lifecycle.md 9.1) is the SDK's
        // MlsKeyPackageState, which carries it on every KeyPackage record.
        let accepted = serde_json::from_value::<MlsKeyPackageState>(json!(to)).is_ok();
        let expected = required_str(case, "expected")?;
        tally.check(!(accepted != (expected == "accepted")), || {
            format!(
                "keypackage wire transition {from}->{to} produced {}, expected {expected}",
                if accepted {
                    "accepted"
                } else {
                    "schema_violation"
                },
            )
        })?;
    }
    tally.check(
        !(!seen.contains(&("published", "revoked")) || !seen.contains(&("published", "expired"))),
        || {
            "keypackage wire-state cases must cover revoked acceptance and expired rejection"
                .to_owned()
        },
    )?;
    Ok(())
}

fn last_resort_claim_and_reuse_case(vector: &Value, tally: &mut Tally) -> Result<()> {
    tally.check(
        required_str(vector, "feature")? == LAST_RESORT_FEATURE,
        || "last-resort feature id drifted".to_owned(),
    )?;
    let principal = core_did(required_account_principal(vector, "target_account_id")?)?;
    let signer = verification_method(
        "did:webvh:z6mkfixture:alice.example#ak:device:0196419b-0000-7000-8000-000000000001",
    )?;
    let device = device(required_str(vector, "device_id")?)?;
    let realm = realm(required_str(vector, "intended_realm_id")?)?;
    let expires_at = parse_time("2100-01-01T00:00:00.000Z")?;
    let mut pool = vec![
        MiniKeypackage::new_normal(
            required_str(vector, "normal_keypackage_ref")?,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            principal.clone(),
            signer.clone(),
            device.clone(),
            realm.clone(),
            expires_at,
        ),
        MiniKeypackage::new_last_resort(
            required_str(vector, "last_resort_keypackage_ref")?,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            principal,
            signer,
            device,
            realm.clone(),
            expires_at,
        ),
    ];

    let normal_claim = parse_claim_outcome(claim_from_pool(
        &mut pool,
        &realm,
        "ak:keypackage_claim:0199c001-0000-7000-8000-000000000001",
        true,
        false,
    )?)?;
    tally.check(
        !(expected_bool(vector, "normal_preferred_when_available")?
            && normal_claim.claims[0].keypackage_ref
                != required_str(vector, "normal_keypackage_ref")?),
        || "single-use package was not preferred while available".to_owned(),
    )?;

    let claim_ids = vector
        .get("last_resort_claim_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("last-resort vector missing claim ids"))?;
    let first_claim_id = claim_ids[0]
        .as_str()
        .ok_or_else(|| anyhow!("claim id must be string"))?;
    let last_resort_claim = parse_claim_outcome(claim_from_pool(
        &mut pool,
        &realm,
        first_claim_id,
        true,
        true,
    )?)?;
    tally.check(
        !(last_resort_claim.claims[0].keypackage_ref
            != required_str(vector, "last_resort_keypackage_ref")?
            || last_resort_claim.claims[0].last_resort != Some(true)),
        || "empty single-use pool did not return last_resort=true claim record".to_owned(),
    )?;

    let last_resort = pool
        .iter_mut()
        .find(|package| package.last_resort)
        .ok_or_else(|| anyhow!("last-resort package missing"))?;
    for claim_id in claim_ids {
        let claim_id = claim_id
            .as_str()
            .ok_or_else(|| anyhow!("last-resort claim id must be string"))?;
        let consume = last_resort.consume(claim_id, &realm, expires_at)?;
        tally.check(
            consume == MiniConsumeDecision::Consumed(last_resort.keypackage_ref.clone()),
            || "last-resort consume did not return idempotent success".to_owned(),
        )?;
    }
    tally.check(
        last_resort.state.as_str() == expected_str(vector, "state_after_consume")?,
        || "last-resort consume changed package state".to_owned(),
    )?;
    tally.check(
        !(expected_bool(vector, "last_resort_consume_idempotent")?
            && last_resort
                .audit_records
                .iter()
                .any(|record| !record.last_resort)),
        || "last-resort audit record lost last_resort=true marker".to_owned(),
    )?;
    tally.check(
        last_resort.audit_records.len() as u64 == expected_u64(vector, "audit_records")?,
        || "last-resort consume audit record count drifted".to_owned(),
    )?;
    tally.check(
        !(expected_str(vector, "forbidden_reason")?
            != arkret_wire::ErrorCode::KEYPACKAGE_ALREADY_CONSUMED),
        || "last-resort forbidden reason constant drifted".to_owned(),
    )?;
    Ok(())
}

fn last_resort_forced_rotation_case(vector: &Value, tally: &mut Tally) -> Result<()> {
    tally.check(
        required_str(vector, "feature")? == LAST_RESORT_FEATURE,
        || "last-resort feature id drifted".to_owned(),
    )?;
    let principal = core_did("ak:did_core:web:alice.example")?;
    let signer = verification_method(
        "did:web:alice.example#ak:device:0196419b-0000-7000-8000-000000000001",
    )?;
    let device = device(required_str(vector, "device_id")?)?;
    let realm = realm("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1")?;
    let expires_at = parse_time("2100-01-01T00:00:00.000Z")?;
    let mut old = MiniKeypackage::new_last_resort(
        required_str(vector, "old_last_resort_keypackage_ref")?,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        principal,
        signer,
        device,
        realm.clone(),
        expires_at,
    );
    old.joined_groups = vector
        .get("joined_groups")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("rotation vector missing joined_groups"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("joined group must be string"))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut pool = vec![old];
    let commits = rotate_last_resort(
        &mut pool,
        required_str(vector, "old_last_resort_keypackage_ref")?,
        required_str(vector, "new_last_resort_keypackage_ref")?,
    )?;
    let old = pool
        .iter()
        .find(|package| {
            package.keypackage_ref
                == required_str(vector, "old_last_resort_keypackage_ref").unwrap()
        })
        .ok_or_else(|| anyhow!("old package missing after rotation"))?;
    tally.check(
        old.state.as_str() == expected_str(vector, "old_state")?,
        || "old last-resort package was not revoked after rotation".to_owned(),
    )?;
    tally.check(
        commits.len() as u64 == expected_u64(vector, "self_update_commits")?,
        || "rotation did not emit one MLS self-update per joined group".to_owned(),
    )?;
    tally.check(
        !(expected_str(vector, "rotation_reason")?
            != arkret_wire::ReasonCode::LAST_RESORT_ROTATION_REQUIRED),
        || "last-resort rotation reason drifted".to_owned(),
    )?;

    let claim = parse_claim_outcome(claim_from_pool(
        &mut pool,
        &realm,
        "ak:keypackage_claim:0199c001-0000-7000-8000-000000000002",
        true,
        true,
    )?)?;
    tally.check(
        !(expected_bool(vector, "old_not_distributed_after_rotation")?
            && claim.claims[0].keypackage_ref
                != required_str(vector, "new_last_resort_keypackage_ref")?),
        || "rotated old last-resort package was still distributed".to_owned(),
    )?;
    let new = pool
        .iter()
        .find(|package| {
            package.keypackage_ref
                == required_str(vector, "new_last_resort_keypackage_ref").unwrap()
        })
        .ok_or_else(|| anyhow!("new package missing after rotation"))?;
    tally.check(
        new.state.as_str() == expected_str(vector, "new_state")?,
        || "replacement last-resort package is not published".to_owned(),
    )?;
    Ok(())
}

/// Execute the Station half of
/// `last_resort_expiry_blocks_new_claim_not_old_decryption`, and bind it to the
/// crypto evidence block that carries the other half.
///
/// The case is published in two places under one timeline. Splitting a case
/// across two runners is fine; letting the two halves drift apart is not, and
/// nothing else would catch it — the registered Python runner never reads
/// `cases`, and this suite never decrypts anything.
///
/// The three verdicts that must agree are the ones that would flip the security
/// claim: expiry MUST block a new claim, expiry MUST NOT reach backwards into a
/// captured Welcome, and a later secret update MUST NOT restore confidentiality
/// that was already lost.
fn last_resort_expiry_security_case(
    fixture: &KeypackageLifecycleFixture,
    lifecycle: &Value,
    tally: &mut Tally,
) -> Result<()> {
    let evidence = &fixture.expiry_security_case;
    tally.check(evidence.runner == EXPIRY_SECURITY_EVIDENCE_RUNNER, || {
        format!(
            "expiry security evidence runner drifted: {}",
            evidence.runner
        )
    })?;
    tally.check(!(evidence.evidence_scope.trim().is_empty()), || {
        "expiry security evidence must state what it does and does not cover".to_owned()
    })?;
    for (field, value, exact_len) in [
        (
            "recipient_private_key_hex",
            &evidence.recipient_private_key_hex,
            Some(X25519_PRIVATE_KEY_LEN),
        ),
        (
            "ephemeral_private_key_hex",
            &evidence.ephemeral_private_key_hex,
            Some(X25519_PRIVATE_KEY_LEN),
        ),
        ("encrypt_context_hex", &evidence.encrypt_context_hex, None),
        ("group_secrets_hex", &evidence.group_secrets_hex, None),
        (
            "captured_ciphertext_hex",
            &evidence.captured_ciphertext_hex,
            None,
        ),
    ] {
        let bytes = hex::decode(value).map_err(|error| anyhow!("{field} is not hex: {error}"))?;
        tally.check(!(bytes.is_empty()), || {
            format!("{field} carries no material")
        })?;
        if let Some(len) = exact_len
            && bytes.len() != len
        {
            bail!("{field} must be {len} bytes, got {}", bytes.len());
        }
    }
    // A sealed GroupSecrets layer is strictly longer than the plaintext it
    // hides. Without this the fixture could carry the plaintext twice and the
    // registered runner's "recovers the captured GroupSecrets" result would be
    // vacuous.
    tally.check(
        !(hex::decode(&evidence.captured_ciphertext_hex)?.len()
            <= hex::decode(&evidence.group_secrets_hex)?.len()),
        || "captured ciphertext is not an AEAD expansion of the GroupSecrets plaintext".to_owned(),
    )?;
    tally.check(!(!(evidence.created_day <= evidence.welcome_day
        && evidence.welcome_day < evidence.expires_day
        && evidence.expires_day < evidence.compromise_day)), || "expiry security timeline must capture the Welcome before expiry and compromise it after".to_owned())?;

    tally.check(
        required_str(lifecycle, "kind")? == EXPIRY_SECURITY_CASE_KIND,
        || format!("{EXPIRY_SECURITY_CASE_NAME} is no longer a last-resort expiry security case"),
    )?;
    tally.check(
        required_str(lifecycle, "vector_id")? == VECTOR_ID_KEYPACKAGE_LAST_RESORT_FORCED_ROTATION,
        || format!("{EXPIRY_SECURITY_CASE_NAME} moved to another vector"),
    )?;
    for (field, declared) in [
        ("created_day", evidence.created_day),
        ("welcome_day", evidence.welcome_day),
        ("expires_day", evidence.expires_day),
        ("compromise_day", evidence.compromise_day),
    ] {
        tally.check(required_u64(lifecycle, field)? == declared, || {
            format!("{EXPIRY_SECURITY_CASE_NAME} and its crypto evidence disagree about {field}")
        })?;
    }
    tally.check(
        !((evidence.expected.new_claim_at_or_after_expiry == "reject")
            == expected_bool(lifecycle, "new_claim_returns_old_package")?),
        || "expiry claim verdict disagrees with its crypto evidence block".to_owned(),
    )?;
    tally.check(
        !(evidence
            .expected
            .matching_private_key_recovers_captured_group_secrets
            != expected_bool(
                lifecycle,
                "captured_welcome_decryptable_with_matching_private_key",
            )?),
        || "captured-Welcome recovery verdict disagrees with its crypto evidence block".to_owned(),
    )?;
    tally.check(
        !(evidence.expected.expiry_revokes_historical_decryption
            || evidence.expected.historical_confidentiality_restored),
        || {
            "expiry security evidence claims retrospective secrecy the protocol does not provide"
                .to_owned()
        },
    )?;
    tally.check(
        !(evidence.expected.future_epoch_recovery.trim().is_empty()),
        || "expiry security evidence must state the future-epoch condition".to_owned(),
    )?;

    // The half cotest owns: at `compromise_day` the package is past its own
    // `expires_day`, so it leaves the distributable pool with the registered
    // expiry reason and a new claim cannot return it.
    let day = |offset: u64| -> Result<DateTime<Utc>> {
        Ok(parse_time("2026-01-01T00:00:00.000Z")? + Duration::days(i64::try_from(offset)?))
    };
    let realm = realm("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1")?;
    let mut pool = vec![MiniKeypackage::new_last_resort(
        "ak:keypackage:expiring-last-resort",
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        core_did("ak:did_core:web:alice.example")?,
        verification_method(
            "did:web:alice.example#ak:device:0196419b-0000-7000-8000-000000000001",
        )?,
        device("ak:device:0196419b-0000-7000-8000-000000000001")?,
        realm.clone(),
        day(evidence.expires_day)?,
    )];
    let welcome_claim = parse_claim_outcome(claim_from_pool(
        &mut pool,
        &realm,
        "ak:keypackage_claim:0199c001-0000-7000-8000-000000000003",
        true,
        true,
    )?)?;
    tally.check(welcome_claim.claims.len() == 1, || {
        "last-resort package was not claimable before its own expiry".to_owned()
    })?;
    // The Welcome the attacker captures is sealed against this consumption, at
    // `welcome_day` — well before expiry. Claiming alone would leave the audit
    // trail empty and make the invariant below vacuous.
    if pool[0].consume(
        "ak:keypackage_claim:0199c001-0000-7000-8000-000000000003",
        &realm,
        day(evidence.welcome_day)?,
    )? != MiniConsumeDecision::Consumed("ak:keypackage:expiring-last-resort".to_owned())
    {
        bail!("last-resort package was not usable before its own expiry");
    }
    let reason = pool[0]
        .expire(day(evidence.compromise_day)?)
        .ok_or_else(|| anyhow!("package past its expires_day did not expire"))?;
    tally.check(
        !(reason != arkret_wire::ReasonCode::KEYPACKAGE_EXPIRED
            || reason != expected_str(lifecycle, "revocation_reason")?),
        || "expired last-resort package did not carry the registered expiry reason".to_owned(),
    )?;
    tally.check(
        pool[0].state.as_str() == expected_str(lifecycle, "state_after_expiry")?,
        || "expired last-resort package did not reach the declared state".to_owned(),
    )?;
    assert_claim_failed(&claim_from_pool(
        &mut pool,
        &realm,
        "ak:keypackage_claim:0199c001-0000-7000-8000-000000000004",
        true,
        true,
    )?)?;
    // Expiry revoked the distributable package without touching the audit
    // record the pre-expiry claim produced: the captured Welcome keeps whatever
    // confidentiality it already had, no more and no less.
    tally.check(pool[0].audit_records.len() == 1, || {
        "expiry rewrote the pre-expiry claim audit history".to_owned()
    })?;
    Ok(())
}

fn last_resort_affinity_and_optionality_case(vector: &Value, tally: &mut Tally) -> Result<()> {
    tally.check(
        required_str(vector, "feature")? == LAST_RESORT_FEATURE,
        || "last-resort feature id drifted".to_owned(),
    )?;
    let principal = core_did("ak:did_core:web:alice.example")?;
    let signer = verification_method(
        "did:web:alice.example#ak:device:0196419b-0000-7000-8000-000000000001",
    )?;
    let device = device("ak:device:0196419b-0000-7000-8000-000000000001")?;
    let r1 = realm(required_str(vector, "realm_r1")?)?;
    let r2 = realm(required_str(vector, "realm_r2")?)?;
    let expires_at = parse_time("2100-01-01T00:00:00.000Z")?;
    let mut package = MiniKeypackage::new_last_resort(
        required_str(vector, "last_resort_keypackage_ref")?,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        principal.clone(),
        signer.clone(),
        device.clone(),
        r1.clone(),
        expires_at,
    );
    let cross_realm = package.consume(
        "ak:keypackage_claim:0199c001-0000-7000-8000-000000000005",
        &r2,
        expires_at,
    )?;
    tally.check(
        !(cross_realm
            != MiniConsumeDecision::Rejected(
                expected_str(vector, "cross_realm_reason")?.to_owned(),
            )),
        || "cross-Realm last-resort reuse did not fail with affinity violation".to_owned(),
    )?;

    let unsupported = claim_from_pool(
        &mut [],
        &r1,
        "ak:keypackage_claim:0199c001-0000-7000-8000-000000000006",
        false,
        true,
    )?;
    assert_claim_failed(&unsupported)?;
    let _internal_unsupported_reason = expected_str(vector, "unsupported_reason")?;

    let mut r1_only_pool = vec![MiniKeypackage::new_last_resort(
        required_str(vector, "last_resort_keypackage_ref")?,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        principal,
        signer,
        device,
        r1,
        expires_at,
    )];
    let missing_r2 = claim_from_pool(
        &mut r1_only_pool,
        &r2,
        "ak:keypackage_claim:0199c001-0000-7000-8000-000000000007",
        true,
        true,
    )?;
    assert_claim_failed(&missing_r2)?;
    let _internal_missing_reason = expected_str(vector, "no_cross_realm_fallback_reason")?;
    tally.check(
        expected_bool(vector, "claim_realm_matches_intended_realm")?,
        || "claim Realm affinity requirement drifted".to_owned(),
    )?;
    Ok(())
}

/// Welcome is a recipient-private signed delivery, never an Event payload.
fn welcome_keypackage_hash_case(
    fixture: &KeypackageLifecycleFixture,
    vector: &Value,
    tally: &mut Tally,
) -> Result<()> {
    let claim_id = required_str(vector, "claim_id")?;
    let digest = required_str(vector, "keypackage_digest")?;
    let mismatched_digest = required_str(vector, "mismatched_keypackage_digest")?;
    let delivery_value = fixture
        .schema_validation_cases
        .iter()
        .find(|row| row.get("name").and_then(Value::as_str) == Some("mls_welcome_delivery_valid"))
        .and_then(|row| row.get("instance"))
        .cloned()
        .ok_or_else(|| anyhow!("fixture omits the canonical MLS Welcome delivery"))?;
    schema_valid(MLS_WELCOME_DELIVERY_SCHEMA, &delivery_value)?;
    let delivery: MlsWelcomeDelivery = serde_json::from_value(delivery_value.clone())?;
    delivery.validate_shape()?;
    tally.check(
        delivery.keypackage_claim_ref.as_str() == required_str(vector, "keypackage_claim_ref")?,
        || "Welcome delivery does not bind the fixture's exact claim reference".to_owned(),
    )?;

    let claim_record = claim_record_value(ClaimRecordInput {
        claim_id,
        keypackage_ref: required_str(vector, "keypackage_ref")?,
        principal_id: &core_did("ak:did_core:web:alice.example")?,
        device_id: &device("ak:device:0196419b-0000-7000-8000-000000000001")?,
        device_authorize_event_id: required_str(vector, "device_authorization_event_id")?,
        last_resort: false,
        expires_at: parse_time("2100-01-01T00:00:00.000Z")?,
    });
    let claim_outcome = parse_claim_outcome(claim_outcome_value(claim_record))?;
    let claim = claim_outcome
        .claims
        .first()
        .ok_or_else(|| anyhow!("claim outcome missing record"))?;
    let keypackage_bytes =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(claim.keypackage.as_bytes())?;
    let recomputed = format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(&keypackage_bytes))
    );
    tally.check(
        !(recomputed != digest || recomputed == mismatched_digest),
        || "fixture KeyPackage digest does not match claimed bytes".to_owned(),
    )?;
    tally.check(
        !(claim.claim_id != claim_id
            || claim.keypackage_ref != required_str(vector, "keypackage_ref")?),
        || "Welcome claim ledger reference is inconsistent".to_owned(),
    )?;

    let queue_value = json!({"delivery_kind": "mls_welcome", "mls_welcome": delivery_value});
    let queued: RecipientDelivery = serde_json::from_value(queue_value.clone())?;
    tally.check(
        matches!(queued, RecipientDelivery::MlsWelcome { mls_welcome } if mls_welcome == delivery),
        || "recipient delivery queue changed the signed Welcome object".to_owned(),
    )?;
    for retired_field in [
        "claim_ref",
        "claim_envelope",
        "claim_receipt",
        "ciphertext",
        "expires_at",
    ] {
        let mut invalid = delivery_value.clone();
        invalid[retired_field] = json!("retired");
        schema_invalid(MLS_WELCOME_DELIVERY_SCHEMA, &invalid)?;
        tally.check(
            !(serde_json::from_value::<MlsWelcomeDelivery>(invalid).is_ok()),
            || format!("retired Welcome member was accepted: {retired_field}"),
        )?;
    }
    for invalid_ciphertext in ["AA==", "AB", "A"] {
        let mut invalid = delivery_value.clone();
        invalid["ciphertext_b64"] = json!(invalid_ciphertext);
        if invalid_ciphertext == "AA==" {
            schema_invalid(MLS_WELCOME_DELIVERY_SCHEMA, &invalid)?;
        }
        let rejected = match serde_json::from_value::<MlsWelcomeDelivery>(invalid) {
            Ok(delivery) => delivery.validate_shape().is_err(),
            Err(_) => true,
        };
        tally.check(rejected, || {
            format!("noncanonical Welcome ciphertext was accepted: {invalid_ciphertext}")
        })?;
    }
    let mut wrong_context = delivery_value.clone();
    wrong_context["producer_proof"]["context"] = json!("ak.realm_commit_signature.v1");
    schema_invalid(MLS_WELCOME_DELIVERY_SCHEMA, &wrong_context)?;
    let mut wrong_scope = delivery_value.clone();
    wrong_scope["realm_id"] = json!("ak:realm:AYmzq24KUdbYXjZtMiyVdibogezW-fCFD3oy0iviR-UD");
    schema_valid(MLS_WELCOME_DELIVERY_SCHEMA, &wrong_scope)?;
    serde_json::from_value::<MlsWelcomeDelivery>(wrong_scope)?
        .validate_shape()
        .expect_err("cross-Realm scope must be rejected");
    let mut wrong_branch = queue_value;
    wrong_branch["delivery_kind"] = json!("device_message");
    tally.check(
        !(serde_json::from_value::<RecipientDelivery>(wrong_branch).is_ok()),
        || "Welcome parsed as a DeviceMessage queue branch".to_owned(),
    )?;
    tally.check(expected_bool(vector, "reject_before_decrypt")?, || {
        "Welcome vector must reject mismatched claim ledger before decrypt".to_owned()
    })?;
    Ok(())
}

/// Exact runner for `ak.vector.keypackage.self_claim_authorization_idempotency.v1`.
fn self_claim_authorization_idempotency_case(
    fixture: &KeypackageLifecycleFixture,
    vector: &Value,
    tally: &mut Tally,
) -> Result<()> {
    validate_unsigned_selector_transcripts(fixture, tally)?;
    let requester_device_id = required_str(vector, "requester_device_id")?;
    let device_authorization_event_id = required_str(vector, "device_authorization_event_id")?;
    let expected_verification_method =
        required_str(vector, "requester_verification_method")?.to_owned();
    let expected_verification_method_typed = verification_method(&expected_verification_method)?;
    tally.check(
        !(expected_verification_method_typed
            .as_str()
            .rsplit_once('#')
            .map(|(_, fragment)| fragment)
            != Some(requester_device_id)),
        || "self-claim verification method does not name requester_device_id".to_owned(),
    )?;
    device(requester_device_id)?;
    arkret_wire::EventId::new(device_authorization_event_id.to_owned())?;
    require_model_generation_ref(vector, "model_generation_ref")?;

    let request = fixture
        .schema_validation_cases
        .iter()
        .find(|case| {
            case.get("name").and_then(Value::as_str)
                == Some("local_and_remote_claim_share_closed_authorization_carrier")
        })
        .and_then(|case| case.get("instance"))
        .cloned()
        .ok_or_else(|| anyhow!("fixture omits the canonical unified claim request"))?;
    let typed: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(request.clone())?;
    typed.validate_shape()?;
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
        verification_method,
        requester_device_id: authorized_device_id,
        device_authorize_event_id: authorized_event_id,
        ..
    } = &typed.requester_authorization
    else {
        bail!("self-claim fixture must use the closed device authorization branch");
    };
    tally.check(
        !(verification_method != &expected_verification_method_typed
            || authorized_device_id.as_str() != requester_device_id
            || authorized_event_id.as_str() != device_authorization_event_id),
        || "self-claim authorization is not bound to the accepted device selector".to_owned(),
    )?;
    tally.check(
        !(serde_json::to_value(typed.unsigned_request())? != vector["unsigned_request"]
            || serde_json::to_value(&typed.service_binding)? != vector["service_binding"]),
        || "unified claim request drifted from its unsigned request or service binding".to_owned(),
    )?;
    let binding = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &typed.unsigned_request(),
        &typed.service_binding,
        &typed.requester_authorization,
    )?;
    tally.check(
        binding.starts_with(b"ak.keypackage-claim-authorization-v1\n"),
        || "self-claim authorization uses the wrong signing domain".to_owned(),
    )?;
    let request_digest = arkret_canonical::canonical_sha256(&serde_json::to_value(&typed)?)?;

    let identity = (
        typed.service_binding.source_id.as_str().to_owned(),
        typed.claim_request_id.as_str().to_owned(),
    );
    let outcome = arkret_canonical::canonical_json_bytes(&claim_outcome_value(json!({
        "claim_id": "fixture",
        "device_id": requester_device_id
    })))?;
    let mut ledger = BTreeMap::new();
    ledger.insert(identity.clone(), (request_digest.clone(), outcome.clone()));
    let replay = ledger.get(&identity).expect("inserted terminal outcome");
    tally.check(!(replay.0 != request_digest || replay.1 != outcome), || {
        "exact retry did not return the byte-identical terminal outcome".to_owned()
    })?;
    let mut conflict = request;
    conflict["target_account_id"]["principal_id"] =
        json!("ak:did_core:webvh:z6mkfixturemalloryexample");
    let conflict: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(conflict)?;
    let conflict_digest = arkret_canonical::canonical_sha256(&serde_json::to_value(&conflict)?)?;
    tally.check(conflict_digest != replay.0, || {
        "same requester/claim_request_id with a changed payload did not conflict".to_owned()
    })?;
    let conflict_binding = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &conflict.unsigned_request(),
        &conflict.service_binding,
        &conflict.requester_authorization,
    )?;
    tally.check(conflict_binding != binding, || {
        "claim authorization transcript did not bind the changed target".to_owned()
    })?;

    let mut next_attempt = serde_json::to_value(&typed)?;
    next_attempt["claim_request_id"] = json!("AAAAAAAAAAAAAAAAAAAAAg");
    let next_attempt: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(next_attempt)?;
    next_attempt.validate_shape()?;
    let next_identity = (
        next_attempt.service_binding.source_id.as_str().to_owned(),
        next_attempt.claim_request_id.as_str().to_owned(),
    );
    tally.check(
        !(next_identity == identity || ledger.contains_key(&next_identity)),
        || "a new claim attempt reused the prior claim_request_id ledger identity".to_owned(),
    )?;

    let mut missing = serde_json::to_value(&typed)?;
    missing
        .as_object_mut()
        .expect("request object")
        .remove("requester_authorization");
    tally.check(
        !(serde_json::from_value::<arkret_models_crypto::KeyPackagesClaimRequestBody>(missing)
            .is_ok()),
        || "a self claim without requester authorization was accepted".to_owned(),
    )?;
    let mut wrong_branch = serde_json::to_value(&typed)?;
    wrong_branch["requester_authorization"]["signature"]["kid"] =
        json!("did:webvh:z6mkfixture:alice.example#other-key");
    let wrong_branch: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(wrong_branch)?;
    tally.check(!(wrong_branch.validate_shape().is_ok()), || {
        "a requester authorization whose signature key differs from its method was accepted"
            .to_owned()
    })?;
    Ok(())
}

fn validate_unsigned_selector_transcripts(
    fixture: &KeypackageLifecycleFixture,
    tally: &mut Tally,
) -> Result<()> {
    let rows = &fixture.unsigned_selector_transcripts;
    tally.check(rows.len() == 2, || {
        "unsigned selector transcript fixture must cover exactly the device and agent branches"
            .to_owned()
    })?;

    let mut seen = BTreeSet::new();
    for row in rows {
        let branch = required_str(row, "branch")?;
        let request_value = row
            .get("unsigned_request")
            .cloned()
            .ok_or_else(|| anyhow!("{branch} omits unsigned_request"))?;
        let request: arkret_models_crypto::PeerKeyPackagesClaimUnsignedRequest =
            serde_json::from_value(request_value.clone())?;
        let exact_branch = match branch {
            "device" => {
                !request.target_device_ids.is_empty()
                    && request.target_agent_id.is_none()
                    && request.target_agent_verification_method.is_none()
                    && request.target_agent_key_authorize_event_id.is_none()
                    && request.target_pairwise_verification_method.is_none()
            }
            "agent" => {
                request.target_device_ids.is_empty()
                    && request.target_agent_id.is_some()
                    && request.target_agent_verification_method.is_some()
                    && request.target_agent_key_authorize_event_id.is_some()
                    && request.target_pairwise_verification_method.is_none()
            }
            other => bail!("unknown unsigned selector transcript branch {other}"),
        };
        tally.check(!(!exact_branch || !seen.insert(branch)), || {
            format!("{branch} does not preserve one exact selector branch")
        })?;

        let canonical = arkret_canonical::canonical_json_string(&request_value)?;
        let digest = arkret_canonical::canonical_sha256(&request_value)?;
        tally.check(
            !(canonical != required_str(row, "canonical_jcs")?
                || digest != required_str(row, "request_digest")?),
            || format!("{branch} unsigned request transcript drifted"),
        )?;

        let mut changed = request_value.clone();
        match branch {
            "device" => {
                changed["target_device_ids"][0] =
                    json!("ak:device:0196419b-0000-7000-8000-000000000099");
            }
            "agent" => {
                changed["target_agent_key_authorize_event_id"] =
                    json!("ak:event:Aao964Xuq1Q7PmnLt9I97ih00Qs2N6qMkBgKgYCvUFFe");
            }
            _ => unreachable!(),
        }
        tally.check(
            arkret_canonical::canonical_sha256(&changed)? != digest,
            || format!("{branch} selector mutation did not change the idempotency digest"),
        )?;
    }
    tally.check(seen == BTreeSet::from(["device", "agent"]), || {
        "unsigned selector transcript branch set is incomplete".to_owned()
    })?;
    Ok(())
}

pub fn run_keypackage_exhaustion_claim_limits_vector() -> Result<()> {
    run_single_case("exhaustion_claim_limits", |_, case, tally| {
        exhaustion_claim_limits_case(case, tally)
    })
}

pub fn run_keypackage_last_resort_claim_and_reuse_vector() -> Result<()> {
    run_single_case("last_resort_claim_and_reuse", |_, case, tally| {
        last_resort_claim_and_reuse_case(case, tally)
    })
}

pub fn run_keypackage_last_resort_forced_rotation_vector() -> Result<()> {
    run_single_case("last_resort_forced_rotation", |_, case, tally| {
        last_resort_forced_rotation_case(case, tally)
    })?;
    run_single_case(EXPIRY_SECURITY_CASE_NAME, last_resort_expiry_security_case)
}

pub fn run_keypackage_last_resort_affinity_and_optionality_vector() -> Result<()> {
    run_single_case("last_resort_affinity_and_optionality", |_, case, tally| {
        last_resort_affinity_and_optionality_case(case, tally)
    })
}

pub fn run_mls_welcome_keypackage_hash_vector() -> Result<()> {
    run_single_case("welcome_keypackage_hash", welcome_keypackage_hash_case)
}

pub fn run_keypackage_self_claim_authorization_idempotency_vector() -> Result<()> {
    run_single_case(
        "self_claim_authorization_idempotency",
        self_claim_authorization_idempotency_case,
    )
}

/// Every fixture case through the named suite.
pub fn run_keypackage_lifecycle_fixture_suite() -> Result<()> {
    let execution = run_keypackage_lifecycle_suite()?;
    execution.assert_complete_against(&load_fixture_value_for_suite()?)
}

fn load_fixture_value_for_suite() -> Result<Value> {
    super::load_fixture_value(KEYPACKAGE_LIFECYCLE_FIXTURE_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypackage_lifecycle_vectors_run_clean() {
        run_keypackage_lifecycle_fixture_suite().unwrap();
    }
}
