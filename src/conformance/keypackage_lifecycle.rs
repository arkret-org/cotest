//! MLS KeyPackage lifecycle conformance vectors.
//!
//! Covers single-use claim limits, last-resort KeyPackage semantics, and MLS
//! Welcome digest binding against the spec artifact fixture.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, anyhow, bail};
use arkret_identifiers::{DeviceId, DidCoreId, DidFullId, Hash, RealmId};
use arkret_models_collaboration::events_payloads::{
    MlsKeypackagePayload, MlsWelcomePayload, MlsWelcomeRecipient,
    validate_mls_welcome_claim_envelope,
};
use arkret_models_crypto::{KeyPackagesClaimOutcome, KeyPackagesUploadOutcome};
use arkret_wire::{DidUrl, ProfileId};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::schema_validation_fixture::SchemaEnv;

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
pub const VECTOR_ID_KEYPACKAGE_MINIMAL_METADATA_PAIRWISE_FULL_LIFECYCLE: &str =
    "ak.vector.keypackage.minimal_metadata_pairwise_full_lifecycle.v1";

pub const ALL_KEYPACKAGE_LIFECYCLE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_KEYPACKAGE_EXHAUSTION_CLAIM_LIMITS,
    VECTOR_ID_KEYPACKAGE_LAST_RESORT_CLAIM_AND_REUSE,
    VECTOR_ID_KEYPACKAGE_LAST_RESORT_FORCED_ROTATION,
    VECTOR_ID_KEYPACKAGE_LAST_RESORT_AFFINITY_AND_OPTIONALITY,
    VECTOR_ID_KEYPACKAGE_SELF_CLAIM_AUTHORIZATION_IDEMPOTENCY,
    VECTOR_ID_KEYPACKAGE_MINIMAL_METADATA_PAIRWISE_FULL_LIFECYCLE,
    VECTOR_ID_MLS_WELCOME_KEYPACKAGE_HASH,
];

const KEYPACKAGE_LIFECYCLE_FIXTURE_FILE: &str = "keypackage-lifecycle-fixture.json";
const KEY_PACKAGES_UPLOAD_OUTCOME_SCHEMA: &str =
    "schemas/keypackage-operations.schema.json#/$defs/keypackages_upload_outcome";
const KEY_PACKAGES_CLAIM_OUTCOME_SCHEMA: &str =
    "schemas/keypackage-operations.schema.json#/$defs/keypackages_claim_outcome";
const MLS_WELCOME_PAYLOAD_SCHEMA: &str =
    "schemas/event-payload.schema.json#/$defs/mls_welcome_payload";
const MLS_KEYPACKAGE_PAYLOAD_SCHEMA: &str =
    "schemas/event-payload.schema.json#/$defs/mls_keypackage_payload";
const LAST_RESORT_FEATURE: &str = "ak.feature.mls_last_resort_keypackage.v1";

fn keypackage_fixture() -> Result<Value> {
    let fixture = super::load_fixture_value(KEYPACKAGE_LIFECYCLE_FIXTURE_FILE)?;
    super::validate_profile(&fixture, ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1)?;
    validate_keypackage_lifecycle_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_keypackage_lifecycle_fixture_metadata(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some("keypackage_lifecycle") {
        bail!("keypackage lifecycle fixture suite drifted");
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("keypackage lifecycle fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("keypackage lifecycle fixture missing cases[]"))?;

    for vector_id in ALL_KEYPACKAGE_LIFECYCLE_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
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
        arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE,
        arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM,
        arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME,
        arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE,
    ] {
        if !op.starts_with("ak.self.keys.keypackages.") {
            bail!("keypackage operation id namespace drifted: {op}");
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
        .ok_or_else(|| anyhow!("keypackage lifecycle fixture missing case {vector_id}"))
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

fn expected_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .pointer(&format!("/expected/{field}"))
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("case missing u64 expected.{field}"))
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

fn full_did(value: &str) -> Result<DidFullId> {
    DidFullId::new(value.to_owned()).map_err(Into::into)
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

fn schema_valid(schema_ref: &str, value: &Value) -> Result<()> {
    let env = SchemaEnv::load()?;
    let validator = env.compile(schema_ref)?;
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

fn schema_invalid(schema_ref: &str, value: &Value) -> Result<()> {
    let env = SchemaEnv::load()?;
    let validator = env.compile(schema_ref)?;
    if validator.is_valid(value) {
        bail!("value unexpectedly passed schema {schema_ref}");
    }
    Ok(())
}

struct ClaimRecordInput<'a> {
    claim_id: &'a str,
    keypackage_ref: &'a str,
    principal_id: &'a DidCoreId,
    device_id: &'a DeviceId,
    last_resort: bool,
    expires_at: DateTime<Utc>,
}

fn claim_record_value(input: ClaimRecordInput<'_>) -> Value {
    let ClaimRecordInput {
        claim_id,
        keypackage_ref,
        principal_id,
        device_id,
        last_resort,
        expires_at,
    } = input;
    let mut value = json!({
        "claim_id": claim_id,
        "keypackage_ref": keypackage_ref,
        "principal_id": principal_id.as_str(),
        "device_id": device_id.as_str(),
        "keypackage": "AQID",
        "capabilities": ["ak.content.v1"],
        "device_authorize_event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
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
        "target_principal_id": "ak:did_core:webvh:z6mkfixture",
        "intended_realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "requester": "ak:did_core:webvh:z6mkfixture",
        "mls_group_id": "fixture-group",
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
        "source_service_id": "ak:did_core:webvh:z6mkfixtureservice",
        "destination_service_id": "ak:did_core:webvh:z6mkfixtureservice",
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
    Retired,
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
            Self::Retired => "retired",
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
            (
                _,
                MiniKeypackageState::Revoked
                | MiniKeypackageState::Retired
                | MiniKeypackageState::Consumed,
            ) => Ok(MiniConsumeDecision::Rejected(
                arkret_wire::ErrorCode::KEYPACKAGE_UNKNOWN.to_owned(),
            )),
            (false, MiniKeypackageState::Published) => Ok(MiniConsumeDecision::Rejected(
                arkret_wire::ErrorCode::KEYPACKAGE_UNKNOWN.to_owned(),
            )),
        }
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

pub fn run_keypackage_exhaustion_claim_limits_vector() -> Result<()> {
    let fixture = keypackage_fixture()?;
    let vector = case(&fixture, VECTOR_ID_KEYPACKAGE_EXHAUSTION_CLAIM_LIMITS)?;
    let min_available = vector
        .get("keypackage_min_available")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("exhaustion vector missing keypackage_min_available"))?;
    let local_usable_count = vector
        .get("local_usable_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("exhaustion vector missing local_usable_count"))?;
    if local_usable_count >= min_available {
        bail!("exhaustion vector must start below keypackage_min_available");
    }
    let refill_count = min_available - local_usable_count;
    if vector
        .pointer("/expected/bounded_refill_count")
        .and_then(Value::as_u64)
        != Some(refill_count)
    {
        bail!("local KeyPackage refill must equal the startup deficit");
    }

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
    if attempt <= limit {
        bail!("rate-limit control must exceed the allowed claim count");
    }
    let rate_limited = claim_failure_outcome_value();
    assert_claim_failed(&rate_limited)?;
    if expected_str(vector, "rate_limit_audit_reason")? != "keypackage_claim_rate_limited" {
        bail!("keypackage claim rate-limit audit reason drifted");
    }
    if expected_str(vector, "rate_limit_external_failure")? != "anti_enumeration" {
        bail!("rate-limit external failure semantics drifted");
    }

    let principal = core_did(required_str(vector, "target_principal_id")?)?;
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
    if package.state.as_str() != expected_str(vector, "expired_status")? {
        bail!("expired claimed keypackage did not become revoked");
    }
    if consume
        != MiniConsumeDecision::Rejected(
            expected_str(vector, "expired_external_reason")?.to_owned(),
        )
    {
        bail!("expired keypackage consume did not reject with expected reason");
    }
    validate_wire_state_cases(vector)?;
    Ok(())
}

fn validate_wire_state_cases(vector: &Value) -> Result<()> {
    let cases = vector
        .get("wire_state_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("keypackage vector missing wire_state_cases[]"))?;
    let mut seen = BTreeSet::new();
    for case in cases {
        let from = required_str(case, "from")?;
        let to = required_str(case, "to")?;
        if !seen.insert((from, to)) {
            bail!("duplicate keypackage wire transition {from}->{to}");
        }
        if from != "published" {
            bail!("wire-state fixture currently requires a published source state");
        }
        if to == "retired" && MiniKeypackageState::Retired.as_str() != to {
            bail!("mini lifecycle model does not expose the retired wire state");
        }
        let mut payload = keypackage_payload_value(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );
        payload["state"] = json!(to);
        let accepted = schema_valid(MLS_KEYPACKAGE_PAYLOAD_SCHEMA, &payload).is_ok()
            && serde_json::from_value::<MlsKeypackagePayload>(payload).is_ok();
        let expected = required_str(case, "expected")?;
        if accepted != (expected == "accepted") {
            bail!(
                "keypackage wire transition {from}->{to} produced {}, expected {expected}",
                if accepted {
                    "accepted"
                } else {
                    "schema_violation"
                },
            );
        }
    }
    if !seen.contains(&("published", "retired")) || !seen.contains(&("published", "expired")) {
        bail!("keypackage wire-state cases must cover retired acceptance and expired rejection");
    }
    Ok(())
}

pub fn run_keypackage_last_resort_claim_and_reuse_vector() -> Result<()> {
    let fixture = keypackage_fixture()?;
    let vector = case(&fixture, VECTOR_ID_KEYPACKAGE_LAST_RESORT_CLAIM_AND_REUSE)?;
    if required_str(vector, "feature")? != LAST_RESORT_FEATURE {
        bail!("last-resort feature id drifted");
    }
    let principal = core_did(required_str(vector, "target_principal_id")?)?;
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
        "mls-keypackage-claim-normal-1",
        true,
        false,
    )?)?;
    if expected_bool(vector, "normal_preferred_when_available")?
        && normal_claim.claims[0].keypackage_ref != required_str(vector, "normal_keypackage_ref")?
    {
        bail!("single-use package was not preferred while available");
    }

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
    if last_resort_claim.claims[0].keypackage_ref
        != required_str(vector, "last_resort_keypackage_ref")?
        || last_resort_claim.claims[0].last_resort != Some(true)
    {
        bail!("empty single-use pool did not return last_resort=true claim record");
    }

    let last_resort = pool
        .iter_mut()
        .find(|package| package.last_resort)
        .ok_or_else(|| anyhow!("last-resort package missing"))?;
    for claim_id in claim_ids {
        let claim_id = claim_id
            .as_str()
            .ok_or_else(|| anyhow!("last-resort claim id must be string"))?;
        let consume = last_resort.consume(claim_id, &realm, expires_at)?;
        if consume != MiniConsumeDecision::Consumed(last_resort.keypackage_ref.clone()) {
            bail!("last-resort consume did not return idempotent success");
        }
    }
    if last_resort.state.as_str() != expected_str(vector, "state_after_consume")? {
        bail!("last-resort consume changed package state");
    }
    if expected_bool(vector, "last_resort_consume_idempotent")?
        && last_resort
            .audit_records
            .iter()
            .any(|record| !record.last_resort)
    {
        bail!("last-resort audit record lost last_resort=true marker");
    }
    if last_resort.audit_records.len() as u64 != expected_u64(vector, "audit_records")? {
        bail!("last-resort consume audit record count drifted");
    }
    if expected_str(vector, "forbidden_reason")?
        != arkret_wire::ErrorCode::KEYPACKAGE_ALREADY_CONSUMED
    {
        bail!("last-resort forbidden reason constant drifted");
    }
    Ok(())
}

pub fn run_keypackage_last_resort_forced_rotation_vector() -> Result<()> {
    let fixture = keypackage_fixture()?;
    let vector = case(&fixture, VECTOR_ID_KEYPACKAGE_LAST_RESORT_FORCED_ROTATION)?;
    if required_str(vector, "feature")? != LAST_RESORT_FEATURE {
        bail!("last-resort feature id drifted");
    }
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
    if old.state.as_str() != expected_str(vector, "old_state")? {
        bail!("old last-resort package was not revoked after rotation");
    }
    if commits.len() as u64 != expected_u64(vector, "self_update_commits")? {
        bail!("rotation did not emit one MLS self-update per joined group");
    }
    if expected_str(vector, "rotation_reason")?
        != arkret_wire::ReasonCode::LAST_RESORT_ROTATION_REQUIRED
    {
        bail!("last-resort rotation reason drifted");
    }

    let claim = parse_claim_outcome(claim_from_pool(
        &mut pool,
        &realm,
        "mls-keypackage-claim-after-rotation",
        true,
        true,
    )?)?;
    if expected_bool(vector, "old_not_distributed_after_rotation")?
        && claim.claims[0].keypackage_ref != required_str(vector, "new_last_resort_keypackage_ref")?
    {
        bail!("rotated old last-resort package was still distributed");
    }
    let new = pool
        .iter()
        .find(|package| {
            package.keypackage_ref
                == required_str(vector, "new_last_resort_keypackage_ref").unwrap()
        })
        .ok_or_else(|| anyhow!("new package missing after rotation"))?;
    if new.state.as_str() != expected_str(vector, "new_state")? {
        bail!("replacement last-resort package is not published");
    }
    Ok(())
}

pub fn run_keypackage_last_resort_affinity_and_optionality_vector() -> Result<()> {
    let fixture = keypackage_fixture()?;
    let vector = case(
        &fixture,
        VECTOR_ID_KEYPACKAGE_LAST_RESORT_AFFINITY_AND_OPTIONALITY,
    )?;
    if required_str(vector, "feature")? != LAST_RESORT_FEATURE {
        bail!("last-resort feature id drifted");
    }
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
    let cross_realm = package.consume("mls-keypackage-claim-x", &r2, expires_at)?;
    if cross_realm
        != MiniConsumeDecision::Rejected(expected_str(vector, "cross_realm_reason")?.to_owned())
    {
        bail!("cross-Realm last-resort reuse did not fail with affinity violation");
    }

    let unsupported = claim_from_pool(
        &mut [],
        &r1,
        "mls-keypackage-claim-unsupported",
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
        "mls-keypackage-claim-r2-missing",
        true,
        true,
    )?;
    assert_claim_failed(&missing_r2)?;
    let _internal_missing_reason = expected_str(vector, "no_cross_realm_fallback_reason")?;
    if !expected_bool(vector, "claim_realm_matches_intended_realm")? {
        bail!("claim Realm affinity requirement drifted");
    }
    Ok(())
}

fn keypackage_payload_value(keypackage_ref: &str, keypackage_digest: &str) -> Value {
    json!({
        "keypackage_id": "ak:mls:kp:0196419b-0000-7000-8000-000000000001",
        "principal_id": "ak:did_core:web:alice.example",
        "device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
        "device_authorize_event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": keypackage_digest,
        "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
        "capabilities": ["ak.content.v1"],
        "state": "published",
        "expires_at": "2100-01-01T00:00:00.000Z",
        "created_at": "2026-06-19T00:00:00.000Z"
    })
}

#[derive(Clone, Copy)]
struct WelcomePayloadFixture<'a> {
    keypackage_ref: &'a str,
    claim_digest: &'a str,
    envelope_digest: &'a str,
    capabilities_digest: &'a str,
    claim_id: &'a str,
    device_authorize_event_id: &'a str,
    requester_device_id: &'a str,
    intended_realm_id: &'a str,
    requester_actor_id: &'a str,
    requester_verification_method: &'a str,
    claim_receipt: &'a Value,
    welcome_digest: &'a str,
}

fn welcome_payload_value(fixture: WelcomePayloadFixture<'_>) -> Value {
    json!({
        "mls_group_id": "mls-group-a",
        "epoch": 1,
        "recipient_principal_id": "ak:did_core:web:alice.example",
        "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
        "keypackage_ref": fixture.keypackage_ref,
        "claim_id": fixture.claim_id,
        "claim_ref": {
            "claim_id": fixture.claim_id,
            "keypackage_ref": fixture.keypackage_ref,
            "keypackage_digest": fixture.claim_digest,
            "capabilities_digest": fixture.capabilities_digest,
            "device_authorize_event_id": fixture.device_authorize_event_id
        },
        "claim_envelope": {
            "keypackage_ref": fixture.keypackage_ref,
            "keypackage_digest": fixture.envelope_digest,
            "intended_realm_id": fixture.intended_realm_id,
            "claim_id": fixture.claim_id,
            "requester_actor_id": fixture.requester_actor_id,
            "requester_device_id": fixture.requester_device_id,
            "requester_device_authorize_event_id": fixture.device_authorize_event_id,
            "welcome_digest": fixture.welcome_digest,
            "created_at": "2026-05-25T00:00:00.000Z",
            "signature": {
                "kid": fixture.requester_verification_method,
                "signature_algorithm": "Ed25519",
                "sig": "c2ln"
            }
        },
        "claim_receipt": fixture.claim_receipt,
        "commit_ref": "ak:event:AR8j96rkirO3GDtvwgRddZScc5YX1AgFEOGO5Bs1wrgC",
        "governance_binding": {
            "binding_version": 1,
            "encoding_profile": "cbor-deterministic-rfc8949-v1",
            "realm_id": fixture.intended_realm_id,
            "effective_scope": {
                "kind": "realm",
                "realm_id": fixture.intended_realm_id
            },
            "mls_group_id": "mls-group-a",
            "previous_epoch": 0,
            "next_epoch": 1,
            "security_frontier_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "content_scheme": "mls_rfc9420",
            "binding_profile": "ak.profile.mls_governance_binding.full.v1",
            "reducer_profile": "ak.reducer.core.v1"
        },
        "ciphertext": "AQID",
        "expires_at": "2100-01-01T00:00:00.000Z"
    })
}

pub fn run_mls_welcome_keypackage_hash_vector() -> Result<()> {
    let fixture = keypackage_fixture()?;
    let vector = case(&fixture, VECTOR_ID_MLS_WELCOME_KEYPACKAGE_HASH)?;
    let keypackage_ref = required_str(vector, "keypackage_ref")?;
    let digest = required_str(vector, "keypackage_digest")?;
    let mismatched_digest = required_str(vector, "mismatched_keypackage_digest")?;
    let capabilities_digest = required_str(vector, "capabilities_digest")?;
    let claim_id = required_str(vector, "claim_id")?;
    let intended_realm_id = required_str(vector, "intended_realm_id")?;
    let requester_actor_id = required_str(vector, "requester_actor_id")?;
    let requester_verification_method = required_str(vector, "requester_verification_method")?;
    let claim_request_id = required_str(vector, "claim_request_id")?;
    let welcome_digest = required_str(vector, "welcome_digest")?;
    let device_authorize_event_id = required_str(vector, "device_authorization_event_id")?;
    let requester_device_id = required_str(vector, "requester_device_id")?;
    arkret_wire::EventId::new(device_authorize_event_id.to_owned())?;
    device(requester_device_id)?;
    require_model_generation_ref(vector, "model_generation_ref")?;
    let intended_realm_id = realm(intended_realm_id)?;
    let requester_verification_method = verification_method(requester_verification_method)?;
    let (requester_method_controller, requester_method_fragment) = requester_verification_method
        .as_str()
        .rsplit_once('#')
        .ok_or_else(|| anyhow!("requester verification method omits fragment"))?;
    // The claim envelope binds `requester_actor_id`, a core id (encryption-and-audit.md:576).
    // The full DID exists only inside the verification method controller, so derive it there
    // and prove the two agree instead of carrying a second copy in the vector.
    let requester_did = full_did(requester_method_controller)?;
    let requester_core_id = arkret_identifiers::project_full_id_to_core_id(&requester_did)?;
    if requester_core_id.as_str() != requester_actor_id
        || requester_method_fragment != requester_device_id
    {
        bail!("requester verification method does not bind requester actor id and device");
    }
    let welcome_digest = Hash::new(welcome_digest.to_owned())?;

    let principal_id = core_did("ak:did_core:web:alice.example")?;
    let device_id = device("ak:device:0196419b-0000-7000-8000-000000000001")?;
    let claim_record = claim_record_value(ClaimRecordInput {
        claim_id,
        keypackage_ref,
        principal_id: &principal_id,
        device_id: &device_id,
        last_resort: false,
        expires_at: parse_time("2100-01-01T00:00:00.000Z")?,
    });
    let claim_outcome = parse_claim_outcome(claim_outcome_value(claim_record))?;
    let claim_receipt = serde_json::to_value(&claim_outcome.claim_receipt)?;
    let claim = claim_outcome
        .claims
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("claim outcome missing record"))?;
    let published_value = keypackage_payload_value(keypackage_ref, digest);
    schema_valid(MLS_KEYPACKAGE_PAYLOAD_SCHEMA, &published_value)?;
    let published: MlsKeypackagePayload = serde_json::from_value(published_value)?;

    let good_welcome = WelcomePayloadFixture {
        keypackage_ref,
        claim_digest: digest,
        envelope_digest: digest,
        capabilities_digest,
        claim_id,
        device_authorize_event_id,
        requester_device_id,
        intended_realm_id: intended_realm_id.as_str(),
        requester_actor_id: requester_core_id.as_str(),
        requester_verification_method: requester_verification_method.as_str(),
        claim_receipt: &claim_receipt,
        welcome_digest: welcome_digest.as_str(),
    };
    let good_value = welcome_payload_value(good_welcome);
    schema_valid(MLS_WELCOME_PAYLOAD_SCHEMA, &good_value)?;
    let good: MlsWelcomePayload = serde_json::from_value(good_value)?;
    validate_mls_welcome_claim_envelope(
        &good,
        &claim,
        &published,
        &intended_realm_id,
        &requester_core_id,
        &welcome_digest,
        Some(device_authorize_event_id),
        None,
        Some(requester_device_id),
        Some(device_authorize_event_id),
    )
    .map_err(|reason| anyhow!("good welcome rejected: {reason}"))?;

    if !expected_bool(vector, "reject_before_decrypt")? {
        bail!("welcome vector must reject before decrypt");
    }

    let bad_claim_ref_value = welcome_payload_value(WelcomePayloadFixture {
        claim_digest: mismatched_digest,
        ..good_welcome
    });
    schema_valid(MLS_WELCOME_PAYLOAD_SCHEMA, &bad_claim_ref_value)?;
    let claim_ref_rejected = match parse_welcome_with_early_binding_rejection(bad_claim_ref_value)?
    {
        Ok(bad_claim_ref) => validate_mls_welcome_claim_envelope(
            &bad_claim_ref,
            &claim,
            &published,
            &intended_realm_id,
            &requester_core_id,
            &welcome_digest,
            Some(device_authorize_event_id),
            None,
            Some(requester_device_id),
            Some(device_authorize_event_id),
        )
        .is_err(),
        Err(reason) => reason == arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH,
    };
    if !claim_ref_rejected {
        bail!("mismatched claim_ref keypackage_digest was accepted");
    }
    if expected_str(vector, "reason")?
        != arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH
    {
        bail!("welcome mismatch reason drifted");
    }
    let bad_realm_value = welcome_payload_value(WelcomePayloadFixture {
        intended_realm_id: "ak:realm:AYmzq24KUdbYXjZtMiyVdibogezW-fCFD3oy0iviR-UD",
        ..good_welcome
    });
    schema_valid(MLS_WELCOME_PAYLOAD_SCHEMA, &bad_realm_value)?;
    let bad_realm: MlsWelcomePayload = serde_json::from_value(bad_realm_value)?;
    if validate_mls_welcome_claim_envelope(
        &bad_realm,
        &claim,
        &published,
        &intended_realm_id,
        &requester_core_id,
        &welcome_digest,
        Some(device_authorize_event_id),
        None,
        Some(requester_device_id),
        Some(device_authorize_event_id),
    )
    .is_ok()
    {
        bail!("mismatched claim_envelope intended_realm_id was accepted");
    }
    let bad_welcome_digest = Hash::new(
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned(),
    )?;
    let bad_welcome_digest_value = welcome_payload_value(WelcomePayloadFixture {
        welcome_digest: bad_welcome_digest.as_str(),
        ..good_welcome
    });
    schema_valid(MLS_WELCOME_PAYLOAD_SCHEMA, &bad_welcome_digest_value)?;
    if serde_json::from_value::<MlsWelcomePayload>(bad_welcome_digest_value).is_ok() {
        bail!("mismatched claim_envelope welcome_digest was accepted");
    }
    for invalid_ciphertext in ["AA==", "AB", "A"] {
        let mut invalid_value = welcome_payload_value(good_welcome);
        invalid_value["ciphertext"] = Value::String(invalid_ciphertext.to_owned());
        schema_invalid(MLS_WELCOME_PAYLOAD_SCHEMA, &invalid_value)?;
        if serde_json::from_value::<MlsWelcomePayload>(invalid_value).is_ok() {
            bail!("non-canonical Welcome ciphertext was accepted: {invalid_ciphertext}");
        }
    }
    for retired_field in ["welcome_ref", "encrypted_welcome_ref"] {
        let mut invalid_value = welcome_payload_value(good_welcome);
        invalid_value[retired_field] = Value::String(
            "ak:blob:sha256:8888888888888888888888888888888888888888888888888888888888888888"
                .to_owned(),
        );
        schema_invalid(MLS_WELCOME_PAYLOAD_SCHEMA, &invalid_value)?;
        if serde_json::from_value::<MlsWelcomePayload>(invalid_value).is_ok() {
            bail!("retired Welcome carrier field was accepted: {retired_field}");
        }
    }
    let mut retired_nonce = welcome_payload_value(good_welcome);
    retired_nonce["claim_envelope"]["nonce"] = json!(claim_request_id);
    schema_invalid(MLS_WELCOME_PAYLOAD_SCHEMA, &retired_nonce)?;
    if serde_json::from_value::<MlsWelcomePayload>(retired_nonce).is_ok() {
        bail!("retired claim_envelope nonce was accepted");
    }
    let mut mismatched_receipt_context = welcome_payload_value(good_welcome);
    mismatched_receipt_context["claim_receipt"]["request"]["claim_request_id"] =
        json!("AAAAAAAAAAAAAAAAAAAAAg");
    schema_valid(MLS_WELCOME_PAYLOAD_SCHEMA, &mismatched_receipt_context)?;
    if serde_json::from_value::<MlsWelcomePayload>(mismatched_receipt_context).is_ok() {
        bail!("mismatched claim receipt/request id context was accepted");
    }
    if expected_bool(vector, "all_digest_fields_equal")?
        && good.claim_ref.keypackage_digest.as_str() != digest
    {
        bail!("good welcome digest binding drifted");
    }
    Hash::new(digest.to_owned())?;
    Ok(())
}

fn parse_welcome_with_early_binding_rejection(
    value: Value,
) -> Result<std::result::Result<MlsWelcomePayload, &'static str>> {
    match serde_json::from_value(value) {
        Ok(payload) => Ok(Ok(payload)),
        Err(error)
            if error
                .to_string()
                .contains("claim bindings do not match top-level fields") =>
        {
            Ok(Err(
                arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH,
            ))
        }
        Err(error) => Err(error.into()),
    }
}

/// Exact runner for `ak.vector.keypackage.self_claim_authorization_idempotency.v1`.
pub fn run_keypackage_self_claim_authorization_idempotency_vector() -> Result<()> {
    let fixture = keypackage_fixture()?;
    validate_unsigned_selector_transcripts(&fixture)?;
    let vector = case(
        &fixture,
        VECTOR_ID_KEYPACKAGE_SELF_CLAIM_AUTHORIZATION_IDEMPOTENCY,
    )?;
    let requester_device_id = required_str(vector, "requester_device_id")?;
    let device_authorization_event_id = required_str(vector, "device_authorization_event_id")?;
    let expected_verification_method =
        required_str(vector, "requester_verification_method")?.to_owned();
    let expected_verification_method_typed = verification_method(&expected_verification_method)?;
    if expected_verification_method_typed
        .as_str()
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        != Some(requester_device_id)
    {
        bail!("self-claim verification method does not name requester_device_id");
    }
    device(requester_device_id)?;
    arkret_wire::EventId::new(device_authorization_event_id.to_owned())?;
    require_model_generation_ref(vector, "model_generation_ref")?;

    let request = fixture["schema_validation_cases"]
        .as_array()
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("name").and_then(Value::as_str)
                    == Some("local_and_remote_claim_share_closed_authorization_carrier")
            })
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
    if verification_method != &expected_verification_method_typed
        || authorized_device_id.as_str() != requester_device_id
        || authorized_event_id.as_str() != device_authorization_event_id
    {
        bail!("self-claim authorization is not bound to the accepted device selector");
    }
    if serde_json::to_value(typed.unsigned_request())? != vector["unsigned_request"]
        || serde_json::to_value(&typed.service_binding)? != vector["service_binding"]
    {
        bail!("unified claim request drifted from its unsigned request or service binding");
    }
    let binding = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &typed.unsigned_request(),
        &typed.service_binding,
        &typed.requester_authorization,
    )?;
    if !binding.starts_with(b"ak.keypackage-claim-authorization-v1\n") {
        bail!("self-claim authorization uses the wrong signing domain");
    }
    let request_digest = arkret_canonical::canonical_sha256(&serde_json::to_value(&typed)?)?;

    let identity = (
        typed.service_binding.source_service_id.as_str().to_owned(),
        typed.claim_request_id.as_str().to_owned(),
    );
    let outcome = arkret_canonical::canonical_json_bytes(&claim_outcome_value(json!({
        "claim_id": "fixture",
        "device_id": requester_device_id
    })))?;
    let mut ledger = BTreeMap::new();
    ledger.insert(identity.clone(), (request_digest.clone(), outcome.clone()));
    let replay = ledger.get(&identity).expect("inserted terminal outcome");
    if replay.0 != request_digest || replay.1 != outcome {
        bail!("exact retry did not return the byte-identical terminal outcome");
    }
    let mut conflict = request;
    conflict["target_principal_id"] = json!("ak:did_core:webvh:z6mkfixturemalloryexample");
    let conflict: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(conflict)?;
    let conflict_digest = arkret_canonical::canonical_sha256(&serde_json::to_value(&conflict)?)?;
    if conflict_digest == replay.0 {
        bail!("same requester/claim_request_id with a changed payload did not conflict");
    }
    let conflict_binding = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &conflict.unsigned_request(),
        &conflict.service_binding,
        &conflict.requester_authorization,
    )?;
    if conflict_binding == binding {
        bail!("claim authorization transcript did not bind the changed target");
    }

    let mut next_attempt = serde_json::to_value(&typed)?;
    next_attempt["claim_request_id"] = json!("AAAAAAAAAAAAAAAAAAAAAg");
    let next_attempt: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(next_attempt)?;
    next_attempt.validate_shape()?;
    let next_identity = (
        next_attempt
            .service_binding
            .source_service_id
            .as_str()
            .to_owned(),
        next_attempt.claim_request_id.as_str().to_owned(),
    );
    if next_identity == identity || ledger.contains_key(&next_identity) {
        bail!("a new claim attempt reused the prior claim_request_id ledger identity");
    }

    let mut legacy_nonce = serde_json::to_value(&typed)?;
    legacy_nonce["claim_nonce"] = json!("BBBBBBBBBBBBBBBBBBBBBB");
    if serde_json::from_value::<arkret_models_crypto::KeyPackagesClaimRequestBody>(legacy_nonce)
        .is_ok()
    {
        bail!("legacy KeyPackage claim_nonce was accepted as a second random carrier");
    }

    let mut missing = serde_json::to_value(&typed)?;
    missing
        .as_object_mut()
        .expect("request object")
        .remove("requester_authorization");
    if serde_json::from_value::<arkret_models_crypto::KeyPackagesClaimRequestBody>(missing).is_ok()
    {
        bail!("a self claim without requester authorization was accepted");
    }
    let mut wrong_branch = serde_json::to_value(&typed)?;
    wrong_branch["requester_authorization"]["signature"]["kid"] =
        json!("did:webvh:z6mkfixture:alice.example#other-key");
    let wrong_branch: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(wrong_branch)?;
    if wrong_branch.validate_shape().is_ok() {
        bail!("a requester authorization whose signature key differs from its method was accepted");
    }
    Ok(())
}

fn validate_unsigned_selector_transcripts(fixture: &Value) -> Result<()> {
    let rows = fixture["unsigned_selector_transcripts"]
        .as_array()
        .ok_or_else(|| anyhow!("fixture omits unsigned_selector_transcripts[]"))?;
    if rows.len() != 3 {
        bail!("unsigned selector transcript fixture must cover exactly three branches");
    }

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
            "native_agent" => {
                request.target_device_ids.is_empty()
                    && request.target_agent_id.is_some()
                    && request.target_agent_verification_method.is_some()
                    && request.target_agent_key_authorize_event_id.is_some()
                    && request.target_pairwise_verification_method.is_none()
            }
            "minimal_metadata_pairwise" => {
                request.target_device_ids.is_empty()
                    && request.target_agent_id.is_none()
                    && request.target_agent_verification_method.is_none()
                    && request.target_agent_key_authorize_event_id.is_none()
                    && request.target_pairwise_verification_method.is_some()
            }
            other => bail!("unknown unsigned selector transcript branch {other}"),
        };
        if !exact_branch || !seen.insert(branch) {
            bail!("{branch} does not preserve one exact selector branch");
        }

        let canonical = arkret_canonical::canonical_json_string(&request_value)?;
        let digest = arkret_canonical::canonical_sha256(&request_value)?;
        if canonical != required_str(row, "canonical_jcs")?
            || digest != required_str(row, "request_digest")?
        {
            bail!("{branch} unsigned request transcript drifted");
        }

        let mut changed = request_value.clone();
        match branch {
            "device" => {
                changed["target_device_ids"][0] =
                    json!("ak:device:0196419b-0000-7000-8000-000000000099");
            }
            "native_agent" => {
                changed["target_agent_key_authorize_event_id"] =
                    json!("ak:event:Aao964Xuq1Q7PmnLt9I97ih00Qs2N6qMkBgKgYCvUFFe");
            }
            "minimal_metadata_pairwise" => {
                changed["target_pairwise_verification_method"] = json!(
                    "did:key:z6MkrJVnaZkeFzdQyUQ5mZKfNA8ZtQZVQzVQzVQzVQzVQzVQ#z6MkrJVnaZkeFzdQyUQ5mZKfNA8ZtQZVQzVQzVQzVQzVQzVQ"
                );
            }
            _ => unreachable!(),
        }
        if arkret_canonical::canonical_sha256(&changed)? == digest {
            bail!("{branch} selector mutation did not change the idempotency digest");
        }
    }
    if seen != BTreeSet::from(["device", "native_agent", "minimal_metadata_pairwise"]) {
        bail!("unsigned selector transcript branch set is incomplete");
    }
    Ok(())
}

/// Closed-XOR model coverage for the pairwise publish/claim/Welcome/consume
/// chain. Live cross-process coverage builds on the same SDK values; this
/// runner prevents either endpoint branch from silently widening back to a
/// Device/Account carrier.
pub fn run_keypackage_minimal_metadata_pairwise_full_lifecycle_vector() -> Result<()> {
    let fixture = keypackage_fixture()?;
    let _vector = case(
        &fixture,
        VECTOR_ID_KEYPACKAGE_MINIMAL_METADATA_PAIRWISE_FULL_LIFECYCLE,
    )?;
    let cases = fixture["schema_validation_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("keypackage fixture missing schema_validation_cases[]"))?;
    for name in [
        "minimal_metadata_pairwise_keypackage_upload_valid",
        "minimal_metadata_pairwise_claim_selects_exact_target_authority",
        "minimal_metadata_pairwise_claim_record_has_reconstructible_facts_only",
        "minimal_metadata_pairwise_consume_single_claim_valid",
    ] {
        let row = cases
            .iter()
            .find(|row| row.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| anyhow!("pairwise lifecycle fixture missing {name}"))?;
        schema_valid(
            required_str(row, "schema_ref")?,
            row.get("instance")
                .ok_or_else(|| anyhow!("pairwise lifecycle case {name} missing instance"))?,
        )?;
    }
    for name in [
        "minimal_metadata_pairwise_upload_rejects_device_mixture",
        "claim_record_rejects_unreconstructible_upload_signature_echo",
        "minimal_metadata_pairwise_consume_rejects_device_mixture",
    ] {
        let row = cases
            .iter()
            .find(|row| row.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| anyhow!("pairwise lifecycle fixture missing {name}"))?;
        schema_invalid(
            required_str(row, "schema_ref")?,
            row.get("instance")
                .ok_or_else(|| anyhow!("pairwise lifecycle case {name} missing instance"))?,
        )?;
    }

    let claim_value = cases
        .iter()
        .find(|row| {
            row.get("name").and_then(Value::as_str)
                == Some("minimal_metadata_pairwise_claim_selects_exact_target_authority")
        })
        .and_then(|row| row.get("instance"))
        .cloned()
        .ok_or_else(|| anyhow!("pairwise claim instance is missing"))?;
    let claim: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(claim_value)?;
    claim.validate_shape().map_err(anyhow::Error::msg)?;
    if !matches!(
        claim.requester_authorization,
        arkret_models_crypto::PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise { .. }
    ) || claim.target_pairwise_verification_method.is_none()
        || !claim.target_device_ids.is_empty()
        || claim.target_agent_id.is_some()
    {
        bail!("pairwise claim did not deserialize to the exact pairwise endpoint branch");
    }

    let welcome_fixture = super::load_fixture_value("keypackage-pairwise-welcome-fixture.json")?;
    super::validate_profile(&welcome_fixture, ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1)?;
    let welcome_cases = welcome_fixture["schema_validation_cases"]
        .as_array()
        .ok_or_else(|| anyhow!("pairwise Welcome fixture missing schema_validation_cases[]"))?;
    let valid_welcome = welcome_cases
        .iter()
        .find(|row| {
            row.get("name").and_then(Value::as_str)
                == Some("minimal_metadata_pairwise_welcome_valid")
        })
        .and_then(|row| row.get("instance"))
        .cloned()
        .ok_or_else(|| anyhow!("pairwise Welcome positive instance is missing"))?;
    schema_valid(MLS_WELCOME_PAYLOAD_SCHEMA, &valid_welcome)?;
    let welcome: MlsWelcomePayload = serde_json::from_value(valid_welcome.clone())?;
    if !matches!(
        welcome.recipient,
        MlsWelcomeRecipient::MinimalMetadataPairwise { .. }
    ) {
        bail!("pairwise Welcome did not deserialize to the exact pairwise recipient branch");
    }
    let mut mixed_welcome = valid_welcome;
    mixed_welcome["recipient_device_id"] = json!("ak:device:0196419b-0000-7000-8000-000000000001");
    schema_invalid(MLS_WELCOME_PAYLOAD_SCHEMA, &mixed_welcome)?;
    Ok(())
}

pub fn run_keypackage_lifecycle_fixture_suite() -> Result<()> {
    validate_keypackage_lifecycle_fixture_metadata(&keypackage_fixture()?)?;

    run_keypackage_exhaustion_claim_limits_vector()
        .context("keypackage exhaustion/claim-limits vector")?;
    run_keypackage_last_resort_claim_and_reuse_vector()
        .context("keypackage last-resort claim/reuse vector")?;
    run_keypackage_last_resort_forced_rotation_vector()
        .context("keypackage last-resort forced-rotation vector")?;
    run_keypackage_last_resort_affinity_and_optionality_vector()
        .context("keypackage last-resort affinity/optionality vector")?;
    run_keypackage_self_claim_authorization_idempotency_vector()
        .context("keypackage self-claim authorization/idempotency vector")?;
    run_keypackage_minimal_metadata_pairwise_full_lifecycle_vector()
        .context("minimal-metadata pairwise KeyPackage full-lifecycle vector")?;
    run_mls_welcome_keypackage_hash_vector().context("MLS welcome KeyPackage hash vector")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypackage_lifecycle_vectors_run_clean() {
        run_keypackage_lifecycle_fixture_suite().unwrap();
    }
}
