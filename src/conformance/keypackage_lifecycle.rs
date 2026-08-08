//! MLS KeyPackage lifecycle conformance vectors.
//!
//! Covers single-use claim limits, last-resort KeyPackage semantics, and MLS
//! Welcome digest binding against the spec artifact fixture.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, anyhow, bail};
use arkret_identifiers::{DeviceId, Did, Hash, RealmId};
use arkret_models_collaboration::events_payloads::{
    MlsKeypackagePayload, MlsWelcomePayload, validate_mls_welcome_claim_envelope,
};
use arkret_models_crypto::{KeyPackagesClaimOutcome, KeyPackagesUploadOutcome};
use arkret_wire::ProfileId;
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

pub const ALL_KEYPACKAGE_LIFECYCLE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_KEYPACKAGE_EXHAUSTION_CLAIM_LIMITS,
    VECTOR_ID_KEYPACKAGE_LAST_RESORT_CLAIM_AND_REUSE,
    VECTOR_ID_KEYPACKAGE_LAST_RESORT_FORCED_ROTATION,
    VECTOR_ID_KEYPACKAGE_LAST_RESORT_AFFINITY_AND_OPTIONALITY,
    VECTOR_ID_KEYPACKAGE_SELF_CLAIM_AUTHORIZATION_IDEMPOTENCY,
    VECTOR_ID_MLS_WELCOME_KEYPACKAGE_HASH,
];

const KEYPACKAGE_LIFECYCLE_FIXTURE_FILE: &str = "keypackage-lifecycle-fixture.json";
const KEY_PACKAGES_UPLOAD_OUTCOME_SCHEMA: &str =
    "schemas/keypackage-operations.schema.json#/$defs/key_packages_upload_outcome";
const KEY_PACKAGES_CLAIM_OUTCOME_SCHEMA: &str =
    "schemas/keypackage-operations.schema.json#/$defs/key_packages_claim_outcome";
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

fn require_root_generation_ref<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    let generation_ref = required_str(value, field)?;
    let (version, entry_hash) = generation_ref
        .split_once('-')
        .ok_or_else(|| anyhow!("{field} must be a did:webvh version id"))?;
    if version
        .parse::<u64>()
        .ok()
        .filter(|version| *version > 0)
        .is_none()
        || entry_hash.is_empty()
    {
        bail!("{field} must be a non-zero did:webvh version id");
    }
    Ok(generation_ref)
}

fn did(value: &str) -> Result<Did> {
    Did::new(value.to_owned()).map_err(Into::into)
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

fn claim_record_value(
    claim_id: &str,
    keypackage_ref: &str,
    keypackage_digest: &str,
    principal_id: &Did,
    device_id: &DeviceId,
    last_resort: bool,
    expires_at: DateTime<Utc>,
) -> Value {
    let mut value = json!({
        "claim_id": claim_id,
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": keypackage_digest,
        "principal_id": principal_id.as_str(),
        "device_id": device_id.as_str(),
        "key_package": "AQID",
        "capabilities": ["ak.mls.profile.full"],
        "capabilities_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "device_authorize_event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
        "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
        "device_signature": {
            "kid": format!("{}#{}", principal_id.as_str(), device_id.as_str()),
            "signature_algorithm": "Ed25519",
            "sig": "c2ln"
        },
        "revocation_status": "active"
    });
    if last_resort {
        value["last_resort"] = json!(true);
    }
    value
}

fn claim_outcome_value(record: Value, available_count: u64) -> Value {
    json!({
        "claims": [record],
        "available_count": available_count
    })
}

fn failure_value(keypackage_ref: Option<&str>, reason_code: &str) -> Value {
    let mut failure = json!({
        "reason_code": reason_code
    });
    if let Some(keypackage_ref) = keypackage_ref {
        failure["keypackage_ref"] = json!(keypackage_ref);
    }
    failure
}

fn claim_failure_outcome_value(reason_code: &str, available_count: Option<u64>) -> Value {
    let mut value = json!({
        "claims": [],
        "failures": [failure_value(None, reason_code)]
    });
    if let Some(available_count) = available_count {
        value["available_count"] = json!(available_count);
    }
    value
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
    principal_id: Did,
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
        principal_id: Did,
        device_id: DeviceId,
        intended_realm_id: RealmId,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            keypackage_ref: keypackage_ref.into(),
            keypackage_digest: keypackage_digest.into(),
            principal_id,
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
        principal_id: Did,
        device_id: DeviceId,
        intended_realm_id: RealmId,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let mut package = Self::new_normal(
            keypackage_ref,
            keypackage_digest,
            principal_id,
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
        claim_record_value(
            claim_id,
            &self.keypackage_ref,
            &self.keypackage_digest,
            &self.principal_id,
            &self.device_id,
            self.last_resort,
            self.expires_at,
        )
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
        return Ok(claim_outcome_value(package.claim_record(claim_id), 0));
    }

    if explicit_last_resort_fallback && !feature_supported {
        return Ok(claim_failure_outcome_value(
            arkret_wire::ReasonCode::LAST_RESORT_NOT_SUPPORTED,
            Some(0),
        ));
    }

    if feature_supported
        && let Some(package) = pool.iter_mut().find(|package| {
            package.last_resort
                && package.state == MiniKeypackageState::Published
                && &package.intended_realm_id == realm_id
        })
    {
        return Ok(claim_outcome_value(package.claim_record(claim_id), 0));
    }

    Ok(claim_failure_outcome_value(
        arkret_wire::ErrorCode::KEYPACKAGE_UNKNOWN,
        Some(0),
    ))
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
    let available_count = vector
        .get("available_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("exhaustion vector missing available_count"))?;
    if available_count >= min_available {
        bail!("exhaustion vector must start below keypackage_min_available");
    }

    let upload_value = json!({
        "accepted": 0,
        "available_count": available_count,
        "key_package_refs": ["sha256:5555555555555555555555555555555555555555555555555555555555555555"]
    });
    schema_valid(KEY_PACKAGES_UPLOAD_OUTCOME_SCHEMA, &upload_value)?;
    let upload: KeyPackagesUploadOutcome = serde_json::from_value(upload_value)?;
    if expected_bool(vector, "available_count_visible")?
        && upload.available_count != Some(available_count)
    {
        bail!("visible keypackage response did not expose available_count");
    }

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
    let rate_limited = parse_claim_outcome(claim_failure_outcome_value(
        arkret_wire::ErrorCode::KEYPACKAGE_UNKNOWN,
        Some(available_count),
    ))?;
    if rate_limited.failures.len() != 1 || !rate_limited.claims.is_empty() {
        bail!("rate-limited claim did not fail closed without claims");
    }
    if expected_str(vector, "rate_limit_audit_reason")? != "keypackage_claim_rate_limited" {
        bail!("keypackage claim rate-limit audit reason drifted");
    }
    if expected_str(vector, "rate_limit_external_failure")? != "anti_enumeration" {
        bail!("rate-limit external failure semantics drifted");
    }

    let principal = did(required_str(vector, "target_principal_id")?)?;
    let device = device(required_str(vector, "device_id")?)?;
    let realm = realm(required_str(vector, "intended_realm_id")?)?;
    let expired = vector
        .get("expired_claim")
        .ok_or_else(|| anyhow!("exhaustion vector missing expired_claim"))?;
    let mut package = MiniKeypackage::new_normal(
        required_str(expired, "keypackage_ref")?,
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        principal,
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
                }
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
    let principal = did(required_str(vector, "target_principal_id")?)?;
    let device = device(required_str(vector, "device_id")?)?;
    let realm = realm(required_str(vector, "intended_realm_id")?)?;
    let expires_at = parse_time("2100-01-01T00:00:00.000Z")?;
    let mut pool = vec![
        MiniKeypackage::new_normal(
            required_str(vector, "normal_keypackage_ref")?,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            principal.clone(),
            device.clone(),
            realm.clone(),
            expires_at,
        ),
        MiniKeypackage::new_last_resort(
            required_str(vector, "last_resort_keypackage_ref")?,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            principal,
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
    let principal = did("did:web:alice.example")?;
    let device = device(required_str(vector, "device_id")?)?;
    let realm = realm("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1")?;
    let expires_at = parse_time("2100-01-01T00:00:00.000Z")?;
    let mut old = MiniKeypackage::new_last_resort(
        required_str(vector, "old_last_resort_keypackage_ref")?,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        principal,
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
    let principal = did("did:web:alice.example")?;
    let device = device("ak:device:0196419b-0000-7000-8000-000000000001")?;
    let r1 = realm(required_str(vector, "realm_r1")?)?;
    let r2 = realm(required_str(vector, "realm_r2")?)?;
    let expires_at = parse_time("2100-01-01T00:00:00.000Z")?;
    let mut package = MiniKeypackage::new_last_resort(
        required_str(vector, "last_resort_keypackage_ref")?,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        principal.clone(),
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

    let unsupported = parse_claim_outcome(claim_from_pool(
        &mut [],
        &r1,
        "mls-keypackage-claim-unsupported",
        false,
        true,
    )?)?;
    if unsupported
        .failures
        .first()
        .map(|failure| failure.reason_code.as_str())
        != Some(expected_str(vector, "unsupported_reason")?)
        || unsupported
            .claims
            .iter()
            .any(|claim| claim.last_resort == Some(true))
    {
        bail!("unsupported last-resort fallback did not fail closed");
    }

    let mut r1_only_pool = vec![MiniKeypackage::new_last_resort(
        required_str(vector, "last_resort_keypackage_ref")?,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        principal,
        device,
        r1,
        expires_at,
    )];
    let missing_r2 = parse_claim_outcome(claim_from_pool(
        &mut r1_only_pool,
        &r2,
        "mls-keypackage-claim-r2-missing",
        true,
        true,
    )?)?;
    if missing_r2
        .failures
        .first()
        .map(|failure| failure.reason_code.as_str())
        != Some(expected_str(vector, "no_cross_realm_fallback_reason")?)
    {
        bail!("missing Realm-local last-resort entry did not fail closed");
    }
    if expected_bool(vector, "claim_realm_matches_intended_realm")?
        && missing_r2
            .claims
            .iter()
            .any(|claim| claim.last_resort == Some(true))
    {
        bail!("claim returned cross-Realm last-resort package");
    }
    Ok(())
}

fn keypackage_payload_value(keypackage_ref: &str, keypackage_digest: &str) -> Value {
    json!({
        "keypackage_id": "kp-1",
        "principal_id": "did:web:alice.example",
        "device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
        "keypackage_ref": keypackage_ref,
        "keypackage_digest": keypackage_digest,
        "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
        "capabilities": ["ak.mls.profile.full"],
        "state": "published",
        "expires_at": "2100-01-01T00:00:00.000Z",
        "created_at": "2026-06-19T00:00:00.000Z",
        "device_signature": {
            "kid": "did:web:alice.example#ak:device:0196419b-0000-7000-8000-000000000001",
            "signature_algorithm": "Ed25519",
            "sig": "c2ln"
        }
    })
}

#[derive(Clone, Copy)]
struct WelcomePayloadFixture<'a> {
    keypackage_ref: &'a str,
    top_digest: &'a str,
    claim_digest: &'a str,
    envelope_digest: &'a str,
    capabilities_digest: &'a str,
    claim_id: &'a str,
    device_authorize_event_id: &'a str,
    requester_device_id: &'a str,
    intended_realm_id: &'a str,
    requester_did: &'a str,
    claim_nonce: &'a str,
    welcome_digest: &'a str,
}

fn welcome_payload_value(fixture: WelcomePayloadFixture<'_>) -> Value {
    json!({
        "mls_group_id": "mls-group-a",
        "epoch": 1,
        "recipient_principal_id": "did:web:alice.example",
        "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
        "keypackage_ref": fixture.keypackage_ref,
        "keypackage_digest": fixture.top_digest,
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
            "requester_did": fixture.requester_did,
            "requester_device_id": fixture.requester_device_id,
            "nonce": fixture.claim_nonce,
            "welcome_digest": fixture.welcome_digest,
            "created_at": "2026-05-25T00:00:00.000Z",
            "signature": {
                "kid": "did:web:alice.example#ak:device:0196419b-0000-7000-8000-000000000001",
                "signature_algorithm": "Ed25519",
                "sig": "c2ln"
            }
        },
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
    let requester_did = required_str(vector, "requester_did")?;
    let claim_nonce = required_str(vector, "claim_nonce")?;
    let welcome_digest = required_str(vector, "welcome_digest")?;
    let device_authorize_event_id = required_str(vector, "device_authorization_event_id")?;
    let requester_device_id = required_str(vector, "requester_device_id")?;
    arkret_wire::EventId::new(device_authorize_event_id.to_owned())?;
    device(requester_device_id)?;
    require_root_generation_ref(vector, "model_generation_ref")?;
    let intended_realm_id = realm(intended_realm_id)?;
    let requester_did = did(requester_did)?;
    let welcome_digest = Hash::new(welcome_digest.to_owned())?;

    let claim_record = claim_record_value(
        claim_id,
        keypackage_ref,
        digest,
        &did("did:web:alice.example")?,
        &device("ak:device:0196419b-0000-7000-8000-000000000001")?,
        false,
        parse_time("2100-01-01T00:00:00.000Z")?,
    );
    let claim = parse_claim_outcome(claim_outcome_value(claim_record, 1))?
        .claims
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("claim outcome missing record"))?;
    let published_value = keypackage_payload_value(keypackage_ref, digest);
    schema_valid(MLS_KEYPACKAGE_PAYLOAD_SCHEMA, &published_value)?;
    let published: MlsKeypackagePayload = serde_json::from_value(published_value)?;

    let good_welcome = WelcomePayloadFixture {
        keypackage_ref,
        top_digest: digest,
        claim_digest: digest,
        envelope_digest: digest,
        capabilities_digest,
        claim_id,
        device_authorize_event_id,
        requester_device_id,
        intended_realm_id: intended_realm_id.as_str(),
        requester_did: requester_did.as_str(),
        claim_nonce,
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
        &requester_did,
        &welcome_digest,
        claim_nonce,
        Some(device_authorize_event_id),
        None,
        Some(requester_device_id),
    )
    .map_err(|reason| anyhow!("good welcome rejected: {reason}"))?;

    let bad_top_value = welcome_payload_value(WelcomePayloadFixture {
        top_digest: mismatched_digest,
        ..good_welcome
    });
    schema_valid(MLS_WELCOME_PAYLOAD_SCHEMA, &bad_top_value)?;
    let reason = match parse_welcome_with_early_binding_rejection(bad_top_value)? {
        Ok(bad_top) => validate_mls_welcome_claim_envelope(
            &bad_top,
            &claim,
            &published,
            &intended_realm_id,
            &requester_did,
            &welcome_digest,
            claim_nonce,
            Some(device_authorize_event_id),
            None,
            Some(requester_device_id),
        )
        .err()
        .ok_or_else(|| anyhow!("mismatched top-level welcome digest was accepted"))?,
        Err(reason) => reason,
    };
    if reason != expected_str(vector, "reason")? {
        bail!("welcome mismatch reason drifted: {reason}");
    }
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
            &requester_did,
            &welcome_digest,
            claim_nonce,
            Some(device_authorize_event_id),
            None,
            Some(requester_device_id),
        )
        .is_err(),
        Err(reason) => reason == arkret_wire::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH,
    };
    if !claim_ref_rejected {
        bail!("mismatched claim_ref keypackage_digest was accepted");
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
        &requester_did,
        &welcome_digest,
        claim_nonce,
        Some(device_authorize_event_id),
        None,
        Some(requester_device_id),
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
    let bad_welcome_digest_payload: MlsWelcomePayload =
        serde_json::from_value(bad_welcome_digest_value)?;
    if validate_mls_welcome_claim_envelope(
        &bad_welcome_digest_payload,
        &claim,
        &published,
        &intended_realm_id,
        &requester_did,
        &welcome_digest,
        claim_nonce,
        Some(device_authorize_event_id),
        None,
        Some(requester_device_id),
    )
    .is_ok()
    {
        bail!("mismatched claim_envelope welcome_digest was accepted");
    }
    let bad_nonce_value = welcome_payload_value(WelcomePayloadFixture {
        claim_nonce: "different-claim-nonce",
        ..good_welcome
    });
    schema_valid(MLS_WELCOME_PAYLOAD_SCHEMA, &bad_nonce_value)?;
    let bad_nonce: MlsWelcomePayload = serde_json::from_value(bad_nonce_value)?;
    if validate_mls_welcome_claim_envelope(
        &bad_nonce,
        &claim,
        &published,
        &intended_realm_id,
        &requester_did,
        &welcome_digest,
        claim_nonce,
        Some(device_authorize_event_id),
        None,
        Some(requester_device_id),
    )
    .is_ok()
    {
        bail!("mismatched claim_envelope nonce was accepted");
    }
    if expected_bool(vector, "all_digest_fields_equal")?
        && good.keypackage_digest.as_str() != claim.keypackage_digest.as_str()
    {
        bail!("good welcome digest fields are not equal");
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
    let vector = case(
        &fixture,
        VECTOR_ID_KEYPACKAGE_SELF_CLAIM_AUTHORIZATION_IDEMPOTENCY,
    )?;
    let requester = required_str(&vector["proof_free_request"], "requester")?;
    let requester_device_id = required_str(vector, "requester_device_id")?;
    let device_authorization_event_id = required_str(vector, "device_authorization_event_id")?;
    let expected_verification_method = format!("{requester}#{requester_device_id}");
    device(requester_device_id)?;
    arkret_wire::EventId::new(device_authorization_event_id.to_owned())?;
    require_root_generation_ref(vector, "model_generation_ref")?;

    let mut request = vector["proof_free_request"].clone();
    request["holder_acceptance_proof"] = json!({
        "kind": "detached_jws",
        "verification_method": expected_verification_method.clone(),
        "payload_digest": required_str(vector, "payload_digest")?,
        "created_at": "2026-07-31T00:00:00.000Z",
        "audience": required_str(vector, "authority_service_id")?,
        "proof_purpose": "holder_acceptance",
        "jws": "eyJhbGciOiJFZDI1NTE5In0..c2ln"
    });
    let typed: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(request.clone())?;
    if typed.holder_acceptance_proof.verification_method.as_str() != expected_verification_method {
        bail!("self-claim proof is not bound to the canonical accepted-device method");
    }
    let typed_payload_digest = typed.payload_digest()?;
    if typed_payload_digest.as_str() != required_str(vector, "payload_digest")? {
        let mut typed_proof_free = serde_json::to_value(&typed)?;
        typed_proof_free
            .as_object_mut()
            .expect("request object")
            .remove("holder_acceptance_proof");
        bail!(
            "self-claim proof-free payload digest drifted: expected {}, got {}, projection={}",
            required_str(vector, "payload_digest")?,
            typed_payload_digest,
            String::from_utf8(arkret_canonical::canonical_json_bytes(&typed_proof_free)?)?
        );
    }
    let proof_free_bytes = arkret_canonical::canonical_json_bytes(&vector["proof_free_request"])?;
    if std::str::from_utf8(&proof_free_bytes)?
        != required_str(vector, "canonical_proof_free_request_json")?
    {
        bail!("self-claim proof-free canonical projection drifted");
    }
    let binding = typed.proof_binding_bytes()?;
    let actual_binding = std::str::from_utf8(&binding)?;
    let actual_binding_digest =
        arkret_canonical::canonical_sha256(&serde_json::from_slice::<Value>(&binding)?)?;
    if actual_binding != required_str(vector, "canonical_proof_binding_json")?
        || actual_binding_digest != required_str(vector, "proof_binding_digest")?
    {
        bail!(
            "self-claim proof binding or digest drifted: binding={actual_binding}, digest={actual_binding_digest}"
        );
    }
    let authority = did(required_str(vector, "authority_service_id")?)?;
    typed.validate_proof_shape(&authority, parse_time("2026-07-31T00:01:00.000Z")?)?;

    let identity = (
        typed.requester.as_str().to_owned(),
        typed.claim_nonce.as_str().to_owned(),
    );
    let outcome = br#"{"claims":[{"claim_id":"fixture"}],"failures":[]}"#.to_vec();
    let mut ledger = BTreeMap::new();
    ledger.insert(
        identity.clone(),
        (typed.payload_digest()?.to_string(), outcome.clone()),
    );
    let replay = ledger.get(&identity).expect("inserted terminal outcome");
    if replay.0 != typed.payload_digest()?.as_str() || replay.1 != outcome {
        bail!("exact retry did not return the byte-identical terminal outcome");
    }
    let mut conflict = request;
    conflict["target_principal_id"] = json!("did:webvh:z6mkfixture:mallory.example");
    let conflict: arkret_models_crypto::KeyPackagesClaimRequestBody =
        serde_json::from_value(conflict)?;
    if conflict.payload_digest()?.as_str() == replay.0 {
        bail!("same requester/nonce with a changed payload did not conflict");
    }

    let mut missing = serde_json::to_value(&typed)?;
    missing
        .as_object_mut()
        .expect("request object")
        .remove("holder_acceptance_proof");
    if serde_json::from_value::<arkret_models_crypto::KeyPackagesClaimRequestBody>(missing).is_ok()
    {
        bail!("a self claim without exactly one proof was accepted");
    }
    let mut multiple = serde_json::to_value(&typed)?;
    let proof = multiple["holder_acceptance_proof"].clone();
    multiple["proofs"] = json!([proof.clone(), proof]);
    if serde_json::from_value::<arkret_models_crypto::KeyPackagesClaimRequestBody>(multiple).is_ok()
    {
        bail!("a self claim with multiple proofs was accepted");
    }
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
