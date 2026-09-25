//! Final fixture-backed closure for the remaining privacy/security vectors.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::helpers::assert_expected_subset;
use super::{
    expected, required_array, required_bool, required_object, required_str, required_str_obj,
    required_u64, string_set, string_vec,
};
use crate::transcripts::record_vector_event;

pub const VECTOR_ID_APPLET_TRANSACTION_DELIVERY_AUTHENTICATION_RECORD_DIGEST: &str =
    "ak.vector.applet.transaction_delivery_authentication_record_digest.v1";
pub const VECTOR_ID_CALENDAR_RSVP_OCCURRENCE_KEY: &str =
    "ak.vector.calendar.rsvp_occurrence_key.v1";
pub const VECTOR_ID_FEDERATION_TIMING_BUCKET: &str = "ak.vector.federation.timing_bucket.v1";
pub const VECTOR_ID_MLS_KEY_ACCESS_REVISION: &str =
    "ak.vector.mls.key_access_revision_key_access_only.v1";
pub const VECTOR_ID_MLS_PROPOSAL_PRODUCER_BINDING: &str =
    "ak.vector.mls.proposal_producer_binding.v1";
pub const VECTOR_ID_MODERATION_FRANKING_ROUNDTRIP: &str =
    "ak.vector.moderation.franking_roundtrip.v1";
pub const VECTOR_ID_MODERATION_EVIDENCE_PACKAGE_MINIMAL_DISCLOSURE: &str =
    "ak.vector.moderation.evidence_package_minimal_disclosure.v1";
pub const VECTOR_ID_MODERATION_REVIEW_RESOLUTION_FOLD: &str =
    "ak.vector.moderation.review_resolution_fold.v1";
pub const VECTOR_ID_RELATION_REFERENCE_PROJECTION_INDISTINGUISHABLE: &str =
    "ak.vector.relation.reference_projection_indistinguishable.v1";

pub const ALL_FINAL_CONFORMANCE_CLOSURE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_APPLET_TRANSACTION_DELIVERY_AUTHENTICATION_RECORD_DIGEST,
    VECTOR_ID_CALENDAR_RSVP_OCCURRENCE_KEY,
    VECTOR_ID_FEDERATION_TIMING_BUCKET,
    VECTOR_ID_MLS_KEY_ACCESS_REVISION,
    VECTOR_ID_MLS_PROPOSAL_PRODUCER_BINDING,
    VECTOR_ID_MODERATION_FRANKING_ROUNDTRIP,
    VECTOR_ID_MODERATION_EVIDENCE_PACKAGE_MINIMAL_DISCLOSURE,
    VECTOR_ID_MODERATION_REVIEW_RESOLUTION_FOLD,
    VECTOR_ID_RELATION_REFERENCE_PROJECTION_INDISTINGUISHABLE,
];

const FINAL_CONFORMANCE_CLOSURE_FIXTURE_FILE: &str = "final-conformance-closure-fixture.json";
const APPLET_TRANSACTION_DEFAULT_DIRECTION: &str = "applet_to_arkret_inbound";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalConformanceClosureFixture {
    profile: String,
    version: String,
    suite: String,
    runner: Value,
    covers_vectors: Vec<String>,
    security_evidence: Vec<super::SecurityEvidenceRow>,
    cases: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AppletTransactionReplayIdentity {
    operation_id: String,
    direction: String,
    source_id: String,
    destination_id: String,
    idempotency_key: String,
}

#[derive(Clone, Debug)]
struct AppletTransactionReplayRecord {
    body_digest: String,
    delivery_authentication_record_digest: String,
}

pub fn run_final_conformance_closure_fixture_suite() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_applet_transaction_delivery_authentication_record_digest_case(case(
        &fixture,
        VECTOR_ID_APPLET_TRANSACTION_DELIVERY_AUTHENTICATION_RECORD_DIGEST,
    )?)?;
    run_calendar_rsvp_occurrence_key_case(case(&fixture, VECTOR_ID_CALENDAR_RSVP_OCCURRENCE_KEY)?)?;
    run_federation_timing_bucket_case(case(&fixture, VECTOR_ID_FEDERATION_TIMING_BUCKET)?)?;
    run_mls_key_access_revision_cases(&fixture)?;
    run_mls_proposal_producer_binding_case(case(
        &fixture,
        VECTOR_ID_MLS_PROPOSAL_PRODUCER_BINDING,
    )?)?;
    run_moderation_review_resolution_fold_case(case(
        &fixture,
        VECTOR_ID_MODERATION_REVIEW_RESOLUTION_FOLD,
    )?)?;
    run_moderation_franking_roundtrip_case(case(
        &fixture,
        VECTOR_ID_MODERATION_FRANKING_ROUNDTRIP,
    )?)?;
    run_moderation_evidence_package_minimal_disclosure_case(case(
        &fixture,
        VECTOR_ID_MODERATION_EVIDENCE_PACKAGE_MINIMAL_DISCLOSURE,
    )?)?;
    run_relation_reference_projection_indistinguishable_case(case(
        &fixture,
        VECTOR_ID_RELATION_REFERENCE_PROJECTION_INDISTINGUISHABLE,
    )?)?;
    Ok(())
}

pub fn run_applet_transaction_delivery_authentication_record_digest_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_applet_transaction_delivery_authentication_record_digest_case(case(
        &fixture,
        VECTOR_ID_APPLET_TRANSACTION_DELIVERY_AUTHENTICATION_RECORD_DIGEST,
    )?)
}

pub fn run_calendar_rsvp_occurrence_key_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_calendar_rsvp_occurrence_key_case(case(&fixture, VECTOR_ID_CALENDAR_RSVP_OCCURRENCE_KEY)?)
}

pub fn run_federation_timing_bucket_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_federation_timing_bucket_case(case(&fixture, VECTOR_ID_FEDERATION_TIMING_BUCKET)?)
}

pub fn run_mls_proposal_producer_binding_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_mls_proposal_producer_binding_case(case(&fixture, VECTOR_ID_MLS_PROPOSAL_PRODUCER_BINDING)?)
}

pub fn run_mls_key_access_revision_vector() -> Result<()> {
    run_mls_key_access_revision_cases(&final_conformance_closure_fixture()?)
}

pub fn run_moderation_review_resolution_fold_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_moderation_review_resolution_fold_case(case(
        &fixture,
        VECTOR_ID_MODERATION_REVIEW_RESOLUTION_FOLD,
    )?)
}

pub fn run_moderation_franking_roundtrip_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_moderation_franking_roundtrip_case(case(&fixture, VECTOR_ID_MODERATION_FRANKING_ROUNDTRIP)?)
}

pub fn run_moderation_evidence_package_minimal_disclosure_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_moderation_evidence_package_minimal_disclosure_case(case(
        &fixture,
        VECTOR_ID_MODERATION_EVIDENCE_PACKAGE_MINIMAL_DISCLOSURE,
    )?)
}

pub fn run_relation_reference_projection_indistinguishable_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_relation_reference_projection_indistinguishable_case(case(
        &fixture,
        VECTOR_ID_RELATION_REFERENCE_PROJECTION_INDISTINGUISHABLE,
    )?)
}

fn final_conformance_closure_fixture() -> Result<FinalConformanceClosureFixture> {
    let raw = super::load_fixture_value(FINAL_CONFORMANCE_CLOSURE_FIXTURE_FILE)?;
    let fixture: FinalConformanceClosureFixture = serde_json::from_value(raw.clone())?;
    validate_final_conformance_closure_fixture_metadata(&fixture)?;
    super::verify_security_evidence(
        FINAL_CONFORMANCE_CLOSURE_FIXTURE_FILE,
        &raw,
        &fixture.security_evidence,
        &fixture.covers_vectors,
    )?;
    Ok(fixture)
}

fn validate_final_conformance_closure_fixture_metadata(
    fixture: &FinalConformanceClosureFixture,
) -> Result<()> {
    if fixture.profile != crate::conformance::helpers::PRIVACY_SECURITY_VECTOR_GROUP_PROFILE
        || fixture.suite != "final_conformance_closure"
        || fixture.version.trim().is_empty()
    {
        bail!("final conformance closure fixture suite drifted");
    }
    if fixture.runner.get("entrypoint").and_then(Value::as_str)
        != Some("ak.suite.conformance.final_closure.v1")
    {
        bail!("final conformance closure fixture runner drifted");
    }

    let covers = &fixture.covers_vectors;
    let cases = &fixture.cases;

    for vector_id in ALL_FINAL_CONFORMANCE_CLOSURE_VECTOR_IDS {
        if !covers.iter().any(|entry| entry == vector_id) {
            bail!("final conformance closure fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("final conformance closure fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

fn case<'a>(fixture: &'a FinalConformanceClosureFixture, vector_id: &str) -> Result<&'a Value> {
    fixture
        .cases
        .iter()
        .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
        .ok_or_else(|| anyhow!("final conformance closure fixture missing case {vector_id}"))
}

fn run_applet_transaction_delivery_authentication_record_digest_case(case: &Value) -> Result<()> {
    let active_install = required_object(case, "active_install")?;
    let required_components = string_set(case, "required_components")?;
    assert_required_assertions(
        case,
        &[
            "valid_transaction_requires_delivery_authentication_record",
            "delivery_authentication_record_is_closed_and_receiver_derived",
            "delivery_authentication_record_digest_is_domain_separated",
            "bearer_only_rejected",
            "source_destination_and_content_digest_bound",
            "idempotent_replay_returns_cached_outcome",
            "idempotency_identity_body_drift_rejected",
            "active_install_and_actor_namespace_required",
        ],
    )?;
    let mut cache = BTreeMap::new();
    let mut identity_by_name = BTreeMap::new();
    let mut seen = BTreeSet::new();

    for transaction in required_array(case, "transactions")? {
        let name = required_str(transaction, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_applet_transaction(
            active_install,
            &required_components,
            transaction,
            &mut cache,
            &mut identity_by_name,
        )?;
        assert_expected_subset(name, expected(transaction)?, &observed)?;
        record_step(
            VECTOR_ID_APPLET_TRANSACTION_DELIVERY_AUTHENTICATION_RECORD_DIGEST,
            name,
            transaction,
            &observed,
        );
    }

    for required in [
        "valid_inbound",
        "missing_signature",
        "source_mismatch",
        "exact_replay",
        "idempotency_body_drift",
        "no_active_install",
        "actor_namespace_mismatch",
    ] {
        if !seen.contains(required) {
            bail!("applet transaction vector missing transaction {required}");
        }
    }
    Ok(())
}

fn evaluate_applet_transaction(
    active_install: &Map<String, Value>,
    required_components: &BTreeSet<&str>,
    transaction: &Value,
    cache: &mut BTreeMap<AppletTransactionReplayIdentity, AppletTransactionReplayRecord>,
    identity_by_name: &mut BTreeMap<String, AppletTransactionReplayIdentity>,
) -> Result<Value> {
    if let Some(replay_of) = transaction.get("replay_of").and_then(Value::as_str) {
        let original_identity = identity_by_name
            .get(replay_of)
            .ok_or_else(|| anyhow!("replay references unknown accepted transaction {replay_of}"))?;
        let idempotency_key = required_str(transaction, "idempotency_key")?;
        if original_identity.idempotency_key != idempotency_key {
            return Ok(json!({"decision": "reject", "reason": "duplicate_conflict"}));
        }
        let body_digest = required_str(transaction, "body_digest")?;
        // A replay presenting its own record is re-derived; otherwise it names
        // the digest its receiver derived at verification time.
        let delivery_authentication_record_digest = match transaction
            .get("delivery_authentication_record")
        {
            Some(record) => delivery_authentication_record_digest(record)?,
            None => required_str(transaction, "delivery_authentication_record_digest")?.to_owned(),
        };
        return match cache.get(original_identity) {
            Some(record)
                if record.body_digest == body_digest
                    && record.delivery_authentication_record_digest
                        == delivery_authentication_record_digest =>
            {
                Ok(json!({
                    "decision": "accept_cached",
                    "side_effects_applied": false,
                }))
            }
            Some(_) => Ok(json!({"decision": "reject", "reason": "duplicate_conflict"})),
            None => Ok(json!({"decision": "reject", "reason": "failed_precondition"})),
        };
    }

    if transaction
        .get("signature_present")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Ok(json!({"decision": "reject", "reason": "http_signature_required"}));
    }

    // Covered components come first when the transaction declares them: a
    // signature that does not cover the required components authenticates none
    // of the identity fields below, so such a transaction may legitimately omit
    // them. Reading those fields first turned that case into a fixture-parse
    // error instead of the rejection it asserts. A transaction that declares no
    // covered_components at all is asserting some other rejection and falls
    // through to the checks below.
    if transaction.get("covered_components").is_some()
        && !covered_components_include_all(transaction, required_components)?
    {
        return Ok(json!({"decision": "reject", "reason": "http_signature_invalid"}));
    }

    let source_header = required_str(transaction, "source_id_header")?;
    let source_body = required_str(transaction, "source_id_body")?;
    let destination_header = required_str(transaction, "destination_id_header")?;
    let install_source = required_str_obj(active_install, "service_id")?;
    let install_destination = required_str_obj(active_install, "destination_id")?;

    if source_header != install_source {
        return Ok(json!({
            "decision": "reject",
            "reason": "applet_registration_unauthorized",
        }));
    }
    if source_header != source_body
        || destination_header != install_destination
        || transaction
            .get("content_digest_matches_body")
            .and_then(Value::as_bool)
            != Some(true)
        || required_str(transaction, "keyid")? != required_str_obj(active_install, "key_ref")?
    {
        return Ok(json!({"decision": "reject", "reason": "http_signature_invalid"}));
    }

    if let Some(registration_epoch) = transaction
        .get("registration_epoch")
        .and_then(Value::as_str)
        && Some(registration_epoch)
            != active_install
                .get("registration_epoch")
                .and_then(Value::as_str)
    {
        return Ok(json!({
            "decision": "reject",
            "reason": "applet_registration_unauthorized",
        }));
    }

    if required_str(transaction, "actor_namespace")?
        != required_str_obj(active_install, "actor_namespace")?
        || required_str(transaction, "authorization_ref_owner")? != install_source
    {
        return Ok(json!({
            "decision": "reject",
            "reason": "applet_namespace_mismatch",
        }));
    }

    let idempotency_key = required_str(transaction, "idempotency_key")?;
    let body_digest = required_str(transaction, "body_digest")?;
    let record = derive_delivery_authentication_record(active_install, transaction)?;
    let record_bytes = arkret_canonical::canonical_json_bytes(&record)?;
    let delivery_authentication_record_digest = delivery_authentication_record_digest(&record)?;
    let delivery_authentication_record_digest = delivery_authentication_record_digest.as_str();
    let replay_identity = applet_transaction_replay_identity(
        transaction,
        source_header,
        destination_header,
        idempotency_key,
    )?;
    if let Some(record) = cache.get(&replay_identity) {
        if record.body_digest == body_digest
            && record.delivery_authentication_record_digest == delivery_authentication_record_digest
        {
            return Ok(json!({
                "decision": "accept_cached",
                "side_effects_applied": false,
            }));
        }
        return Ok(json!({"decision": "reject", "reason": "duplicate_conflict"}));
    }

    cache.insert(
        replay_identity.clone(),
        AppletTransactionReplayRecord {
            body_digest: body_digest.to_owned(),
            delivery_authentication_record_digest: delivery_authentication_record_digest.to_owned(),
        },
    );
    identity_by_name.insert(
        required_str(transaction, "name")?.to_owned(),
        replay_identity,
    );

    Ok(json!({
        "decision": "accept",
        "delivery_authentication_record_persisted": true,
        "delivery_authentication_record": record,
        "delivery_authentication_record_canonical_bytes_utf8": String::from_utf8(record_bytes)?,
        "delivery_authentication_record_digest": delivery_authentication_record_digest,
        "side_effects_applied": true,
    }))
}

fn assert_required_assertions(case: &Value, required: &[&str]) -> Result<()> {
    let assertions = string_set(case, "assertions")?;
    for assertion in required {
        if !assertions.contains(*assertion) {
            bail!("applet transaction vector missing assertion {assertion}");
        }
    }
    Ok(())
}

const DELIVERY_AUTHENTICATION_RECORD_DOMAIN: &[u8] =
    b"ak.applet.delivery_authentication_record.v1\n";

/// Receiver-derived closed `delivery_authentication_record`
/// (`applet-integration.md` 投递认证记录): taken from the verified message,
/// the effective registration and the actual verification key, never from a
/// caller-supplied value.
fn derive_delivery_authentication_record(
    active_install: &Map<String, Value>,
    transaction: &Value,
) -> Result<Value> {
    let operation_id = required_str(transaction, "arkret_operation")?;
    if operation_id != arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1 {
        bail!("applet transaction selected operation {operation_id}");
    }
    Ok(json!({
        "operation_id": operation_id,
        "direction": APPLET_TRANSACTION_DEFAULT_DIRECTION,
        "source_id": required_str(transaction, "source_id_header")?,
        "destination_id": required_str(transaction, "destination_id_header")?,
        "signature_label": required_str(transaction, "signature_label")?,
        "verification_method": required_str(transaction, "keyid")?,
        "verification_key_digest": required_str(transaction, "verification_key_digest")?,
        "signature_algorithm": required_str(transaction, "signature_algorithm")?,
        "registration_epoch": required_str_obj(active_install, "registration_epoch")?,
        "idempotency_key": required_str(transaction, "idempotency_key")?,
        "content_digest": required_str(transaction, "content_digest")?,
        "covered_components": string_vec(transaction, "covered_components")?,
        "created": required_u64(transaction, "created")?,
        "expires": required_u64(transaction, "expires")?,
    }))
}

fn delivery_authentication_record_digest(record: &Value) -> Result<String> {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(DELIVERY_AUTHENTICATION_RECORD_DOMAIN);
    hasher.update(arkret_canonical::canonical_json_bytes(record)?);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn applet_transaction_replay_identity(
    transaction: &Value,
    source_id: &str,
    destination_id: &str,
    idempotency_key: &str,
) -> Result<AppletTransactionReplayIdentity> {
    Ok(AppletTransactionReplayIdentity {
        operation_id: transaction
            .get("operation_id")
            .and_then(Value::as_str)
            .unwrap_or(arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1)
            .to_owned(),
        direction: transaction
            .get("direction")
            .and_then(Value::as_str)
            .unwrap_or(APPLET_TRANSACTION_DEFAULT_DIRECTION)
            .to_owned(),
        source_id: source_id.to_owned(),
        destination_id: destination_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
    })
}

fn covered_components_include_all(
    transaction: &Value,
    required_components: &BTreeSet<&str>,
) -> Result<bool> {
    let covered = string_set(transaction, "covered_components")?;
    Ok(required_components.is_subset(&covered))
}

fn run_calendar_rsvp_occurrence_key_case(case: &Value) -> Result<()> {
    let timezone = required_str(case, "timezone")?;
    let mut seen = BTreeSet::new();
    for occurrence in required_array(case, "occurrences")? {
        let name = required_str(occurrence, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_calendar_occurrence(occurrence, timezone)?;
        assert_expected_subset(name, expected(occurrence)?, &observed)?;
        record_step(
            VECTOR_ID_CALENDAR_RSVP_OCCURRENCE_KEY,
            name,
            occurrence,
            &observed,
        );
    }

    for required in [
        "dst_day_non_all_day",
        "next_day_same_wall_clock",
        "all_day_local_date",
    ] {
        if !seen.contains(required) {
            bail!("calendar RSVP vector missing occurrence {required}");
        }
    }

    let observed = evaluate_duplicate_rsvp_writes(case)?;
    assert_expected_subset("duplicate_rsvp_writes", expected(case)?, &observed)?;
    record_step(
        VECTOR_ID_CALENDAR_RSVP_OCCURRENCE_KEY,
        "duplicate_rsvp_writes",
        case,
        &observed,
    );
    Ok(())
}

fn evaluate_calendar_occurrence(occurrence: &Value, timezone: &str) -> Result<Value> {
    let local_start = required_str(occurrence, "local_start")?;
    let all_day = required_bool(occurrence, "all_day")?;
    // The schedule lives under one `calendar` namespace; flat keys at the
    // `metadata.fields` root are a rejected activation impostor.
    let mut calendar = serde_json::Map::new();
    calendar.insert("timezone".to_owned(), Value::String(timezone.to_owned()));
    calendar.insert("tzdb_version".to_owned(), Value::String("2025a".to_owned()));
    calendar.insert("all_day".to_owned(), Value::Bool(all_day));
    calendar.insert("status".to_owned(), Value::String("confirmed".to_owned()));
    // The interval is half-open, so a single all-day event ends on the
    // following date rather than repeating its start.
    let (start_value, end_value, probe) = if all_day {
        let date = local_start
            .get(..10)
            .ok_or_else(|| anyhow!("all-day local_start must include local date"))?;
        let parsed = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
            .map_err(|error| anyhow!("all-day local_start invalid: {error}"))?;
        let next = parsed + chrono::Duration::days(1);
        (
            date.to_owned(),
            next.format("%Y-%m-%d").to_string(),
            date.to_owned(),
        )
    } else {
        let start = chrono::NaiveDateTime::parse_from_str(local_start, "%Y-%m-%dT%H:%M:%S")
            .map_err(|error| anyhow!("non-all-day local_start invalid: {error}"))?;
        let end = start + chrono::Duration::hours(1);
        (
            local_start.to_owned(),
            end.format("%Y-%m-%dT%H:%M:%S").to_string(),
            format!("{local_start}[{timezone}]"),
        )
    };
    calendar.insert("start".to_owned(), Value::String(start_value));
    calendar.insert("end".to_owned(), Value::String(end_value));
    let mut fields = BTreeMap::new();
    fields.insert(
        arkret_models_collaboration::objects::productivity::CALENDAR_METADATA_FIELDS_NAMESPACE
            .to_owned(),
        Value::Object(calendar),
    );
    let occurrence_key =
        arkret_models_collaboration::objects::productivity::canonical_calendar_rsvp_occurrence_key(
            &fields,
            Some(&probe),
        )?
        .ok_or_else(|| anyhow!("instance occurrence must canonicalize to a key"))?;
    Ok(json!({"occurrence_key": occurrence_key}))
}

fn evaluate_duplicate_rsvp_writes(case: &Value) -> Result<Value> {
    // The no-op condition is byte equality of the whole entry, not equality of
    // status alone: a changed basis or comment is a different lattice value and
    // must stay a distinct head.
    let mut writes_by_actor_occurrence: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut duplicate_byte_equal_entry_noop = false;
    for write in required_array(case, "duplicate_rsvp_writes")? {
        let key = (
            required_str(write, "actor")?.to_owned(),
            required_str(write, "occurrence_key")?.to_owned(),
        );
        let entry = write
            .get("entry")
            .ok_or_else(|| anyhow!("duplicate rsvp write must carry the complete entry"))?;
        let canonical = arkret_canonical::canonical_json_string(entry)
            .map_err(|error| anyhow!("rsvp entry is not canonicalizable: {error}"))?;
        match writes_by_actor_occurrence.insert(key, canonical.clone()) {
            Some(previous) if previous == canonical => duplicate_byte_equal_entry_noop = true,
            Some(_) => duplicate_byte_equal_entry_noop = false,
            None => {}
        }
    }
    Ok(json!({
        "duplicate_byte_equal_entry_noop": duplicate_byte_equal_entry_noop
    }))
}

fn run_federation_timing_bucket_case(case: &Value) -> Result<()> {
    let observed = evaluate_federation_timing_bucket(case)?;
    assert_expected_subset("federation_timing_bucket", expected(case)?, &observed)?;
    record_step(
        VECTOR_ID_FEDERATION_TIMING_BUCKET,
        "failure_family",
        case,
        &observed,
    );
    Ok(())
}

fn evaluate_federation_timing_bucket(case: &Value) -> Result<Value> {
    let samples = required_array(case, "failure_samples")?;
    if samples.is_empty() {
        bail!("federation timing vector requires at least one failure sample");
    }

    let first = &samples[0];
    let first_status = required_u64(first, "status")?;
    let first_reason = required_str(first, "reason_code")?;
    let first_visible_fields = string_vec(first, "visible_fields")?;
    let mut p95_values = Vec::with_capacity(samples.len());
    let mut p99_values = Vec::with_capacity(samples.len());

    for sample in samples {
        p95_values.push(required_u64(sample, "p95_ms")?);
        p99_values.push(required_u64(sample, "p99_ms")?);
        if required_u64(sample, "status")? != first_status
            || required_str(sample, "reason_code")? != first_reason
            || string_vec(sample, "visible_fields")? != first_visible_fields
        {
            return Ok(json!({
                "public_shapes_identical": false,
                "p95_diff_ms": latency_diff(&p95_values),
                "p95_within_bucket": false,
                "p99_within_high_security_bucket": false,
            }));
        }
    }

    let p95_diff = latency_diff(&p95_values);
    let p99_diff = latency_diff(&p99_values);
    Ok(json!({
        "public_shapes_identical": true,
        "p95_diff_ms": p95_diff,
        "p95_within_bucket": p95_diff <= 50,
        "p99_within_high_security_bucket": p99_diff <= 50,
    }))
}

fn latency_diff(values: &[u64]) -> u64 {
    let min = values.iter().copied().min().unwrap_or(0);
    let max = values.iter().copied().max().unwrap_or(0);
    max.saturating_sub(min)
}

/// Typed results whose change moves the MLS key-access revision: they change
/// which leaves may hold the group's keys. Ordinary governance, message
/// metadata, grants and roster display never do.
/// Only a membership change on the scope's own stream advances the
/// key-access revision; endpoint key revocations are refused at the send gate.
const KEY_ACCESS_BEARING_RESULTS: &[&str] = &["member_key_access"];

/// Send-gate refusal of a revoked endpoint's own encrypted send, per
/// revoked key kind (encryption-and-audit.md §2.5.2).
fn revoked_endpoint_send_code(scenario: &Value) -> Result<&'static str> {
    let changed = required_array(scenario, "changed_results")?;
    match changed
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["device_key"] => Ok("device_revoked"),
        ["agent_key"] => Ok("capability_denied"),
        other => bail!("endpoint revoke case must change exactly one endpoint key: {other:?}"),
    }
}

fn key_access_revision_changed(scenario: &Value) -> Result<bool> {
    let changed = scenario
        .get("changed_results")
        .map(|_| required_array(scenario, "changed_results"))
        .transpose()?
        .unwrap_or_default();
    Ok(changed
        .iter()
        .filter_map(Value::as_str)
        .any(|result| KEY_ACCESS_BEARING_RESULTS.contains(&result)))
}

fn run_mls_key_access_revision_cases(fixture: &FinalConformanceClosureFixture) -> Result<()> {
    let rows = fixture
        .cases
        .iter()
        .filter(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(VECTOR_ID_MLS_KEY_ACCESS_REVISION)
        })
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    for row in &rows {
        let scenarios = match (row.get("cases"), row.get("samples")) {
            (Some(_), None) => required_array(row, "cases")?,
            (None, Some(_)) => required_array(row, "samples")?,
            _ => bail!("key-access revision row must carry exactly one of cases or samples"),
        };
        for scenario in scenarios {
            let name = required_str(scenario, "name")?;
            seen.insert(name.to_owned());
            let changed = key_access_revision_changed(scenario)?;
            let observed = match name {
                "valid_key_access_revision_commit" => {
                    let current = scenario
                        .get("key_access_revision_matches_accepted_key_access_state")
                        .and_then(Value::as_bool)
                        == Some(true);
                    json!({
                        "decision": if current { "accept" } else { "reject" },
                        "mls_epoch_result_advanced": current,
                        "active_epoch_advanced": current,
                    })
                }
                "unrelated_governance_and_new_commit_ref"
                | "membership_change_without_key_access_effect" => json!({
                    "decision": if changed { "reject" } else { "accept" },
                    "key_access_revision_changed": changed,
                }),
                "membership_change_pauses_sending" => {
                    if changed {
                        json!({
                            "decision": "reject",
                            "reason": "epoch_update_required",
                            "key_access_revision_changed": true,
                            "self_heal_commit_required": true,
                        })
                    } else {
                        json!({"decision": "accept", "key_access_revision_changed": false})
                    }
                }
                "device_revoke_refuses_only_the_revoked_sender"
                | "agent_key_revoke_refuses_only_the_revoked_sender" => json!({
                    "key_access_revision_changed": changed,
                    "other_member_send_decision": if changed { "reject" } else { "accept" },
                    "revoked_endpoint_send_decision": "reject",
                    "revoked_endpoint_send_code": revoked_endpoint_send_code(scenario)?,
                    "self_heal_commit_required": changed,
                }),
                // Authorization is decided by current membership, never by the
                // key-access revision, and a membership rejection is not an
                // MLS reason.
                "current_revision_does_not_authorize_a_non_member_producer" => {
                    if required_bool(scenario, "producer_current_authorized")? {
                        json!({"decision": "accept", "mls_reason_emitted": false})
                    } else {
                        json!({
                            "decision": "reject",
                            "reason": "not_member",
                            "mls_reason_emitted": false,
                        })
                    }
                }
                "advanced_revision_admits_nobody_by_itself" => json!({
                    "decision": "accept",
                    "membership_admitted_by_revision":
                        required_bool(scenario, "membership_decision_changed")?,
                }),
                other => bail!("unknown MLS key-access revision closure case {other}"),
            };
            assert_expected_subset(name, expected(scenario)?, &observed)?;
            record_step(VECTOR_ID_MLS_KEY_ACCESS_REVISION, name, scenario, &observed);
        }
    }
    for required in [
        "valid_key_access_revision_commit",
        "unrelated_governance_and_new_commit_ref",
        "membership_change_pauses_sending",
        "device_revoke_refuses_only_the_revoked_sender",
        "agent_key_revoke_refuses_only_the_revoked_sender",
        "membership_change_without_key_access_effect",
        "current_revision_does_not_authorize_a_non_member_producer",
        "advanced_revision_admits_nobody_by_itself",
    ] {
        if !seen.contains(required) {
            bail!("MLS key-access revision closure vector missing case {required}");
        }
    }
    Ok(())
}

/// Standard proposal types a member sender may carry.
const MEMBER_PROPOSAL_TYPES: &[&str] = &[
    "add",
    "update",
    "remove",
    "psk",
    "reinit",
    "group_context_extensions",
];
/// RFC 9420 `external_senders` GroupContext extension code point.
const EXTERNAL_SENDERS_EXTENSION: &str = "0x0004";

fn proposal_rejection(reason_code: &str) -> Value {
    json!({
        "decision": "reject",
        "reason_code": reason_code,
        "durable_proposal_written": false,
    })
}

fn evaluate_proposal_producer_binding(scenario: &Value) -> Result<Value> {
    if let Some(kind) = scenario.get("transition_kind").and_then(Value::as_str) {
        let staged = required_str(scenario, "staged_group_context_extension")?;
        if kind != "ak.mls.commit" {
            bail!("unexpected MLS transition kind {kind}");
        }
        return Ok(if staged == EXTERNAL_SENDERS_EXTENSION {
            json!({
                "decision": "reject",
                "reason_code": "unsupported_feature",
                "active_epoch_advanced": false,
            })
        } else {
            json!({"decision": "accept", "active_epoch_advanced": true})
        });
    }
    // External senders, self-add proposals and external commits are not a
    // supported producer class; they are an unsupported feature, never a
    // schema violation, whatever else the proposal carries.
    if required_str(scenario, "sender_class")? != "member" {
        return Ok(proposal_rejection("unsupported_feature"));
    }
    let types = match scenario.get("proposal_types") {
        Some(_) => required_array(scenario, "proposal_types")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| anyhow!("proposal type must be a string"))
            })
            .collect::<Result<Vec<_>>>()?,
        None => vec![required_str(scenario, "proposal_type")?],
    };
    if types
        .iter()
        .any(|proposal_type| !MEMBER_PROPOSAL_TYPES.contains(proposal_type))
    {
        return Ok(proposal_rejection("unsupported_feature"));
    }
    if !required_bool(scenario, "sender_leaf_occupied_in_exact_base")? {
        return Ok(proposal_rejection("failed_precondition"));
    }
    if !required_bool(scenario, "leaf_credential_equals_verified_producer")? {
        return Ok(proposal_rejection("signature_invalid"));
    }
    Ok(json!({"decision": "accept", "durable_proposal_written": true}))
}

fn run_mls_proposal_producer_binding_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "cases")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_proposal_producer_binding(scenario)?;
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(
            VECTOR_ID_MLS_PROPOSAL_PRODUCER_BINDING,
            name,
            scenario,
            &observed,
        );
    }
    for required in [
        "member_remove_bound_to_verified_producer",
        "member_standard_types_remain_admissible",
        "external_sender_configured_and_authorized",
        "new_member_proposal_self_add",
        "external_init_decoded_before_declared_token_mismatch",
        "app_custom_codepoint_not_registered",
        "member_leaf_absent_from_exact_base",
        "member_leaf_credential_not_verified_producer",
        "transition_installs_external_senders_extension",
    ] {
        if !seen.contains(required) {
            bail!("MLS proposal producer binding vector missing case {required}");
        }
    }
    Ok(())
}

/// Strictness order of active moderation verdicts; the effective verdict is
/// the strictest active one, never a split.
fn moderation_strictness(verdict: &str) -> Result<u8> {
    Ok(match verdict {
        "none" => 0,
        "require_review" => 1,
        "quarantine" => 2,
        "hard_deny" => 3,
        other => bail!("unknown moderation verdict {other}"),
    })
}

fn strictest(verdicts: &[&str]) -> Result<String> {
    let mut best = "none";
    for verdict in verdicts {
        if moderation_strictness(verdict)? > moderation_strictness(best)? {
            best = verdict;
        }
    }
    Ok(best.to_owned())
}

fn evaluate_review_resolution(scenario: &Value) -> Result<Value> {
    if scenario
        .get("same_add_identity_conflicting_canonical_bytes")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Ok(json!({
            "decision": "fail_closed",
            "reason": "moderation_state_conflict",
            "moderation_control_split": true,
        }));
    }
    let active = required_array(scenario, "active_decisions")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| anyhow!("decision must be a string"))
        })
        .collect::<Result<Vec<_>>>()?;
    let effective = strictest(&active)?;
    let Some(lifts) = scenario
        .get("same_batch_review_lifts")
        .and_then(Value::as_u64)
    else {
        return Ok(json!({
            "effective_verdict": effective,
            "moderation_control_split": false,
            "candidate_effective": effective == "none",
        }));
    };
    let reviews = active
        .iter()
        .filter(|verdict| **verdict == "require_review")
        .count() as u64;
    // A resolution lifts every active review gate in one batch or nothing.
    if lifts != reviews {
        return Ok(json!({
            "decision": "reject",
            "effective_verdict": effective,
            "partial_state_written": false,
        }));
    }
    let mut remaining = active
        .iter()
        .copied()
        .filter(|verdict| *verdict != "require_review")
        .collect::<Vec<_>>();
    let replacement = scenario
        .get("same_batch_replacement")
        .and_then(Value::as_str);
    if let Some(replacement) = replacement {
        moderation_strictness(replacement)?;
        remaining.push(replacement);
    }
    let after = strictest(&remaining)?;
    Ok(json!({
        "decision": "accept",
        "effective_verdict_after_batch": after,
        // Lifting review never auto-accepts the candidate; it re-enters the
        // current authorization check.
        "candidate_auto_accepted": false,
        "current_authz_recheck_required": replacement.is_none(),
        "review_decision_active": false,
        "replacement_decision_active": replacement.is_some(),
    }))
}

fn run_moderation_review_resolution_fold_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "cases")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_review_resolution(scenario)?;
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(
            VECTOR_ID_MODERATION_REVIEW_RESOLUTION_FOLD,
            name,
            scenario,
            &observed,
        );
    }
    for required in [
        "two_review_adds_are_joinable",
        "quarantine_is_stricter_than_review",
        "allow_lifts_all_review_adds",
        "partial_review_lift_rejected",
        "deny_replacement_is_atomic",
        "same_add_identity_different_bytes_is_split",
    ] {
        if !seen.contains(required) {
            bail!("moderation review resolution fold vector missing case {required}");
        }
    }
    Ok(())
}

fn run_moderation_franking_roundtrip_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "cases")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_moderation_franking_roundtrip(scenario)?;
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(
            VECTOR_ID_MODERATION_FRANKING_ROUNDTRIP,
            name,
            scenario,
            &observed,
        );
    }
    for required in [
        "roundtrip_valid",
        "target_event_commitment_mismatch",
        "unknown_field_violation",
    ] {
        if !seen.contains(required) {
            bail!("moderation franking vector missing case {required}");
        }
    }
    Ok(())
}

fn evaluate_moderation_franking_roundtrip(scenario: &Value) -> Result<Value> {
    let unexpected_fields = string_set(scenario, "unexpected_fields")?;
    let evidence_forbidden_secret_fields = scenario
        .get("evidence_forbidden_secret_fields")
        .and_then(Value::as_array)
        .is_some_and(|fields| !fields.is_empty());

    if !unexpected_fields.is_empty()
        || required_bool(scenario, "proof_contains_plaintext_body")?
        || evidence_forbidden_secret_fields
    {
        return Ok(json!({"decision": "reject", "reason": "schema_violation"}));
    }
    if !required_bool(scenario, "target_event_content_commitment_matches")?
        || !required_bool(scenario, "franking_signature_matches")?
        || !required_bool(scenario, "durable_proof_event_matches")?
        // Renamed with the move to scoped Seals: the condition is now that
        // the Event has a valid existence anchor, not that a covering Seal was
        // observed.
        || !required_bool(scenario, "existence_anchor_valid")?
    {
        return Ok(json!({
            "decision": "manual_clue_only",
            "verifiable_delivery_proof": false,
        }));
    }
    Ok(json!({
        "decision": "verifiable_delivery_proof",
        "governance_key_released": false,
    }))
}

fn run_moderation_evidence_package_minimal_disclosure_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "cases")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_moderation_evidence_package(scenario)?;
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(
            VECTOR_ID_MODERATION_EVIDENCE_PACKAGE_MINIMAL_DISCLOSURE,
            name,
            scenario,
            &observed,
        );
    }
    for required in [
        "targeted_encrypted_package_valid",
        "unrelated_message_plaintext_rejected",
        "recipient_binding_missing_rejected",
    ] {
        if !seen.contains(required) {
            bail!("moderation evidence-package vector missing case {required}");
        }
    }
    Ok(())
}

fn evaluate_moderation_evidence_package(scenario: &Value) -> Result<Value> {
    let target_refs = string_set(scenario, "target_refs")?;
    if target_refs.is_empty() {
        return Ok(json!({"decision": "reject", "reason": "schema_violation"}));
    }
    if required_str(scenario, "recipient_public_key_ref")?
        != required_str(scenario, "encrypted_to")?
    {
        return Ok(json!({"decision": "reject", "reason": "evidence_recipient_mismatch"}));
    }
    if !required_bool(scenario, "reporter_signature_present")? {
        return Ok(json!({"decision": "reject", "reason": "schema_violation"}));
    }

    let forbidden_material = string_set(scenario, "forbidden_material")?;
    if !forbidden_material.is_empty() {
        return Ok(json!({"decision": "reject", "reason": "schema_violation"}));
    }

    let plaintext_event_refs = string_set(scenario, "plaintext_event_refs")?;
    if !plaintext_event_refs.is_subset(&target_refs) {
        return Ok(json!({
            "decision": "reject",
            "reason": "minimal_disclosure_violation",
        }));
    }

    let included_material = string_set(scenario, "included_material")?;
    if !(included_material.contains("encrypted_envelope")
        && included_material.contains("franking_proof"))
    {
        return Ok(json!({"decision": "reject", "reason": "schema_violation"}));
    }

    Ok(json!({
        "decision": "accept",
        "minimal_disclosure": true,
        "governance_key_released": false,
    }))
}

fn run_relation_reference_projection_indistinguishable_case(case: &Value) -> Result<()> {
    let observed = evaluate_relation_reference_projection_indistinguishable(case)?;
    assert_expected_subset(
        "relation_reference_projection_indistinguishable",
        expected(case)?,
        &observed,
    )?;
    record_step(
        VECTOR_ID_RELATION_REFERENCE_PROJECTION_INDISTINGUISHABLE,
        "caller_locked_views",
        case,
        &observed,
    );
    Ok(())
}

fn evaluate_relation_reference_projection_indistinguishable(case: &Value) -> Result<Value> {
    let caller_views = required_array(case, "caller_views")?;
    if caller_views.len() < 2 {
        bail!("relation projection vector requires at least two caller views");
    }

    let first_visible_fields = string_vec(&caller_views[0], "visible_fields")?;
    let first_projection_status = required_str(&caller_views[0], "projection_status")?;
    let first_raw_event_view = required_str(&caller_views[0], "raw_event_view")?;
    let mut p95_values = Vec::with_capacity(caller_views.len());
    let mut caller_shapes_identical = true;
    let mut raw_views_identical = true;
    let forbidden_fields = string_set(case, "forbidden_fields")?;
    let mut forbidden_fields_present = false;

    for view in caller_views {
        let visible_fields = string_vec(view, "visible_fields")?;
        if required_str(view, "projection_status")? != first_projection_status
            || visible_fields != first_visible_fields
        {
            caller_shapes_identical = false;
        }
        if required_str(view, "raw_event_view")? != first_raw_event_view {
            raw_views_identical = false;
        }
        forbidden_fields_present |= visible_fields
            .iter()
            .any(|field| forbidden_fields.contains(field.as_str()));
        p95_values.push(required_u64(view, "p95_ms")?);
    }

    let auditor_view = required_object(case, "auditor_view")?;
    let auditor_changes_caller_shape = auditor_view
        .get("has_full_canonical_bytes")
        .and_then(Value::as_bool)
        != Some(true)
        || !caller_shapes_identical;
    let p95_diff = latency_diff(&p95_values);

    Ok(json!({
        "caller_shapes_identical": caller_shapes_identical,
        "forbidden_fields_present": forbidden_fields_present,
        "raw_views_identical": raw_views_identical,
        "p95_diff_ms": p95_diff,
        "p95_within_bucket": p95_diff <= 50,
        "auditor_changes_caller_shape": auditor_changes_caller_shape,
    }))
}

fn record_step(vector_id: &str, name: &str, input: &Value, observed: &Value) {
    let expected = input.get("expected").cloned().unwrap_or_else(|| json!({}));
    record_vector_event(
        &format!("final_conformance_closure.{name}"),
        &json!({"vector_id": vector_id, "input": input}),
        &expected,
        observed,
    );
}
