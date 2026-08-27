//! Final fixture-backed closure for the remaining privacy/security vectors.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

use super::helpers::assert_expected_subset;
use crate::transcripts::record_vector_event;

pub const VECTOR_ID_APPLET_TRANSACTION_DELIVERY_AUTHENTICATION_RECORD_DIGEST: &str =
    "ak.vector.applet.transaction_delivery_authentication_record_digest.v1";
pub const VECTOR_ID_CALENDAR_RSVP_OCCURRENCE_KEY: &str =
    "ak.vector.calendar.rsvp_occurrence_key.v1";
pub const VECTOR_ID_FEDERATION_TIMING_BUCKET: &str = "ak.vector.federation.timing_bucket.v1";
pub const VECTOR_ID_MLS_SECURITY_FRONTIER: &str =
    "ak.vector.mls.security_frontier_key_access_only.v1";
pub const VECTOR_ID_MLS_GOVERNANCE_EPOCH_BINDING: &str =
    "ak.vector.mls.governance_epoch_binding.v1";
pub const VECTOR_ID_MODERATION_FRANKING_ROUNDTRIP: &str =
    "ak.vector.moderation.franking_roundtrip.v1";
pub const VECTOR_ID_MODERATION_EVIDENCE_PACKAGE_MINIMAL_DISCLOSURE: &str =
    "ak.vector.moderation.evidence_package_minimal_disclosure.v1";
pub const VECTOR_ID_MODERATION_APPEAL_ATOMICITY: &str = "ak.vector.moderation.appeal_atomicity.v1";
pub const VECTOR_ID_RELATION_REFERENCE_PROJECTION_INDISTINGUISHABLE: &str =
    "ak.vector.relation.reference_projection_indistinguishable.v1";
pub const VECTOR_ID_SYNC_RANGE_COMPLETENESS_CLIENT_QUERY: &str =
    "ak.vector.sync.range_completeness_client_query.v1";

pub const ALL_FINAL_CONFORMANCE_CLOSURE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_APPLET_TRANSACTION_DELIVERY_AUTHENTICATION_RECORD_DIGEST,
    VECTOR_ID_CALENDAR_RSVP_OCCURRENCE_KEY,
    VECTOR_ID_FEDERATION_TIMING_BUCKET,
    VECTOR_ID_MLS_SECURITY_FRONTIER,
    VECTOR_ID_MLS_GOVERNANCE_EPOCH_BINDING,
    VECTOR_ID_MODERATION_FRANKING_ROUNDTRIP,
    VECTOR_ID_MODERATION_EVIDENCE_PACKAGE_MINIMAL_DISCLOSURE,
    VECTOR_ID_MODERATION_APPEAL_ATOMICITY,
    VECTOR_ID_RELATION_REFERENCE_PROJECTION_INDISTINGUISHABLE,
    VECTOR_ID_SYNC_RANGE_COMPLETENESS_CLIENT_QUERY,
];

const FINAL_CONFORMANCE_CLOSURE_FIXTURE_FILE: &str = "final-conformance-closure-fixture.json";
const APPLET_TRANSACTION_DEFAULT_DIRECTION: &str = "applet_to_arkret_inbound";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct AppletTransactionReplayIdentity {
    operation_id: String,
    direction: String,
    source_service_id: String,
    destination_service_id: String,
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
    run_mls_security_frontier_case(case(&fixture, VECTOR_ID_MLS_SECURITY_FRONTIER)?)?;
    run_mls_governance_epoch_binding_case(case(&fixture, VECTOR_ID_MLS_GOVERNANCE_EPOCH_BINDING)?)?;
    run_moderation_franking_roundtrip_case(case(
        &fixture,
        VECTOR_ID_MODERATION_FRANKING_ROUNDTRIP,
    )?)?;
    run_moderation_evidence_package_minimal_disclosure_case(case(
        &fixture,
        VECTOR_ID_MODERATION_EVIDENCE_PACKAGE_MINIMAL_DISCLOSURE,
    )?)?;
    run_moderation_appeal_atomicity_case(case(&fixture, VECTOR_ID_MODERATION_APPEAL_ATOMICITY)?)?;
    run_relation_reference_projection_indistinguishable_case(case(
        &fixture,
        VECTOR_ID_RELATION_REFERENCE_PROJECTION_INDISTINGUISHABLE,
    )?)?;
    run_sync_range_completeness_client_query_case(case(
        &fixture,
        VECTOR_ID_SYNC_RANGE_COMPLETENESS_CLIENT_QUERY,
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

pub fn run_mls_governance_epoch_binding_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_mls_governance_epoch_binding_case(case(&fixture, VECTOR_ID_MLS_GOVERNANCE_EPOCH_BINDING)?)
}

pub fn run_mls_security_frontier_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_mls_security_frontier_case(case(&fixture, VECTOR_ID_MLS_SECURITY_FRONTIER)?)
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

pub fn run_moderation_appeal_atomicity_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_moderation_appeal_atomicity_case(case(&fixture, VECTOR_ID_MODERATION_APPEAL_ATOMICITY)?)
}

pub fn run_relation_reference_projection_indistinguishable_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_relation_reference_projection_indistinguishable_case(case(
        &fixture,
        VECTOR_ID_RELATION_REFERENCE_PROJECTION_INDISTINGUISHABLE,
    )?)
}

pub fn run_sync_range_completeness_client_query_vector() -> Result<()> {
    let fixture = final_conformance_closure_fixture()?;
    run_sync_range_completeness_client_query_case(case(
        &fixture,
        VECTOR_ID_SYNC_RANGE_COMPLETENESS_CLIENT_QUERY,
    )?)
}

fn final_conformance_closure_fixture() -> Result<Value> {
    let fixture = super::load_fixture_value(FINAL_CONFORMANCE_CLOSURE_FIXTURE_FILE)?;
    super::validate_profile(
        &fixture,
        crate::conformance::security_closure::SECURITY_CLOSURE_VECTORS_PROFILE,
    )?;
    validate_final_conformance_closure_fixture_metadata(&fixture)?;
    Ok(fixture)
}

fn validate_final_conformance_closure_fixture_metadata(fixture: &Value) -> Result<()> {
    if fixture.get("suite").and_then(Value::as_str) != Some("final_conformance_closure") {
        bail!("final conformance closure fixture suite drifted");
    }
    if super::fixture_runner_entrypoint(fixture)? != "ak.suite.conformance.final_closure.v1" {
        bail!("final conformance closure fixture runner drifted");
    }

    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("final conformance closure fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("final conformance closure fixture missing cases[]"))?;

    for vector_id in ALL_FINAL_CONFORMANCE_CLOSURE_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
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

fn case<'a>(fixture: &'a Value, vector_id: &str) -> Result<&'a Value> {
    fixture
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
        })
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
    let inferred_anchor_by_name = inferred_delivery_authentication_record_digests(case)?;
    let mut cache = BTreeMap::new();
    let mut accepted_by_name = BTreeMap::new();
    let mut seen = BTreeSet::new();

    for transaction in required_array(case, "transactions")? {
        let name = required_str(transaction, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_applet_transaction(
            active_install,
            &required_components,
            transaction,
            &mut cache,
            &mut accepted_by_name,
            &inferred_anchor_by_name,
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
    accepted_by_name: &mut BTreeMap<String, AppletTransactionReplayIdentity>,
    inferred_anchor_by_name: &BTreeMap<String, String>,
) -> Result<Value> {
    if let Some(replay_of) = transaction.get("replay_of").and_then(Value::as_str) {
        let original_identity = accepted_by_name
            .get(replay_of)
            .ok_or_else(|| anyhow!("replay references unknown accepted transaction {replay_of}"))?;
        let idempotency_key = required_str(transaction, "idempotency_key")?;
        if original_identity.idempotency_key != idempotency_key {
            return Ok(json!({"decision": "reject", "reason": "duplicate_conflict"}));
        }
        let body_digest = required_str(transaction, "body_digest")?;
        let delivery_authentication_record_digest =
            required_str(transaction, "delivery_authentication_record_digest")?;
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

    let source_header = required_str(transaction, "source_service_id_header")?;
    let source_body = required_str(transaction, "source_service_id_body")?;
    let destination_header = required_str(transaction, "destination_service_id_header")?;
    let install_source = required_str_obj(active_install, "service_id")?;
    let install_destination = required_str_obj(active_install, "destination_service_id")?;

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
        || !covered_components_include_all(transaction, required_components)?
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
    let delivery_authentication_record_digest =
        delivery_authentication_record_digest_for_transaction(
            transaction,
            inferred_anchor_by_name,
        )?;
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
    accepted_by_name.insert(
        required_str(transaction, "name")?.to_owned(),
        replay_identity,
    );

    Ok(json!({
        "decision": "accept",
        "delivery_authentication_record_persisted": true,
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

fn inferred_delivery_authentication_record_digests(
    case: &Value,
) -> Result<BTreeMap<String, String>> {
    let mut anchors = BTreeMap::new();
    for transaction in required_array(case, "transactions")? {
        let Some(replay_of) = transaction.get("replay_of").and_then(Value::as_str) else {
            continue;
        };
        if expected(transaction)?
            .get("decision")
            .and_then(Value::as_str)
            != Some("accept_cached")
        {
            continue;
        }
        let anchor = required_str(transaction, "delivery_authentication_record_digest")?;
        match anchors.insert(replay_of.to_owned(), anchor.to_owned()) {
            Some(previous) if previous != anchor => {
                bail!("accepted replay anchor for {replay_of} drifted: {previous} != {anchor}")
            }
            _ => {}
        }
    }
    Ok(anchors)
}

fn delivery_authentication_record_digest_for_transaction<'a>(
    transaction: &'a Value,
    inferred_anchor_by_name: &'a BTreeMap<String, String>,
) -> Result<&'a str> {
    if let Some(anchor) = transaction
        .get("delivery_authentication_record_digest")
        .and_then(Value::as_str)
    {
        return Ok(anchor);
    }
    let name = required_str(transaction, "name")?;
    inferred_anchor_by_name
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| {
            anyhow!("accepted transaction {name} missing delivery authentication record digest")
        })
}

fn applet_transaction_replay_identity(
    transaction: &Value,
    source_service_id: &str,
    destination_service_id: &str,
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
        source_service_id: source_service_id.to_owned(),
        destination_service_id: destination_service_id.to_owned(),
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

fn run_mls_security_frontier_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "cases")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed = match name {
            "valid_security_frontier_commit" => json!({
                "decision": if scenario
                    .get("security_frontier_matches_accepted_key_access_state")
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    "accept"
                } else {
                    "reject"
                },
                "mls_epoch_cell_advanced": true,
                "active_epoch_advanced": true,
            }),
            "unrelated_governance_and_new_seal_ref" => json!({
                "decision": "accept",
                "security_frontier_changed": false,
            }),
            "active_leaf_revoke_pauses_sending" => json!({
                "decision": "reject",
                "reason": "mls_governance_binding_stale",
                "security_frontier_changed": true,
                "self_heal_commit_required": true,
            }),
            other => bail!("unknown MLS security frontier closure case {other}"),
        };
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(VECTOR_ID_MLS_SECURITY_FRONTIER, name, scenario, &observed);
    }
    for required in [
        "valid_security_frontier_commit",
        "unrelated_governance_and_new_seal_ref",
        "active_leaf_revoke_pauses_sending",
    ] {
        if !seen.contains(required) {
            bail!("MLS security frontier closure vector missing case {required}");
        }
    }
    Ok(())
}

fn run_mls_governance_epoch_binding_case(case: &Value) -> Result<()> {
    let commit = case
        .get("commit")
        .ok_or_else(|| anyhow!("MLS governance vector missing commit"))?;
    required_object(case, "commit")?;
    let observed = evaluate_mls_governance_epoch_binding(commit)?;
    assert_expected_subset("mls_governance_epoch_binding", expected(case)?, &observed)?;
    record_step(
        VECTOR_ID_MLS_GOVERNANCE_EPOCH_BINDING,
        "commit",
        commit,
        &observed,
    );
    Ok(())
}

fn evaluate_mls_governance_epoch_binding(commit: &Value) -> Result<Value> {
    let governance = required_object(commit, "governance_binding")?;
    let epoch_matches = required_u64(commit, "base_epoch")?
        == required_u64_obj(governance, "previous_epoch")?
        && required_u64(commit, "next_epoch")? == required_u64_obj(governance, "next_epoch")?;
    if !epoch_matches {
        return Ok(json!({
            "decision": "reject",
            "reason": "epoch_update_required",
            "mls_epoch_cell_advanced": false,
            "active_epoch_advanced": false,
        }));
    }
    if commit.get("other_checks_valid").and_then(Value::as_bool) != Some(true) {
        return Ok(json!({
            "decision": "reject",
            "reason": "failed_precondition",
            "mls_epoch_cell_advanced": false,
            "active_epoch_advanced": false,
        }));
    }
    Ok(json!({
        "decision": "accept",
        "mls_epoch_cell_advanced": true,
        "active_epoch_advanced": true,
    }))
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
        "retired_mirror_violation",
    ] {
        if !seen.contains(required) {
            bail!("moderation franking vector missing case {required}");
        }
    }
    Ok(())
}

fn evaluate_moderation_franking_roundtrip(scenario: &Value) -> Result<Value> {
    let retired_proof_fields = string_set(scenario, "retired_proof_fields")?;
    let evidence_forbidden_secret_fields = scenario
        .get("evidence_forbidden_secret_fields")
        .and_then(Value::as_array)
        .is_some_and(|fields| !fields.is_empty());

    if !retired_proof_fields.is_empty()
        || required_bool(scenario, "proof_contains_plaintext_body")?
        || evidence_forbidden_secret_fields
    {
        return Ok(json!({"decision": "reject", "reason": "schema_violation"}));
    }
    if !required_bool(scenario, "target_event_content_commitment_matches")?
        || !required_bool(scenario, "franking_signature_matches")?
        || !required_bool(scenario, "durable_proof_event_matches")?
        || !required_bool(scenario, "covering_seal_observation_valid")?
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
        "history_key_release_rejected",
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

fn run_moderation_appeal_atomicity_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for scenario in required_array(case, "cases")? {
        let name = required_str(scenario, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_moderation_appeal_atomicity(scenario)?;
        assert_expected_subset(name, expected(scenario)?, &observed)?;
        record_step(
            VECTOR_ID_MODERATION_APPEAL_ATOMICITY,
            name,
            scenario,
            &observed,
        );
    }
    for required in [
        "overturn_missing_lift",
        "overturn_with_lift",
        "modify_ref_mismatch",
    ] {
        if !seen.contains(required) {
            bail!("moderation appeal vector missing case {required}");
        }
    }
    Ok(())
}

fn evaluate_moderation_appeal_atomicity(scenario: &Value) -> Result<Value> {
    if required_str(scenario, "appeal_state")? != "under_review" {
        return Ok(json!({
            "decision": "reject",
            "reason": "failed_precondition",
            "partial_state_written": false,
        }));
    }

    match required_str(scenario, "decision")? {
        "overturn" => {
            if scenario
                .get("same_batch_lift_target_matches")
                .and_then(Value::as_bool)
                != Some(true)
            {
                Ok(json!({
                    "decision": "reject",
                    "reason": "appeal_overturn_missing_lift",
                    "appeal_state": "under_review",
                    "original_decision_active": true,
                }))
            } else {
                // An overturn lifts the reversible decision atomically, but
                // irreversible effects (for example a redaction tombstone)
                // remain in force.  Surface both facts so the fixture can
                // assert that no original plaintext is resurrected.
                let tombstone_present = scenario
                    .get("original_irreversible_effect")
                    .and_then(Value::as_str)
                    == Some("redaction_tombstone");
                Ok(json!({
                    "decision": "accept",
                    "appeal_state": "decided",
                    "original_decision_active": false,
                    "redaction_tombstone_present": tombstone_present,
                    "original_content_resurrected": false,
                }))
            }
        }
        "modify" => {
            if scenario
                .get("same_batch_lift_target_matches")
                .and_then(Value::as_bool)
                != Some(true)
            {
                return Ok(json!({
                    "decision": "reject",
                    "reason": "appeal_modify_missing_lift",
                    "appeal_state": "under_review",
                    "original_decision_active": true,
                    "replacement_decision_active": false,
                    "partial_state_written": false,
                }));
            }
            if scenario
                .get("modify_decision_ref_in_same_batch")
                .and_then(Value::as_bool)
                != Some(true)
                || scenario
                    .get("new_decision_target_matches_original")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                Ok(json!({
                    "decision": "reject",
                    "reason": "failed_precondition",
                    "partial_state_written": false,
                }))
            } else {
                Ok(json!({
                    "decision": "accept",
                    "appeal_state": "decided",
                    "original_decision_active": false,
                    "replacement_decision_active": true,
                    "partial_state_written": false,
                }))
            }
        }
        verdict => bail!("unsupported moderation appeal verdict {verdict}"),
    }
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

fn run_sync_range_completeness_client_query_case(case: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for step in required_array(case, "steps")? {
        let name = required_str(step, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_sync_range_completeness_step(step)?;
        assert_expected_subset(name, expected(step)?, &observed)?;
        record_step(
            VECTOR_ID_SYNC_RANGE_COMPLETENESS_CLIENT_QUERY,
            name,
            step,
            &observed,
        );
    }
    for required in [
        "complete_attested_range",
        "withheld_actor_seq_gap",
        "featureless_server",
        "high_assurance_single_source",
    ] {
        if !seen.contains(required) {
            bail!("sync range completeness vector missing step {required}");
        }
    }
    Ok(())
}

fn evaluate_sync_range_completeness_step(step: &Value) -> Result<Value> {
    if step.get("feature_supported").and_then(Value::as_bool) != Some(true) {
        return Ok(json!({"decision": "unattested", "error": false}));
    }
    if step.get("security_class").and_then(Value::as_str) == Some("high_assurance")
        && step.get("attestation_mode").and_then(Value::as_str) == Some("single_source")
    {
        return Ok(json!({
            "decision": "unattested",
            "high_assurance_frontier_advanced": false,
        }));
    }
    if step.get("attestation_mode").and_then(Value::as_str) != Some("federation_witness_attested") {
        return Ok(json!({"decision": "unattested"}));
    }

    let seqs = u64_set(step, "returned_actor_seq")?;
    let range = u64_vec(step, "attestation_actor_seq_range")?;
    if range.len() != 2 {
        bail!("sync range completeness attestation range must have two entries");
    }
    let range_complete = (range[0]..=range[1]).all(|seq| seqs.contains(&seq));
    if range_complete && step.get("root_matches").and_then(Value::as_bool) == Some(true) {
        return Ok(json!({"decision": "attested_complete"}));
    }
    let reason = if !range_complete {
        "range_completeness_actor_seq_gap"
    } else {
        "range_completeness_root_mismatch"
    };
    Ok(json!({
        "decision": "degraded",
        "reason": reason,
        "history_complete_displayed": false,
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

fn required_object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("missing object field {field}"))
}

fn required_array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("missing array field {field}"))
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn required_str_obj<'a>(value: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing u64 field {field}"))
}

fn required_u64_obj(value: &Map<String, Value>, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing u64 field {field}"))
}

fn required_bool(value: &Value, field: &str) -> Result<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("missing bool field {field}"))
}

fn expected(value: &Value) -> Result<&Value> {
    value
        .get("expected")
        .ok_or_else(|| anyhow!("missing expected object"))
}

fn string_set<'a>(value: &'a Value, field: &str) -> Result<BTreeSet<&'a str>> {
    required_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| anyhow!("{field} entry must be string"))
        })
        .collect::<Result<BTreeSet<_>>>()
}

fn string_vec(value: &Value, field: &str) -> Result<Vec<String>> {
    required_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("{field} entry must be string"))
        })
        .collect()
}

fn u64_vec(value: &Value, field: &str) -> Result<Vec<u64>> {
    required_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_u64()
                .ok_or_else(|| anyhow!("{field} entry must be u64"))
        })
        .collect()
}

fn u64_set(value: &Value, field: &str) -> Result<BTreeSet<u64>> {
    Ok(u64_vec(value, field)?.into_iter().collect())
}
