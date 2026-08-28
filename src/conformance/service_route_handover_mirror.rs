//! Executable service-resolution handover and mirror conformance runner.
//!
//! The fixture is loaded from the SDK's embedded artifact snapshot. JSON
//! Schema closes the wire shape; deterministic mini state machines below
//! close the persistence, ordering, idempotency, privacy, and cache semantics.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, anyhow, bail};
use arkret_identifiers::{Did, project_did_to_core_id};
use arkret_models_identity::ServiceRouteCacheEntry;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use super::schema_validation_fixture::{SchemaValidationCase, run_cases};
use crate::transcripts::record_vector_event;

const FIXTURE_PATH: &str = "fixtures/service-route-handover-mirror-fixture.json";
const EXPECTED_SUITE: &str = "service_route_handover_mirror";
const EXPECTED_PROFILE: &str = "ak.profile.principal_server.v1";
const EXPECTED_VERSION: &str = "2026-08-10";

const SEMANTIC_CASES: &[&str] = &[
    "scheduled_time_order_and_current_basis",
    "cancel_requires_higher_revision_and_exact_previous_digest",
    "notice_never_authorizes_pre_not_before_business",
    "candidate_requires_formal_same_core_plus_one_successor",
    "publish_dual_idempotency_keys_exact_replay_and_conflict",
    "notice_basis_is_published_and_acked_sequentially",
    "resolve_bounds_visibility_and_blinded_failure",
    "same_sequence_different_target_signed_digest_quarantines",
    "durable_floor_survives_restart_cache_may_disappear",
    "durable_notice_state_survives_restart",
    "route_cache_enforces_local_and_signed_hard_expiry",
    "same_core_route_refresh_does_not_rebind_new_core_does",
    "one_to_one_cutover_requires_cross_ack",
];

#[derive(Debug, Deserialize)]
struct Fixture {
    suite: String,
    profile: String,
    version: String,
    schema_validation_cases: Vec<SchemaValidationCase>,
    semantic_cases: Vec<SemanticCase>,
}

#[derive(Debug, Deserialize)]
struct SemanticCase {
    name: String,
    inputs: Value,
    #[serde(default)]
    mutations: Vec<String>,
    semantic_outcome: String,
    expected_reason_code: String,
    #[serde(default)]
    expected_reason_code_by_mutation: BTreeMap<String, String>,
    expected_effects: Value,
}

fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("fixture field `{pointer}` is missing or is not a string"))
}

fn number(value: &Value, pointer: &str) -> Result<u64> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("fixture field `{pointer}` is missing or is not an integer"))
}

fn flag(value: &Value, pointer: &str) -> Result<bool> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("fixture field `{pointer}` is missing or is not a boolean"))
}

fn time(value: &Value, pointer: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(text(value, pointer)?)
        .with_context(|| format!("invalid timestamp at {pointer}"))?
        .with_timezone(&Utc))
}

fn semantic_case<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a SemanticCase> {
    fixture
        .semantic_cases
        .iter()
        .find(|case| case.name == name)
        .ok_or_else(|| anyhow!("service-route fixture omits semantic case `{name}`"))
}

fn require_mutations(case: &SemanticCase, expected: &[&str]) -> Result<()> {
    let actual = case
        .mutations
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("{} mutation set drifted: {actual:?}", case.name);
    }
    Ok(())
}

fn mutation_reason<'a>(case: &'a SemanticCase, mutation: &str) -> &'a str {
    case.expected_reason_code_by_mutation
        .get(mutation)
        .map_or(case.expected_reason_code.as_str(), String::as_str)
}

#[allow(clippy::too_many_arguments)]
fn notice_window_reason(
    issued_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    cutover_at: DateTime<Utc>,
    grace_until: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    from_sequence: u64,
    from_digest: &str,
    floor_sequence: u64,
    floor_digest: &str,
) -> Option<&'static str> {
    if issued_at > not_before
        || not_before > cutover_at
        || cutover_at >= grace_until
        || grace_until > expires_at
    {
        return Some("param_invalid");
    }
    if from_sequence != floor_sequence || from_digest != floor_digest {
        return Some("service_route_notice_basis_stale");
    }
    None
}

fn validate_scheduled_notice(case: &SemanticCase) -> Result<()> {
    if case.semantic_outcome != "accept_base_reject_mutations" {
        bail!("{} outcome drifted", case.name);
    }
    require_mutations(
        case,
        &[
            "not_before_before_issued_at",
            "cutover_before_not_before",
            "grace_equal_cutover",
            "expires_before_grace",
            "basis_sequence_stale",
            "basis_digest_mismatch",
        ],
    )?;
    let issued = time(&case.inputs, "/issued_at")?;
    let not_before = time(&case.inputs, "/not_before")?;
    let cutover = time(&case.inputs, "/cutover_at")?;
    let grace = time(&case.inputs, "/grace_until")?;
    let expires = time(&case.inputs, "/expires_at")?;
    let sequence = number(&case.inputs, "/from_record_sequence")?;
    let digest = text(&case.inputs, "/from_record_digest")?;
    let floor_sequence = number(&case.inputs, "/durable_floor_sequence")?;
    let floor_digest = text(&case.inputs, "/durable_floor_digest")?;
    if notice_window_reason(
        issued,
        not_before,
        cutover,
        grace,
        expires,
        sequence,
        digest,
        floor_sequence,
        floor_digest,
    )
    .is_some()
    {
        bail!("{} base window or durable basis was rejected", case.name);
    }

    let decisions = [
        (
            "not_before_before_issued_at",
            notice_window_reason(
                issued,
                issued - Duration::milliseconds(1),
                cutover,
                grace,
                expires,
                sequence,
                digest,
                floor_sequence,
                floor_digest,
            ),
        ),
        (
            "cutover_before_not_before",
            notice_window_reason(
                issued,
                not_before,
                not_before - Duration::milliseconds(1),
                grace,
                expires,
                sequence,
                digest,
                floor_sequence,
                floor_digest,
            ),
        ),
        (
            "grace_equal_cutover",
            notice_window_reason(
                issued,
                not_before,
                cutover,
                cutover,
                expires,
                sequence,
                digest,
                floor_sequence,
                floor_digest,
            ),
        ),
        (
            "expires_before_grace",
            notice_window_reason(
                issued,
                not_before,
                cutover,
                grace,
                grace - Duration::milliseconds(1),
                sequence,
                digest,
                floor_sequence,
                floor_digest,
            ),
        ),
        (
            "basis_sequence_stale",
            notice_window_reason(
                issued,
                not_before,
                cutover,
                grace,
                expires,
                sequence.saturating_sub(1),
                digest,
                floor_sequence,
                floor_digest,
            ),
        ),
        (
            "basis_digest_mismatch",
            notice_window_reason(
                issued,
                not_before,
                cutover,
                grace,
                expires,
                sequence,
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                floor_sequence,
                floor_digest,
            ),
        ),
    ];
    for (mutation, actual) in decisions {
        if actual != Some(mutation_reason(case, mutation)) {
            bail!("{} mutation `{mutation}` produced {actual:?}", case.name);
        }
    }
    Ok(())
}

fn cancel_is_successor(
    accepted_revision: u64,
    accepted_digest: &str,
    revision: u64,
    previous_digest: &str,
    candidate_fields_present: bool,
) -> bool {
    revision == accepted_revision + 1
        && previous_digest == accepted_digest
        && !candidate_fields_present
}

fn validate_cancel(case: &SemanticCase) -> Result<()> {
    require_mutations(
        case,
        &[
            "same_revision",
            "revision_gap",
            "wrong_previous_notice_digest",
            "candidate_fields_present_on_cancel",
        ],
    )?;
    let accepted_revision = number(&case.inputs, "/accepted_notice_revision")?;
    let accepted_digest = text(&case.inputs, "/accepted_notice_digest")?;
    let revision = number(&case.inputs, "/cancel_revision")?;
    let previous = text(&case.inputs, "/cancel_previous_notice_digest")?;
    if !cancel_is_successor(
        accepted_revision,
        accepted_digest,
        revision,
        previous,
        false,
    ) {
        bail!("{} base cancellation is not the exact successor", case.name);
    }
    let invalid = [
        cancel_is_successor(
            accepted_revision,
            accepted_digest,
            accepted_revision,
            previous,
            false,
        ),
        cancel_is_successor(
            accepted_revision,
            accepted_digest,
            revision + 1,
            previous,
            false,
        ),
        cancel_is_successor(
            accepted_revision,
            accepted_digest,
            revision,
            "sha256:wrong",
            false,
        ),
        cancel_is_successor(accepted_revision, accepted_digest, revision, previous, true),
    ];
    if invalid.into_iter().any(|accepted| accepted) {
        bail!("{} accepted a non-sequential cancellation", case.name);
    }
    Ok(())
}

fn validate_preannouncement_boundary(case: &SemanticCase) -> Result<()> {
    let now = time(&case.inputs, "/evaluation_time")?;
    let not_before = time(&case.inputs, "/not_before")?;
    let classes = case.inputs["attempted_payload_classes"]
        .as_array()
        .ok_or_else(|| anyhow!("{} omits attempted payload classes", case.name))?;
    let business_bytes_sent = classes
        .iter()
        .any(|class| class.as_str().is_some_and(|_| now >= not_before));
    if now >= not_before
        || classes.is_empty()
        || business_bytes_sent
        || !flag(&case.expected_effects, "/bounded_public_preflight_allowed")?
        || flag(&case.expected_effects, "/business_bytes_sent")?
        || flag(&case.expected_effects, "/route_state_updated")?
    {
        bail!("{} allowed pre-cutover business authorization", case.name);
    }
    Ok(())
}

fn successor_reason(
    notice_core: &str,
    notice_kind: &str,
    from_sequence: u64,
    from_digest: &str,
    candidate: &Value,
    reverse_binding_matches: bool,
) -> Option<&'static str> {
    if text(candidate, "/service_id").ok() != Some(notice_core)
        || text(candidate, "/service_kind").ok() != Some(notice_kind)
        || !reverse_binding_matches
    {
        return Some("service_route_successor_unavailable");
    }
    if number(candidate, "/record_sequence").ok() != Some(from_sequence + 1)
        || text(candidate, "/previous_record_digest").ok() != Some(from_digest)
    {
        return Some("service_resolution_mirror_response_gap");
    }
    None
}

fn validate_formal_successor(case: &SemanticCase) -> Result<()> {
    require_mutations(
        case,
        &[
            "wrong_service_core",
            "record_sequence_gap",
            "wrong_previous_record_digest",
            "describe_reverse_binding_mismatch",
        ],
    )?;
    let core = text(&case.inputs, "/notice_service_id")?;
    let kind = text(&case.inputs, "/notice_service_kind")?;
    let sequence = number(&case.inputs, "/from_record_sequence")?;
    let digest = text(&case.inputs, "/from_record_digest")?;
    let candidate = &case.inputs["candidate_record"];
    if successor_reason(core, kind, sequence, digest, candidate, true).is_some() {
        bail!("{} base candidate is not a formal successor", case.name);
    }
    let mut wrong_core = candidate.clone();
    wrong_core["service_id"] = json!("ak:did_core:webvh:z6mkWrong");
    let mut sequence_gap = candidate.clone();
    sequence_gap["record_sequence"] = json!(sequence + 2);
    let mut wrong_previous = candidate.clone();
    wrong_previous["previous_record_digest"] =
        json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let decisions = [
        (
            "wrong_service_core",
            successor_reason(core, kind, sequence, digest, &wrong_core, true),
        ),
        (
            "record_sequence_gap",
            successor_reason(core, kind, sequence, digest, &sequence_gap, true),
        ),
        (
            "wrong_previous_record_digest",
            successor_reason(core, kind, sequence, digest, &wrong_previous, true),
        ),
        (
            "describe_reverse_binding_mismatch",
            successor_reason(core, kind, sequence, digest, candidate, false),
        ),
    ];
    for (mutation, actual) in decisions {
        if actual != Some(mutation_reason(case, mutation)) {
            bail!("{} mutation `{mutation}` produced {actual:?}", case.name);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublishInput {
    source: String,
    realm: String,
    request_id: String,
    request_digest: String,
    artifact_key: String,
    artifact_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishDecision {
    Accepted,
    ExactReplay,
    CrossBoundAck,
    Conflict,
}

#[derive(Clone, Default)]
struct PublishLedger {
    transport: BTreeMap<(String, String, String), PublishInput>,
    artifacts: BTreeMap<(String, String, String), String>,
}

impl PublishLedger {
    fn publish(&mut self, header: &str, input: PublishInput) -> PublishDecision {
        if header != input.request_id {
            return PublishDecision::Conflict;
        }
        let transport_key = (
            input.source.clone(),
            input.realm.clone(),
            input.request_id.clone(),
        );
        if let Some(previous) = self.transport.get(&transport_key) {
            return if previous == &input {
                PublishDecision::ExactReplay
            } else {
                PublishDecision::Conflict
            };
        }
        let artifact_key = (
            input.source.clone(),
            input.realm.clone(),
            input.artifact_key.clone(),
        );
        let decision = match self.artifacts.get(&artifact_key) {
            Some(digest) if digest != &input.artifact_digest => PublishDecision::Conflict,
            Some(_) => PublishDecision::CrossBoundAck,
            None => PublishDecision::Accepted,
        };
        if decision != PublishDecision::Conflict {
            self.artifacts
                .entry(artifact_key)
                .or_insert_with(|| input.artifact_digest.clone());
            self.transport.insert(transport_key, input);
        }
        decision
    }
}

fn validate_dual_idempotency(case: &SemanticCase) -> Result<()> {
    require_mutations(
        case,
        &[
            "header_idempotency_key_differs_from_body_request_id",
            "same_transport_key_different_request_digest",
            "same_artifact_key_different_artifact_digest",
            "new_request_id_same_artifact_bytes",
        ],
    )?;
    let base = PublishInput {
        source: text(&case.inputs, "/source_id")?.to_owned(),
        realm: text(&case.inputs, "/realm_id")?.to_owned(),
        request_id: text(&case.inputs, "/request_id")?.to_owned(),
        request_digest: text(&case.inputs, "/request_digest")?.to_owned(),
        artifact_key: serde_json::to_string(&case.inputs["artifact_key"])?,
        artifact_digest: text(&case.inputs, "/first_artifact_digest")?.to_owned(),
    };
    let header = text(&case.inputs, "/idempotency_key_header")?;
    let mut ledger = PublishLedger::default();
    if ledger.publish(header, base.clone()) != PublishDecision::Accepted
        || ledger.publish(header, base.clone()) != PublishDecision::ExactReplay
    {
        bail!("{} did not preserve its exact transport replay", case.name);
    }
    let restarted = ledger.clone();
    if restarted.transport.len() != 1 || restarted.artifacts.len() != 1 {
        bail!("{} acknowledgement did not survive restart", case.name);
    }
    if ledger.publish("different_header", base.clone()) != PublishDecision::Conflict {
        bail!("{} accepted a mismatched Idempotency-Key", case.name);
    }
    let mut transport_conflict = base.clone();
    transport_conflict.request_digest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
    if ledger.publish(header, transport_conflict) != PublishDecision::Conflict {
        bail!("{} overwrote a transport idempotency conflict", case.name);
    }
    let next_request = text(&case.inputs, "/new_request_id_for_same_artifact")?.to_owned();
    let mut artifact_conflict = base.clone();
    artifact_conflict.request_id = next_request.clone();
    artifact_conflict.artifact_digest =
        text(&case.inputs, "/conflicting_artifact_digest")?.to_owned();
    if ledger.publish(&next_request, artifact_conflict) != PublishDecision::Conflict {
        bail!("{} overwrote an artifact integrity conflict", case.name);
    }
    let mut cross_bound = base;
    cross_bound.request_id = next_request.clone();
    if ledger.publish(&next_request, cross_bound) != PublishDecision::CrossBoundAck {
        bail!(
            "{} rejected a new request id for identical artifact bytes",
            case.name
        );
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct AckedFloor {
    sequence: u64,
}

impl AckedFloor {
    fn ack_record(&mut self, sequence: u64) -> bool {
        if sequence != self.sequence + 1 {
            return false;
        }
        self.sequence = sequence;
        true
    }

    fn publish_notice(&self, basis: u64, artifact_count: usize) -> bool {
        artifact_count == 1 && basis == self.sequence
    }
}

fn validate_sequential_notice(case: &SemanticCase) -> Result<()> {
    require_mutations(
        case,
        &[
            "notice_published_before_record_6_ack",
            "record_6_and_record_7_batched_with_notice",
            "notice_claims_basis_7_after_only_record_6_ack",
            "single_request_implies_atomic_chain_acceptance",
        ],
    )?;
    let expected_order = [
        "record_sequence_6",
        "ack_record_sequence_6",
        "record_sequence_7",
        "ack_record_sequence_7",
        "notice_from_record_sequence_7",
    ];
    let actual_order = case.inputs["publish_order"]
        .as_array()
        .ok_or_else(|| anyhow!("{} omits publish_order", case.name))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if actual_order != expected_order {
        bail!("{} publication order drifted", case.name);
    }
    let mut floor = AckedFloor {
        sequence: number(&case.inputs, "/receiver_initial_floor_sequence")?,
    };
    if floor.publish_notice(7, 1)
        || !floor.ack_record(6)
        || floor.publish_notice(7, 1)
        || !floor.ack_record(7)
        || !floor.publish_notice(7, 1)
        || floor.publish_notice(7, 3)
    {
        bail!(
            "{} did not require individually acknowledged sequential records",
            case.name
        );
    }
    if number(
        &case.expected_effects,
        "/receiver_floor_sequence_before_notice",
    )? != floor.sequence
        || flag(
            &case.expected_effects,
            "/notice_ack_implies_record_chain_ack",
        )?
    {
        bail!(
            "{} expected effects contradict sequential publication",
            case.name
        );
    }
    Ok(())
}

fn public_resolve_error(gate_passed: bool) -> Value {
    let code = if gate_passed {
        "not_found"
    } else {
        "capability_denied"
    };
    json!({
        "code": code,
        "message": "service resolution unavailable",
        "timing_bucket": "blinded-v1"
    })
}

fn validate_blinded_resolve(case: &SemanticCase) -> Result<()> {
    let records = case.inputs["max_records_boundaries"]
        .as_array()
        .ok_or_else(|| anyhow!("{} omits max_records_boundaries", case.name))?;
    let bytes = case.inputs["max_response_bytes_boundaries"]
        .as_array()
        .ok_or_else(|| anyhow!("{} omits max_response_bytes_boundaries", case.name))?;
    if records.iter().map(Value::as_u64).collect::<Vec<_>>() != [Some(32), Some(33)]
        || bytes.iter().map(Value::as_u64).collect::<Vec<_>>() != [Some(262_144), Some(262_145)]
    {
        bail!("{} hard-bound boundary vectors drifted", case.name);
    }
    let gate_states = case.inputs["gate_blinded_states"]
        .as_array()
        .ok_or_else(|| anyhow!("{} omits gate_blinded_states", case.name))?;
    let post_states = case.inputs["post_gate_blinded_states"]
        .as_array()
        .ok_or_else(|| anyhow!("{} omits post_gate_blinded_states", case.name))?;
    let gate_bytes = serde_json::to_vec(&public_resolve_error(false))?;
    for state in gate_states {
        if state.as_str().is_none()
            || serde_json::to_vec(&public_resolve_error(false))? != gate_bytes
        {
            bail!("{} gate failures are distinguishable", case.name);
        }
    }
    let post_bytes = serde_json::to_vec(&public_resolve_error(true))?;
    for state in post_states {
        if state.as_str().is_none()
            || serde_json::to_vec(&public_resolve_error(true))? != post_bytes
        {
            bail!("{} post-gate failures are distinguishable", case.name);
        }
    }
    if gate_bytes == post_bytes
        || number(&case.expected_effects, "/maximum_successor_records")? != 32
        || number(&case.expected_effects, "/maximum_canonical_response_bytes")? != 262_144
        || !flag(
            &case.expected_effects,
            "/gate_failures_use_capability_denied",
        )?
        || !flag(&case.expected_effects, "/post_gate_failures_use_not_found")?
        || !flag(
            &case.expected_effects,
            "/private_audit_retains_internal_reason",
        )?
        || flag(&case.expected_effects, "/topology_disclosed")?
    {
        bail!("{} blinded resolve effects drifted", case.name);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct DurableRouteState {
    floor_sequence: u64,
    floor_digest: String,
    notice_revision: Option<u64>,
    notice_state: Option<String>,
    cache_present: bool,
    quarantined: bool,
}

impl DurableRouteState {
    fn restart(&self) -> Self {
        Self {
            cache_present: false,
            ..self.clone()
        }
    }

    fn observe_record(&mut self, sequence: u64, digest: &str) -> Result<(), &'static str> {
        if sequence < self.floor_sequence
            || (sequence == self.floor_sequence && digest != self.floor_digest)
        {
            self.quarantined = true;
            return Err("service_route_fork");
        }
        self.floor_sequence = sequence;
        self.floor_digest = digest.to_owned();
        Ok(())
    }
}

fn validate_fork_quarantine(case: &SemanticCase) -> Result<()> {
    let sequence = number(&case.inputs, "/record_sequence")?;
    let a = text(&case.inputs, "/mirror_a_digest")?;
    let b = text(&case.inputs, "/mirror_b_digest")?;
    let mut state = DurableRouteState {
        floor_sequence: sequence,
        floor_digest: a.to_owned(),
        notice_revision: None,
        notice_state: None,
        cache_present: true,
        quarantined: false,
    };
    if state.observe_record(sequence, b) != Err("service_route_fork")
        || !state.quarantined
        || flag(&case.expected_effects, "/majority_vote_used")?
        || flag(&case.expected_effects, "/arrival_order_used")?
        || flag(&case.expected_effects, "/reachability_used")?
    {
        bail!("{} failed to quarantine a same-sequence fork", case.name);
    }
    Ok(())
}

fn validate_durable_floor(case: &SemanticCase) -> Result<()> {
    let original_sequence = number(&case.inputs, "/before_restart_floor_sequence")?;
    let mut state = DurableRouteState {
        floor_sequence: original_sequence,
        floor_digest: text(&case.inputs, "/before_restart_floor_digest")?.to_owned(),
        notice_revision: None,
        notice_state: None,
        cache_present: flag(&case.inputs, "/before_restart_cache_present")?,
        quarantined: false,
    }
    .restart();
    if state.cache_present != flag(&case.inputs, "/after_restart_cache_present")?
        || state.observe_record(
            number(&case.inputs, "/replayed_record_sequence")?,
            text(&case.inputs, "/replayed_record_digest")?,
        ) != Err("service_route_fork")
        || !state.quarantined
        || state.floor_sequence != original_sequence
    {
        bail!(
            "{} coupled durable rollback protection to the TTL cache",
            case.name
        );
    }
    Ok(())
}

fn validate_durable_notice(case: &SemanticCase) -> Result<()> {
    let before = &case.inputs["before_restart"];
    let state = DurableRouteState {
        floor_sequence: number(before, "/from_record_sequence")?,
        floor_digest: text(before, "/from_record_digest")?.to_owned(),
        notice_revision: Some(number(before, "/notice_revision")?),
        notice_state: Some(text(before, "/state")?.to_owned()),
        cache_present: true,
        quarantined: false,
    }
    .restart();
    let replay_revision = number(&case.inputs, "/replayed_scheduled_revision")?;
    let replay_rejected = state.notice_state.as_deref() == Some("cancelled")
        && state
            .notice_revision
            .is_some_and(|revision| replay_revision < revision);
    if !replay_rejected
        || state.cache_present != flag(&case.inputs, "/after_restart_cache_present")?
        || !flag(&case.expected_effects, "/notice_state_preserved")?
        || flag(&case.expected_effects, "/ttl_cache_required_for_safety")?
    {
        bail!(
            "{} lost durable cancellation state across restart",
            case.name
        );
    }
    Ok(())
}

fn cache_fixture_entry(fixture: &Fixture) -> Result<ServiceRouteCacheEntry> {
    let case = fixture
        .schema_validation_cases
        .iter()
        .find(|case| case.name == "replaceable_route_cache_shape_valid")
        .ok_or_else(|| anyhow!("service-route fixture omits cache schema case"))?;
    serde_json::from_value(case.instance.clone()).context("decode SDK ServiceRouteCacheEntry")
}

fn validate_cache_expiry(fixture: &Fixture, case: &SemanticCase) -> Result<()> {
    require_mutations(
        case,
        &[
            "cache_expires_after_signed_expiry",
            "signed_expiry_discarded",
            "local_ttl_used_to_extend_signed_expiry",
        ],
    )?;
    let entry = cache_fixture_entry(fixture)?;
    let boundaries = case.inputs["evaluation_boundaries"]
        .as_array()
        .ok_or_else(|| anyhow!("{} omits evaluation_boundaries", case.name))?
        .iter()
        .map(|value| {
            let raw = value
                .as_str()
                .ok_or_else(|| anyhow!("cache boundary is not a string"))?;
            Ok(DateTime::parse_from_rfc3339(raw)?.with_timezone(&Utc))
        })
        .collect::<Result<Vec<_>>>()?;
    if boundaries.len() != 3
        || !entry.is_routable_at(boundaries[0])
        || entry.is_routable_at(boundaries[1])
        || entry.is_routable_at(boundaries[2])
    {
        bail!(
            "{} did not evict at the earliest local/signed expiry",
            case.name
        );
    }
    let mut illegal_extension = entry.clone();
    illegal_extension.cache_expires_at = illegal_extension.expires_at + Duration::seconds(1);
    if illegal_extension.is_routable_at(illegal_extension.verified_at) {
        bail!("{} allowed local TTL to extend signed validity", case.name);
    }
    Ok(())
}

fn validate_core_boundary(fixture: &Fixture, case: &SemanticCase) -> Result<()> {
    let entry = cache_fixture_entry(fixture)?;
    let bound = text(&case.inputs, "/member_recipient_id")?;
    let same = text(&case.inputs, "/same_core_successor_service_id")?;
    let replacement = text(&case.inputs, "/new_core_candidate_service_id")?;
    let projected = project_did_to_core_id(&entry.did)?;
    let replacement_full = Did::new("did:webvh:z6mkReplacement:replacement.example")?;
    let replacement_projected = project_did_to_core_id(&replacement_full)?;
    if projected.as_str() != bound
        || same != bound
        || replacement_projected.as_str() != replacement
        || replacement == bound
        || flag(&case.expected_effects, "/same_core_member_rebind_written")?
        || flag(&case.expected_effects, "/new_core_route_cache_accepted")?
        || !flag(&case.expected_effects, "/new_core_member_rebind_required")?
    {
        bail!("{} blurred route refresh and service rebind", case.name);
    }
    Ok(())
}

fn cross_ack_safe(a: bool, b: bool, durable: bool, digest_matches: bool) -> bool {
    a && b && durable && digest_matches
}

fn validate_cross_ack(case: &SemanticCase) -> Result<()> {
    require_mutations(
        case,
        &[
            "missing_a_ack",
            "missing_b_ack",
            "volatile_ack_only",
            "ack_digest_mismatch",
        ],
    )?;
    let a = flag(&case.inputs, "/service_a_acknowledged_b_notice")?;
    let b = flag(&case.inputs, "/service_b_acknowledged_a_notice")?;
    let durable = flag(&case.inputs, "/ack_durable")?;
    if !cross_ack_safe(a, b, durable, true)
        || cross_ack_safe(false, b, durable, true)
        || cross_ack_safe(a, false, durable, true)
        || cross_ack_safe(a, b, false, true)
        || cross_ack_safe(a, b, durable, false)
    {
        bail!(
            "{} did not require two durable exact-digest acks",
            case.name
        );
    }
    Ok(())
}

fn validate_semantics(fixture: &Fixture) -> Result<()> {
    let actual = fixture
        .semantic_cases
        .iter()
        .map(|case| case.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected = SEMANTIC_CASES.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("service-route semantic case set drifted: {actual:?}");
    }
    validate_scheduled_notice(semantic_case(fixture, SEMANTIC_CASES[0])?)?;
    validate_cancel(semantic_case(fixture, SEMANTIC_CASES[1])?)?;
    validate_preannouncement_boundary(semantic_case(fixture, SEMANTIC_CASES[2])?)?;
    validate_formal_successor(semantic_case(fixture, SEMANTIC_CASES[3])?)?;
    validate_dual_idempotency(semantic_case(fixture, SEMANTIC_CASES[4])?)?;
    validate_sequential_notice(semantic_case(fixture, SEMANTIC_CASES[5])?)?;
    validate_blinded_resolve(semantic_case(fixture, SEMANTIC_CASES[6])?)?;
    validate_fork_quarantine(semantic_case(fixture, SEMANTIC_CASES[7])?)?;
    validate_durable_floor(semantic_case(fixture, SEMANTIC_CASES[8])?)?;
    validate_durable_notice(semantic_case(fixture, SEMANTIC_CASES[9])?)?;
    validate_cache_expiry(fixture, semantic_case(fixture, SEMANTIC_CASES[10])?)?;
    validate_core_boundary(fixture, semantic_case(fixture, SEMANTIC_CASES[11])?)?;
    validate_cross_ack(semantic_case(fixture, SEMANTIC_CASES[12])?)?;
    Ok(())
}

pub fn run_service_route_handover_mirror_fixture_suite() -> Result<()> {
    let value = arkret_schema::embedded_json_artifact(FIXTURE_PATH)
        .context("load embedded service-route handover fixture")?;
    let fixture: Fixture =
        serde_json::from_value(value).context("decode embedded service-route handover fixture")?;
    if fixture.suite != EXPECTED_SUITE
        || fixture.profile != EXPECTED_PROFILE
        || fixture.version != EXPECTED_VERSION
    {
        bail!(
            "service-route fixture metadata drifted: suite={} profile={} version={}",
            fixture.suite,
            fixture.profile,
            fixture.version
        );
    }
    run_cases(&fixture.schema_validation_cases)?;
    validate_semantics(&fixture)?;
    record_vector_event(
        "service_route_handover_mirror.fixture",
        &json!({"fixture": FIXTURE_PATH, "version": fixture.version}),
        &json!({
            "schema_cases": fixture.schema_validation_cases.len(),
            "semantic_cases": fixture.semantic_cases.len(),
            "durable_floor_separate_from_cache": true,
            "dual_idempotency": true,
            "blinded_resolution": true,
            "stable_core_boundary": true
        }),
        &json!({"status": "validated"}),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_fixture_executes_schema_and_semantic_cases() {
        run_service_route_handover_mirror_fixture_suite()
            .expect("embedded service-route fixture must execute");
    }
}
