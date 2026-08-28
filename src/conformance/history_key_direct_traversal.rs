//! Direct history-governance traversal and history-access ratchet checks.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow, bail};
use arkret_models_collaboration::governance::realm_lifecycle::HistoryAccessPayload;
use arkret_models_collaboration::governance_dependencies::GovernanceDependencyResolveOutcome;
use arkret_models_collaboration::history_key::{
    AuthorizationIncarnation, HistoryCandidateOriginAttribution, HistoryGovernanceTraversalIntent,
    HistoryGovernanceTraversalRetention, HistoryKeyResponseAckRequest,
    HistoryKeyResponseListOutcome, HistoryKeyResponseSendReceipt, HistoryKeyResponseSendRequest,
    HistoryKeyResponseSigningInput, HistoryResponseId, HistorySourceAgentObservationInput,
    HistorySourceSendDisposition, OrganizationRecoveryArchiveListOutcome,
    OrganizationRecoveryArchiveListQuery, OrganizationRecoveryArchiveReplica,
    OrganizationRecoveryArchiveReplicaOutcome, PeerHistoryTraversalAccess, ResponseSenderOriginRef,
    ResponseSenderQuotaDomain, SelfHistoryTraversalAccess, response_capability_commitment,
};
use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
use arkret_state::direct_traversal::{
    BoundedDirectTraversalJournal, DirectCutDescriptorIndex, DirectCutMaterial, DirectCutRequest,
    SealPredecessorDescriptor, discover_direct_cut, verify_direct_traversal_cut_with_registry,
};
use arkret_state::history_backup::{
    OrganizationRecoveryArchiveGcLedger, OrganizationRecoveryArchiveReplicaAdmission,
};
use arkret_state::history_store::HistoryMaterialLedger;
use arkret_state::lattice::{CasRegister, Lattice, SealedOp};
use arkret_state::{BottomMode, CellState, LatticeKind, MemoryCellRegistry, compute_state_root};
use arkret_wire::event_envelope::ScopeRef;
use arkret_wire::{
    AvailabilityReceipt, CellFamilyId, CellRef, DidCoreId, DidFullId, DidUrl, Event,
    EventCandidateBinding, EventCandidateBindingKey, EventCandidateBindingOutcome, EventId,
    EventKind, HISTORY_STORE_LIMITS, Hash, HistoryAccess, HistoryCandidateMaterialKey,
    HistoryEffectiveScope, Hlc, LatticeOp, LatticeOpType, NotarySig, NotarySignerDescriptor,
    NotaryValue, ProducerEventProof, ProjectedCellWrite, ProjectedOp, RealmId, Seal, SealBasis,
    SealId, SealSignature, null_subject_cell,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

use super::{load_artifact_json, required_str};
use crate::transcripts::record_vector_event;

pub fn run_history_key_direct_traversal_suite() -> Result<()> {
    let fixture = load_artifact_json("fixtures/history-key-recovery-fixture.json")?;
    let retention: HistoryGovernanceTraversalRetention = serde_json::from_value(
        fixture
            .pointer("/direct_traversal_kat/member_retention")
            .cloned()
            .context("history-key fixture omits member_retention")?,
    )?;
    retention.validate_digest()?;

    let archive_intent: HistoryGovernanceTraversalIntent = serde_json::from_value(
        fixture
            .pointer("/direct_traversal_kat/organization_recovery_intent")
            .cloned()
            .context("history-key fixture omits organization_recovery_intent")?,
    )?;
    archive_intent.validate()?;

    let self_request: SelfHistoryTraversalAccess = serde_json::from_value(json!({
        "kind": "request_receipt",
        "request_receipt_digest": format!("sha256:{}", "11".repeat(32))
    }))?;
    let self_archive: SelfHistoryTraversalAccess = serde_json::from_value(json!({
        "kind": "archive_replica",
        "archive_replica_digest": format!("sha256:{}", "22".repeat(32))
    }))?;
    let peer_archive: PeerHistoryTraversalAccess = serde_json::from_value(json!({
        "kind": "pending_archive_replica",
        "pending_archive_replica_digest": format!("sha256:{}", "33".repeat(32))
    }))?;
    for access in [
        serde_json::to_value(self_request)?,
        serde_json::to_value(self_archive)?,
        serde_json::to_value(peer_archive)?,
    ] {
        if access.get("kind").and_then(Value::as_str).is_none() {
            bail!("history traversal access lost its closed branch discriminator");
        }
    }

    let negative_cases = fixture
        .pointer("/direct_traversal_kat/negative_cases")
        .and_then(Value::as_array)
        .context("history-key fixture omits direct traversal negative cases")?;
    verify_direct_cut_graph_mutations(
        fixture
            .pointer("/direct_traversal_kat/direct_cut")
            .context("history-key fixture omits direct_cut")?,
        negative_cases,
    )?;
    verify_since_join_lineage(
        fixture
            .pointer("/direct_traversal_kat/since_join_lineage")
            .context("history-key fixture omits since_join_lineage")?,
    )?;
    verify_direct_traversal_replay_kat(
        fixture
            .pointer("/direct_traversal_replay_kat")
            .context("history-key fixture omits direct_traversal_replay_kat")?,
    )?;
    verify_history_digest_and_sender_kats(&fixture)?;
    verify_governance_dependency_kats(&fixture)?;
    verify_rrk_method_evaluator(&fixture)?;
    verify_rrk_production_projection_and_join(&fixture)?;
    verify_rrk_durable_before_gc(&fixture)?;
    verify_response_stream_fixture(&fixture)?;
    verify_client_convergence_kat(&fixture)?;
    verify_history_candidate_store_kat(&fixture)?;
    verify_history_static_gates(&fixture)?;
    verify_scope_and_endpoint_kats(&fixture)?;

    HistoryAccessPayload::initialize(HistoryAccess::AllHistoryForCurrentMembers).validate()?;
    HistoryAccessPayload::tighten().validate()?;
    HistoryAccessPayload {
        from: Some(HistoryAccess::SinceJoin),
        to: HistoryAccess::AllHistoryForCurrentMembers,
        reason: None,
    }
    .validate()
    .expect_err("history access widening must fail closed");

    let capability_kat = fixture
        .pointer("/history_response_capability_kat")
        .context("history-key fixture omits history response capability KAT")?;
    let capability = capability_kat["response_capability_b64u"]
        .as_str()
        .context("history response capability KAT omits capability")?;
    if capability_kat["decoded_length"].as_u64() != Some(32)
        || response_capability_commitment(capability)?.as_ref()
            != capability_kat["expected_response_capability_commitment"]
                .as_str()
                .context("history response capability KAT omits commitment")?
        || capability_kat
            .pointer("/surface/read")
            .and_then(Value::as_str)
            != Some("POST /_arkret/self/history-key-responses/read")
        || capability_kat
            .pointer("/surface/ack")
            .and_then(Value::as_str)
            != Some("POST /_arkret/self/history-key-responses/ack")
        || capability_kat
            .pointer("/surface/request_locator_in_path_query_or_body")
            .and_then(Value::as_bool)
            != Some(false)
    {
        bail!("history response capability KAT drifted");
    }
    let capability_negative_cases = capability_kat["negative_cases"]
        .as_array()
        .context("history response capability KAT omits negative cases")?;
    for required in [
        "unknown_expired_gc_and_unauthorized_same_not_found_shape",
        "stream_a_capability_cannot_read_or_ack_stream_b",
        "stream_a_capability_cannot_consume_stream_b_ack_token",
        "commitment_collision_resampled_before_any_durable_write",
        "exact_create_retry_returns_byte_identical_sealed_capability",
    ] {
        if !capability_negative_cases
            .iter()
            .any(|case| case.as_str() == Some(required))
        {
            bail!("history response capability KAT omits {required}");
        }
    }

    let scale_cases = fixture
        .pointer("/streaming_direct_traversal_scale_kats")
        .and_then(Value::as_array)
        .context("history-key fixture omits streaming scale KATs")?;
    let expected_scale = [
        (
            26_298_u64,
            26_299_u64,
            7_416_182_u64,
            "sha256:c702bba991ec05314014566a763db2c99aeecba920b02fb58cbd0347277aed45",
        ),
        (
            65_536_u64,
            65_537_u64,
            18_481_298_u64,
            "sha256:1d1377c13c8b58b688f887be4d7df282b12aa0597424360d57b74fd06e78da19",
        ),
    ];
    for (epoch_count, seal_count, descriptor_bytes, aggregate_digest) in expected_scale {
        let case = scale_cases
            .iter()
            .find(|case| case["epoch_count"].as_u64() == Some(epoch_count))
            .with_context(|| format!("history scale fixture omits {epoch_count} epochs"))?;
        if case["verified_epoch_count"].as_u64() != Some(epoch_count)
            || case["resolved_control_event_count"].as_u64() != Some(epoch_count)
            || case["resolved_availability_receipt_count"].as_u64() != Some(epoch_count)
            || case["visited_seal_count"].as_u64() != Some(seal_count)
            || case["max_live_descriptor_bytes"].as_u64() != Some(282)
            || case["descriptor_canonical_bytes"].as_u64() != Some(descriptor_bytes)
            || case["descriptor_stream_aggregate_digest"].as_str() != Some(aggregate_digest)
            || case["outbox_write_count"].as_u64() != Some(0)
        {
            bail!("history scale fixture drifted at {epoch_count} epochs");
        }
    }
    let over_limit = fixture
        .pointer("/streaming_direct_traversal_scale_negative_kats/0")
        .context("history-key fixture omits 65,537-epoch prewrite rejection")?;
    if over_limit["epoch_count"].as_u64() != Some(65_537)
        || over_limit["rejected_before_staging"].as_bool() != Some(true)
        || over_limit["journal_rows"].as_u64() != Some(0)
        || over_limit["resolved_objects"].as_u64() != Some(0)
        || over_limit["outbox_writes"].as_u64() != Some(0)
    {
        bail!("history 65,537-epoch prewrite rejection drifted");
    }

    record_vector_event(
        "history_key.direct_traversal",
        &json!({"fixture": "history-key-recovery-fixture.json"}),
        &json!({
            "member_intent_digest_valid": true,
            "organization_recovery_intent_valid": true,
            "closed_access_branches_valid": true,
            "closed_cut_negative_cases_valid": true,
            "since_join_lineage_valid": true,
            "direct_traversal_replay_kat_valid": true,
            "history_digest_and_sender_kats_valid": true,
            "governance_dependency_kats_valid": true,
            "rrk_method_evaluator_valid": true,
            "rrk_durable_before_gc_valid": true,
            "candidate_store_kat_valid": true,
            "history_static_gates_valid": true,
            "scope_and_endpoint_kats_valid": true,
            "history_access_widening_rejected": true,
            "response_capability_kat_valid": true,
            "client_convergence_kat_valid": true,
            "streaming_scale_kats_valid": true,
        }),
        &json!({"status": "validated"}),
    );
    Ok(())
}

fn verify_rrk_production_projection_and_join(fixture: &Value) -> Result<()> {
    let kat = fixture
        .get("rrk_registration_rotation_kat")
        .context("history-key fixture omits rrk_registration_rotation_kat")?;
    let register_event: Event = serde_json::from_value(kat["events"]["register"].clone())?;
    let rotate_event: Event = serde_json::from_value(kat["events"]["rotate"].clone())?;
    let register_write = arkret_schema::project_registered_cell_writes(
        &register_event,
        arkret_canonical::DigestSuite::Sha256,
    )?
    .into_iter()
    .next()
    .context("RRK register produced no cell write")?;
    let rotate_write = arkret_schema::project_registered_cell_writes(
        &rotate_event,
        arkret_canonical::DigestSuite::Sha256,
    )?
    .into_iter()
    .next()
    .context("RRK rotate produced no cell write")?;
    let ProjectedOp::Direct(register_op) = register_write.op else {
        bail!("RRK register must project a direct CAS operation");
    };
    let ProjectedOp::Direct(rotate_op) = rotate_write.op else {
        bail!("RRK rotate must project a direct CAS operation");
    };
    if rotate_op.from.as_ref() != Some(&kat["projected_rotate_op"]["from"])
        || rotate_op.value.as_ref() != Some(&kat["projected_rotate_op"]["to"])
    {
        bail!("RRK production projector lost the exact from/to transition");
    }
    let register_id = Hash::new(
        register_event.proofs[0]
            .as_producer()
            .context("RRK register omits producer proof")?
            .event_digest
            .as_str()
            .to_owned(),
    )?;
    let rotate_id = Hash::new(
        rotate_event.proofs[0]
            .as_producer()
            .context("RRK rotate omits producer proof")?
            .event_digest
            .as_str()
            .to_owned(),
    )?;
    let joined = CasRegister.join(
        &register_write.cell,
        &[
            SealedOp::new(register_id.clone(), register_op.clone()),
            SealedOp::new(rotate_id.clone(), rotate_op),
        ],
    );
    if joined != CellState::Value(kat["projected_rotate_op"]["to"].clone()) {
        bail!("RRK production CAS did not settle the conformant rotation");
    }

    let mut missing_head = rotate_event;
    missing_head.preconditions.clear();
    let stale_write = arkret_schema::project_registered_cell_writes(
        &missing_head,
        arkret_canonical::DigestSuite::Sha256,
    )?
    .into_iter()
    .next()
    .context("RRK missing-head mutation produced no cell write")?;
    let ProjectedOp::Direct(stale_op) = stale_write.op else {
        bail!("RRK missing-head mutation must remain a direct CAS operation");
    };
    if stale_op.from.is_some()
        || !matches!(
            CasRegister.join(
                &register_write.cell,
                &[
                    SealedOp::new(register_id, register_op),
                    SealedOp::new(rotate_id, stale_op),
                ],
            ),
            CellState::Bottom(_)
        )
    {
        bail!("RRK missing exact signed head_eq did not fail closed");
    }
    Ok(())
}

fn verify_rrk_durable_before_gc(fixture: &Value) -> Result<()> {
    let kat = fixture
        .get("organization_recovery_archive_durable_before_gc_kat")
        .context("history-key fixture omits RRK durable-before-GC KAT")?;
    let replica: OrganizationRecoveryArchiveReplica =
        serde_json::from_value(kat["replica"].clone())?;
    let receipt: OrganizationRecoveryArchiveReplicaOutcome =
        serde_json::from_value(kat["first_receipt"].clone())?;
    let query: OrganizationRecoveryArchiveListQuery =
        serde_json::from_value(kat["barrier_query"].clone())?;
    let outcome: OrganizationRecoveryArchiveListOutcome =
        serde_json::from_value(kat["barrier_resolve_outcome"].clone())?;
    outcome.validate_for_query(&query)?;
    if outcome.items[0].archive_replica_digest != receipt.archive_replica_digest {
        bail!("RRK holder list did not expose the exact accepted replica digest");
    }

    let mut missing_digest = kat["barrier_resolve_outcome"].clone();
    missing_digest["items"][0]
        .as_object_mut()
        .context("RRK list fixture item is not an object")?
        .remove("archive_replica_digest");
    if serde_json::from_value::<OrganizationRecoveryArchiveListOutcome>(missing_digest).is_ok() {
        bail!("RRK holder list accepted a row without archive_replica_digest");
    }

    let mut ledger = OrganizationRecoveryArchiveGcLedger::new(&replica)?;
    if serde_json::to_value(&ledger)? != kat["coverage_ledger"]["initial"]
        || ledger.gc_local_history_secret().is_ok()
    {
        bail!("RRK local GC did not fail closed before durable holder acceptance");
    }
    if ledger.record_durable_holder_acceptance(&replica, &receipt)?
        != OrganizationRecoveryArchiveReplicaAdmission::FirstAccepted
        || serde_json::to_value(&ledger)? != kat["coverage_ledger"]["after_first_accept"]
    {
        bail!("RRK first durable holder acceptance did not update exact coverage evidence");
    }
    if ledger.record_durable_holder_acceptance(&replica, &receipt)?
        != OrganizationRecoveryArchiveReplicaAdmission::ExactDuplicate
        || arkret_wire::canonical::canonical_json_bytes(&receipt)?
            != URL_SAFE_NO_PAD.decode(
                kat["first_receipt_jcs_b64u"]
                    .as_str()
                    .context("RRK KAT omits receipt canonical bytes")?,
            )?
    {
        bail!("RRK exact duplicate did not return the first byte-identical receipt");
    }

    let mut changed_replica = replica.clone();
    changed_replica.replicated_at += chrono::Duration::seconds(3);
    if ledger
        .record_durable_holder_acceptance(&changed_replica, &receipt)
        .is_ok()
    {
        bail!("RRK semantic retry with changed replica bytes did not conflict");
    }

    let mut changed_outcome = outcome.clone();
    let ciphertext = &mut changed_outcome.items[0].archive.ciphertext;
    ciphertext.replace_range(
        0..1,
        if ciphertext.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    if ledger
        .record_exact_holder_reread(&query, &changed_outcome)
        .is_ok()
        || serde_json::to_value(&ledger)? != kat["coverage_ledger"]["after_first_accept"]
    {
        bail!("RRK barrier accepted changed archive bytes or mutated coverage state");
    }

    let mut substituted_digest = outcome.clone();
    substituted_digest.items[0].archive_replica_digest =
        substituted_digest.items[0].archive.archive_digest()?;
    if ledger
        .record_exact_holder_reread(&query, &substituted_digest)
        .is_ok()
    {
        bail!("RRK barrier accepted archive_digest as replica access coordinate");
    }

    ledger.record_exact_holder_reread(&query, &outcome)?;
    if serde_json::to_value(&ledger)? != kat["coverage_ledger"]["after_exact_reread"] {
        bail!("RRK exact holder reread did not close the local coverage barrier");
    }
    ledger.gc_local_history_secret()?;
    if serde_json::to_value(&ledger)? != kat["coverage_ledger"]["after_local_gc"] {
        bail!("RRK GC changed more than the source-local history secret");
    }
    Ok(())
}

fn verify_response_stream_fixture(fixture: &Value) -> Result<()> {
    let kat = fixture
        .get("response_stream_cases")
        .context("history fixture omits response_stream_cases")?;
    let send: HistoryKeyResponseSendRequest = serde_json::from_value(
        kat.pointer("/wire_instances/manifest_send")
            .cloned()
            .context("response stream KAT omits manifest_send")?,
    )?;
    send.validate()?;
    let receipt: HistoryKeyResponseSendReceipt = serde_json::from_value(
        kat.pointer("/wire_instances/first_send_receipt")
            .cloned()
            .context("response stream KAT omits first_send_receipt")?,
    )?;
    receipt.validate()?;
    if receipt.source_record_digest != send.source_record_digest()? {
        bail!("response stream receipt does not bind the exact source record bytes");
    }
    let list: HistoryKeyResponseListOutcome = serde_json::from_value(
        kat.pointer("/wire_instances/sequence_ordered_list")
            .cloned()
            .context("response stream KAT omits sequence_ordered_list")?,
    )?;
    list.validate()?;
    let empty: HistoryKeyResponseListOutcome = serde_json::from_value(
        kat.pointer("/wire_instances/empty_list")
            .cloned()
            .context("response stream KAT omits empty_list")?,
    )?;
    empty.validate()?;
    if !empty.ack_entries.is_empty()
        || empty.ack_token.is_some()
        || empty.cursor.is_some()
        || empty.limited
    {
        bail!("response stream empty page is not the canonical non-ack shape");
    }
    let ack: HistoryKeyResponseAckRequest = serde_json::from_value(
        kat.pointer("/wire_instances/ack_request")
            .cloned()
            .context("response stream KAT omits ack_request")?,
    )?;
    ack.validate()?;

    let receipt_bytes =
        arkret_wire::canonical::canonical_json_bytes(&serde_json::to_value(&receipt)?)?;
    let first = URL_SAFE_NO_PAD.decode(
        kat.pointer("/byte_exact/first_receipt_jcs_b64u")
            .and_then(Value::as_str)
            .context("response stream KAT omits first receipt bytes")?,
    )?;
    let retry = URL_SAFE_NO_PAD.decode(
        kat.pointer("/byte_exact/exact_retry_receipt_jcs_b64u")
            .and_then(Value::as_str)
            .context("response stream KAT omits exact retry bytes")?,
    )?;
    if first != receipt_bytes || retry != first {
        bail!("response stream exact retry receipt is not byte-identical");
    }

    let out_of_order: HistoryKeyResponseAckRequest = serde_json::from_value(
        kat.pointer("/negative_cases/2/input")
            .cloned()
            .context("response stream KAT omits out-of-order ack")?,
    )?;
    if out_of_order.validate().is_ok() {
        bail!("response stream KAT accepted an out-of-order ack");
    }
    Ok(())
}

fn verify_client_convergence_kat(fixture: &Value) -> Result<()> {
    let kat = fixture
        .get("client_convergence_kat")
        .context("history fixture omits client_convergence_kat")?;
    let requester = &kat["requester"];
    if requester["trigger"] != "exporter_all_history_missing_epoch"
        || requester["crash_before_create_response"]["durable_pending_intent"] != true
        || requester["crash_before_create_response"]["durable_recipient_hpke_private_key"] != true
        || requester["crash_before_create_response"]["retry_reuses_request_id_and_key"] != true
        || requester["crash_before_create_response"]["live_request_count"] != 1
        || requester["empty_response_page"]["durable_pending_page"] != false
        || requester["empty_response_page"]["ack_sent"] != false
        || requester["empty_response_page"]["high_water_advanced"] != false
        || requester["empty_response_page"]["next_after"] != "last_acked_cursor"
        || requester["empty_response_page"]["later_manifest_visible"] != true
        || requester["temporary_unavailability"]["diagnostic"]
            != "awaiting_authorized_source_response"
        || requester["temporary_unavailability"]["terminal"] != false
        || requester["temporary_unavailability"]["retry_until_request_expiry"] != true
    {
        bail!("history requester convergence KAT drifted");
    }
    let empty: HistoryKeyResponseListOutcome =
        serde_json::from_value(requester["empty_response_page"]["wire"].clone())?;
    empty.validate()?;
    if !empty.ack_entries.is_empty() || empty.ack_token.is_some() || empty.cursor.is_some() {
        bail!("history requester convergence KAT permits an ackable empty page");
    }

    let source = &kat["source"];
    if source["crash_after_ready_marker"]["retry_uses_exact_staged_bytes"] != true
        || source["crash_after_ready_marker"]["new_response_ids"] != false
        || source["later_material"]["completed_attempt_suppresses_new_manifest"] != false
        || source["later_material"]["new_manifest_coverage"] != json!([8])
    {
        bail!("history source convergence KAT drifted");
    }
    let negative_cases = kat["negative_cases"]
        .as_array()
        .context("history convergence KAT omits negative_cases")?;
    for (name, count_field) in [
        ("since_join_missing_prejoin_epoch", "new_request_count"),
        ("requester_not_currently_authorized", "new_request_count"),
        ("source_not_currently_authorized", "new_attempt_count"),
    ] {
        let case = negative_cases
            .iter()
            .find(|case| case["name"] == name)
            .with_context(|| format!("history convergence KAT omits {name}"))?;
        if case[count_field] != 0 {
            bail!("history convergence negative case {name} performed a forbidden write");
        }
    }
    verify_send_rejection_disposition(source)?;
    Ok(())
}

/// Execute the `history-visibility.md` 6.2 rejection-disposition partition.
///
/// The fixture table, the SDK classifier and the operation's closed error
/// surface all have to agree: if any one of them drifts, two conforming sources
/// could split between exact retry, manifest replacement and giving up.
fn verify_send_rejection_disposition(source: &Value) -> Result<()> {
    let kat = source
        .get("send_rejection_disposition")
        .context("history source convergence KAT omits send_rejection_disposition")?;

    let statuses: Vec<&str> = kat["attempt_status_closed_set"]
        .as_array()
        .context("send_rejection_disposition omits attempt_status_closed_set")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if statuses != ["unfinished", "completed", "permanently_rejected", "expired"] {
        bail!("history source attempt status set drifted from the closed four-element set");
    }
    if kat["unfinished_concurrency_counts"] != json!(["unfinished"]) {
        bail!("only unfinished attempts may consume the concurrency budget");
    }
    for field in [
        "transport_failure_disposition",
        "unregistered_code_disposition",
    ] {
        if kat[field] != "retry_same_attempt" {
            bail!("{field} must not churn response ids");
        }
    }

    let table = [
        (
            "retry_same_attempt",
            HistorySourceSendDisposition::RetrySameAttempt,
            HistorySourceSendDisposition::RETRY_SAME_ATTEMPT,
        ),
        (
            "replace_manifest",
            HistorySourceSendDisposition::ReplaceManifest,
            HistorySourceSendDisposition::REPLACE_MANIFEST,
        ),
        (
            "request_terminal",
            HistorySourceSendDisposition::RequestTerminal,
            HistorySourceSendDisposition::REQUEST_TERMINAL,
        ),
    ];
    let mut classified: BTreeSet<String> = BTreeSet::new();
    for (name, expected, sdk_codes) in table {
        let mut fixture_codes: Vec<&str> = kat["dispositions"][name]
            .as_array()
            .with_context(|| format!("send_rejection_disposition omits {name}"))?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        fixture_codes.sort_unstable();
        let mut expected_codes = sdk_codes.to_vec();
        expected_codes.sort_unstable();
        if fixture_codes != expected_codes {
            bail!("fixture {name} codes drifted from the SDK classification: {fixture_codes:?}");
        }
        for code in fixture_codes {
            if HistorySourceSendDisposition::classify(code) != expected {
                bail!("SDK classifies {code} outside {name}");
            }
            if !classified.insert(code.to_owned()) {
                bail!("{code} appears in more than one disposition class");
            }
        }
    }

    // The classification keys on the registered top-level code, so every
    // classified entry must be one, and every top-level code the operation can
    // return must be classified. Entries that are only registered as
    // reason_codes travel under a top-level code; they are covered by naming
    // them in an executable case instead.
    let registry = load_artifact_json("registry/error-code-registry.json")?;
    let top_level: BTreeSet<&str> = registry["codes"]
        .as_array()
        .context("error code registry omits codes[]")?
        .iter()
        .filter_map(|row| row["code"].as_str())
        .collect();
    let reason_codes: BTreeSet<&str> = registry["reason_codes"]
        .as_array()
        .context("error code registry omits reason_codes[]")?
        .iter()
        .filter_map(|row| row["code"].as_str())
        .collect();
    for code in &classified {
        if !top_level.contains(code.as_str()) {
            bail!("{code} is classified but is not a registered top-level error code");
        }
    }

    let case_reason_codes: BTreeSet<&str> = kat["cases"]
        .as_array()
        .context("send_rejection_disposition omits cases[]")?
        .iter()
        .filter_map(|case| case["reason_code"].as_str())
        .collect();

    let mapping = load_artifact_json("registry/operations-error-mapping.json")?;
    let universal = mapping["rules"]["universal_codes"]
        .as_str()
        .context("operations error mapping omits rules.universal_codes")?;
    let operations = mapping["operations"]
        .as_array()
        .context("operations error mapping omits operations[]")?;
    let mut closed: BTreeSet<&str> = universal
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|token| top_level.contains(token))
        .collect();
    for operation_id in kat["operations"]
        .as_array()
        .context("send_rejection_disposition omits operations[]")?
        .iter()
        .filter_map(Value::as_str)
    {
        let entry = operations
            .iter()
            .find(|entry| entry["operation_id"] == operation_id)
            .with_context(|| format!("{operation_id} is not in the operations error mapping"))?;
        for code in entry["operation_specific"]
            .as_array()
            .context("operation entry omits operation_specific[]")?
            .iter()
            .filter_map(Value::as_str)
        {
            if top_level.contains(code) {
                closed.insert(code);
            } else if reason_codes.contains(code) {
                if !case_reason_codes.contains(code) {
                    bail!("reason_code {code} is reachable but no disposition case exercises it");
                }
            } else {
                bail!("{code} is neither a registered code nor a registered reason_code");
            }
        }
    }
    if closed.len() < 20 {
        bail!(
            "universal error surface parsed too small: {} codes",
            closed.len()
        );
    }
    for code in &closed {
        if !classified.contains(*code) {
            bail!("closed error {code} has no source disposition");
        }
    }

    for case in kat["cases"]
        .as_array()
        .context("send_rejection_disposition omits cases[]")?
    {
        let name = required_str(case, "name")?;
        let code = required_str(case, "code")?;
        let expected = required_str(case, "disposition")?;
        let actual = match HistorySourceSendDisposition::classify(code) {
            HistorySourceSendDisposition::RetrySameAttempt => "retry_same_attempt",
            HistorySourceSendDisposition::ReplaceManifest => "replace_manifest",
            HistorySourceSendDisposition::RequestTerminal => "request_terminal",
        };
        if actual != expected {
            bail!("case {name} expects {expected} but the SDK classifies {code} as {actual}");
        }
        let new_manifests = case["new_manifest_count"]
            .as_u64()
            .context("disposition case omits new_manifest_count")?;
        match expected {
            "retry_same_attempt" => {
                if new_manifests != 0
                    || case["attempt_status_after"] != "unfinished"
                    || case["resends_exact_staged_bytes"] != true
                {
                    bail!("case {name} must retry the exact staged bytes without a new manifest");
                }
            }
            "replace_manifest" => {
                if new_manifests != 1
                    || case["attempt_status_after"] != "permanently_rejected"
                    || case["old_attempt_marked_completed"] != false
                {
                    bail!("case {name} must replace the manifest without completing the attempt");
                }
            }
            "request_terminal" => {
                if new_manifests != 0
                    || case["attempt_status_after"] != "permanently_rejected"
                    || case["old_attempt_marked_completed"] != false
                {
                    bail!("case {name} must stop both retry and replacement");
                }
            }
            other => bail!("unknown disposition {other}"),
        }
        if case["restart_before_replacement"] == true
            && case["reverts_to_unfinished_after_restart"] != false
        {
            bail!("case {name} must keep its disposition branch across restart");
        }
    }
    Ok(())
}

fn verify_history_static_gates(fixture: &Value) -> Result<()> {
    let operation_registry = load_artifact_json("registry/operation-registry.json")?;
    let operations = operation_registry["operations"]
        .as_array()
        .context("operation registry omits operations[]")?;
    let mut history_operations = 0_usize;
    for operation in operations {
        let operation_id = operation["operation_id"]
            .as_str()
            .context("operation registry entry omits operation_id")?;
        if !operation_id.contains("history_key") {
            continue;
        }
        history_operations += 1;
        let object = operation
            .as_object()
            .context("operation registry entry is not an object")?;
        if object.contains_key("max_request_body_bytes")
            || object.contains_key("max_response_body_bytes")
        {
            bail!("history operation {operation_id} retains a parallel body-limit field");
        }
        if object
            .get("max_canonical_body_bytes")
            .and_then(Value::as_u64)
            .is_some_and(|limit| limit > 8 * 1024 * 1024)
        {
            bail!("history operation {operation_id} exceeds the general 8 MiB limit");
        }
    }
    if history_operations == 0 {
        bail!("operation registry contains no history-key operations");
    }

    let vector_registry = load_artifact_json("registry/vector-registry.json")?;
    let registered = vector_registry["vectors"]
        .as_array()
        .context("vector registry omits vectors[]")?
        .iter()
        .any(|vector| {
            vector["vector_id"].as_str()
                == Some("ak.vector.history_key.frontier_traversal_split.v1")
        });
    if !registered
        || !fixture["covers_vectors"]
            .as_array()
            .context("history-key fixture omits covers_vectors[]")?
            .iter()
            .any(|vector| {
                vector.as_str() == Some("ak.vector.history_key.frontier_traversal_split.v1")
            })
    {
        bail!("history frontier/direct-traversal split vector is not closed in registry+fixture");
    }
    Ok(())
}

fn sha256_hash(bytes: &[u8]) -> arkret_wire::Result<Hash> {
    Ok(Hash::new(arkret_canonical::sha256_digest(bytes))?)
}

fn verify_history_digest_and_sender_kats(fixture: &Value) -> Result<()> {
    let sender_kat = fixture
        .pointer("/sender_crypto_kats")
        .context("history-key fixture omits sender_crypto_kats")?;
    let authoritative_name = sender_kat["authoritative_fixture"]
        .as_str()
        .context("history sender KAT omits authoritative_fixture")?;
    if authoritative_name != "arkret-private-kdf-fixture.json" {
        bail!("history sender KAT points at a non-authoritative fixture");
    }
    let authoritative = load_artifact_json(&format!("fixtures/{authoritative_name}"))?;
    let authoritative_cases = authoritative["cases"]
        .as_array()
        .context("private KDF fixture omits cases[]")?;
    for link in sender_kat["cases"]
        .as_array()
        .context("history sender KAT omits cases[]")?
    {
        let case_ref = link["case_ref"]
            .as_str()
            .context("history sender KAT link omits case_ref")?;
        let target = authoritative_cases
            .iter()
            .find(|case| case["name"].as_str() == Some(case_ref))
            .with_context(|| format!("history sender KAT target {case_ref} is absent"))?;
        if target
            .pointer("/expected/content_key_hex")
            .and_then(Value::as_str)
            != link["expected_content_key_hex"].as_str()
        {
            bail!("history sender KAT {case_ref} drifted from its authoritative key bytes");
        }
    }

    let observation_kat = fixture
        .pointer("/history_source_agent_observation_digest_kat")
        .context("history-key fixture omits source Agent observation digest KAT")?;
    let input: HistorySourceAgentObservationInput =
        serde_json::from_value(observation_kat["preimage"].clone())?;
    input.validate()?;
    let expected_observation = observation_kat["expected_digest"]
        .as_str()
        .context("source Agent observation KAT omits expected_digest")?;
    if input.history_source_agent_observation_digest()?.as_str() != expected_observation {
        bail!("history source Agent observation digest drifted");
    }
    for branch in ["signing_input_a", "signing_input_b"] {
        let signing_input: HistoryKeyResponseSigningInput =
            serde_json::from_value(observation_kat[branch].clone())?;
        signing_input.validate()?;
        if signing_input
            .history_source_agent_observation_digest()?
            .as_str()
            != expected_observation
        {
            bail!("history signer evidence coordinates leaked into the observation digest");
        }
    }
    let mut mutated_content = observation_kat["preimage"].clone();
    mutated_content["content"]["chunks"][0]["chunk_response_id"] =
        json!("ak:history_response:019c0000-0000-7000-8000-000000000003");
    let mutated: HistorySourceAgentObservationInput = serde_json::from_value(mutated_content)?;
    if mutated.history_source_agent_observation_digest()?.as_str() == expected_observation {
        bail!("history source Agent observation digest ignored response content");
    }
    Ok(())
}

fn verify_governance_dependency_kats(fixture: &Value) -> Result<()> {
    let signer_kat = fixture
        .pointer("/authenticated_signer_resolution_evidence_kat")
        .context("history-key fixture omits authenticated signer evidence KAT")?;
    let signer_evidence: AuthenticatedSignerResolutionEvidence =
        serde_json::from_value(signer_kat["evidence"].clone())?;
    let signer_digest = signer_evidence.canonical_sha256_digest()?;
    if signer_digest.as_str()
        != signer_kat["evidence_digest"]
            .as_str()
            .context("signer evidence KAT omits evidence_digest")?
        || signer_evidence.evidence_ref()?.as_ref()
            != signer_kat["evidence_ref"]
                .as_str()
                .context("signer evidence KAT omits evidence_ref")?
        || arkret_canonical::canonical::canonical_json_bytes(&signer_evidence)?.len() as u64
            != signer_kat["canonical_bytes"]
                .as_u64()
                .context("signer evidence KAT omits canonical_bytes")?
    {
        bail!("authenticated signer evidence KAT drifted");
    }

    let dependency_kat = fixture
        .pointer("/governance_dependency_resolve_kat")
        .context("history-key fixture omits governance dependency resolve KAT")?;
    let receipt: AvailabilityReceipt =
        serde_json::from_value(dependency_kat["availability_receipt"].clone())?;
    receipt.validate_structural()?;
    let expected_receipt_digest = Hash::new(
        dependency_kat["availability_receipt_digest"]
            .as_str()
            .context("governance dependency KAT omits availability_receipt_digest")?,
    )?;
    let receipt_digest_suite = expected_receipt_digest.digest_suite()?;
    let computed_receipt_digest = receipt.full_receipt_digest(|bytes| {
        Ok(Hash::new(arkret_canonical::canonical::digest(
            receipt_digest_suite,
            bytes,
        ))?)
    })?;
    if computed_receipt_digest != expected_receipt_digest {
        bail!("availability receipt full digest drifted");
    }
    receipt.validate_signature_payload_digest(sha256_hash)?;

    let outcome: GovernanceDependencyResolveOutcome =
        serde_json::from_value(dependency_kat["resolve_outcome"].clone())?;
    outcome.validate()?;

    let mut branch_mismatch = dependency_kat["resolve_outcome"].clone();
    let items = branch_mismatch["items"]
        .as_array_mut()
        .context("governance dependency outcome omits items")?;
    let availability = items
        .iter()
        .find_map(|item| item.get("availability_receipt").cloned())
        .context("governance dependency outcome omits availability receipt")?;
    let signer_item = items
        .iter_mut()
        .find(|item| {
            item.get("authenticated_signer_resolution_evidence")
                .is_some()
        })
        .context("governance dependency outcome omits signer evidence")?;
    signer_item
        .as_object_mut()
        .context("governance dependency item is not an object")?
        .remove("authenticated_signer_resolution_evidence");
    signer_item
        .as_object_mut()
        .context("governance dependency item is not an object")?
        .insert("availability_receipt".to_owned(), availability);
    let mismatched: GovernanceDependencyResolveOutcome = serde_json::from_value(branch_mismatch)?;
    mismatched
        .validate()
        .expect_err("selector/payload branch mismatch must fail closed");
    Ok(())
}

fn fixture_limit(kat: &Value, name: &str) -> Result<u64> {
    kat.pointer(&format!("/limits/{name}"))
        .and_then(Value::as_u64)
        .with_context(|| format!("candidate-store KAT omits limits.{name}"))
}

fn candidate_digest(byte: u8) -> Result<Hash> {
    Ok(Hash::new(arkret_wire::canonical::sha256_digest(
        [byte; 32],
    ))?)
}

fn candidate_material_key(
    effective_scope: &HistoryEffectiveScope,
    candidate_digest: Hash,
) -> Result<HistoryCandidateMaterialKey> {
    Ok(HistoryCandidateMaterialKey {
        mls_group_id: effective_scope.canonical_mls_group_id()?,
        effective_scope: effective_scope.clone(),
        epoch: 4,
        candidate_digest,
    })
}

fn candidate_attribution(
    effective_scope: &HistoryEffectiveScope,
    candidate_byte: u8,
    sender_domain: &str,
    response_index: u8,
    now: DateTime<Utc>,
) -> Result<HistoryCandidateOriginAttribution> {
    Ok(HistoryCandidateOriginAttribution::ResponseSender {
        material_key: candidate_material_key(effective_scope, candidate_digest(candidate_byte)?)?,
        origin_quota_domain: ResponseSenderQuotaDomain {
            source_sender_domain: sender_domain.to_owned(),
        },
        origin_ref: ResponseSenderOriginRef {
            response_id: HistoryResponseId::new(format!(
                "ak:history_response:019a0000-0000-7000-8000-0000000000{response_index:02x}"
            ))?,
            source_record_digest: candidate_digest(0xf0 ^ response_index)?,
        },
        first_observed_at: now,
    })
}

fn candidate_binding_key(
    material_key: &HistoryCandidateMaterialKey,
) -> Result<EventCandidateBindingKey> {
    Ok(EventCandidateBindingKey {
        effective_scope: material_key.effective_scope.clone(),
        mls_group_id: material_key.mls_group_id.clone(),
        epoch: material_key.epoch,
        event_id: EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?,
        verified_sender_domain: "ak:device:sender".to_owned(),
    })
}

fn verify_history_candidate_store_kat(fixture: &Value) -> Result<()> {
    let kat = fixture
        .pointer("/candidate_store_kat")
        .context("history-key fixture omits candidate_store_kat")?;
    let declared_limits = [
        (
            "received_candidates_per_scope_group_epoch",
            HISTORY_STORE_LIMITS.max_received_candidates_per_scope_group_epoch as u64,
        ),
        (
            "origin_attributions_per_candidate",
            HISTORY_STORE_LIMITS.max_origin_attributions_per_candidate as u64,
        ),
        (
            "origin_attributions_per_scope_group_epoch",
            HISTORY_STORE_LIMITS.max_origin_attributions_per_scope_group_epoch as u64,
        ),
        (
            "origin_attributions_per_scope_group_epoch_quota_domain",
            HISTORY_STORE_LIMITS.max_origin_attributions_per_scope_group_epoch_quota_domain as u64,
        ),
        (
            "origin_attribution_ttl_seconds",
            HISTORY_STORE_LIMITS.origin_attribution_ttl_seconds as u64,
        ),
        (
            "event_candidate_bindings_per_scope_group_epoch",
            HISTORY_STORE_LIMITS.max_event_candidate_bindings_per_scope_group_epoch as u64,
        ),
        (
            "event_candidate_binding_ttl_seconds",
            HISTORY_STORE_LIMITS.event_candidate_binding_ttl_seconds as u64,
        ),
    ];
    for (name, generated) in declared_limits {
        if fixture_limit(kat, name)? != generated {
            bail!("candidate-store fixture limit {name} drifted from generated registry");
        }
    }

    let effective_scope = HistoryEffectiveScope::Realm {
        realm_id: RealmId::new(TRAVERSAL_REALM_ID)?,
    };
    let now = DateTime::parse_from_rfc3339("2026-08-22T12:00:00Z")?.with_timezone(&Utc);
    let mut ledger = HistoryMaterialLedger::default();

    let first = candidate_attribution(&effective_scope, 1, "sender.one", 1, now)?;
    let first_plan = ledger.admit_received_candidate(&first, now)?;
    let first_sequence = ledger
        .resident
        .first()
        .context("first received candidate did not become resident")?
        .material_received_sequence;
    let second_origin = candidate_attribution(&effective_scope, 1, "sender.two", 2, now)?;
    let duplicate_plan = ledger.admit_received_candidate(&second_origin, now)?;
    if first_plan.store.is_none()
        || duplicate_plan.store.is_some()
        || !duplicate_plan.resident
        || ledger.resident.len() != 1
        || ledger.origins.len() != 2
        || ledger.resident[0].material_received_sequence != first_sequence
    {
        bail!("candidate-store exact-byte dedupe or immutable sequence rule drifted");
    }

    for candidate_byte in 2..=8_u8 {
        let attribution = candidate_attribution(
            &effective_scope,
            candidate_byte,
            "sender.one",
            candidate_byte + 1,
            now,
        )?;
        let _ = ledger.admit_received_candidate(&attribution, now)?;
    }
    let first_key = candidate_material_key(&effective_scope, candidate_digest(1)?)?;
    let successful_binding = EventCandidateBinding::new(
        candidate_binding_key(&first_key)?,
        candidate_digest(1)?,
        EventCandidateBindingOutcome::Success,
        now,
    )?;
    ledger.record_event_binding(&successful_binding, now)?;

    let ninth = candidate_attribution(&effective_scope, 9, "sender.one", 10, now)?;
    let ninth_plan = ledger.admit_received_candidate(&ninth, now)?;
    let second_key = candidate_material_key(&effective_scope, candidate_digest(2)?)?;
    if ninth_plan.evict != vec![second_key.clone()]
        || ninth_plan.store
            != Some(candidate_material_key(
                &effective_scope,
                candidate_digest(9)?,
            )?)
        || ledger.resident.len()
            != HISTORY_STORE_LIMITS.max_received_candidates_per_scope_group_epoch
        || !ledger
            .resident
            .iter()
            .any(|entry| entry.material_key == first_key)
        || ledger
            .resident
            .iter()
            .any(|entry| entry.material_key == second_key)
        || ledger.origins.len() != 10
    {
        bail!("candidate-store two-tier eviction or bounded tombstone rule drifted");
    }

    let failure_key = candidate_material_key(&effective_scope, candidate_digest(3)?)?;
    let failure = EventCandidateBinding::new(
        candidate_binding_key(&failure_key)?,
        candidate_digest(3)?,
        EventCandidateBindingOutcome::Failure,
        now,
    )?;
    ledger.record_event_binding(&failure, now)?;
    let contradiction = EventCandidateBinding::new(
        failure.event_binding_key.clone(),
        failure.candidate_digest.clone(),
        EventCandidateBindingOutcome::Success,
        now,
    )?;
    ledger
        .record_event_binding(&contradiction, now)
        .expect_err("contradictory exact Event/candidate binding must fail closed");

    let expired_attribution = candidate_attribution(&effective_scope, 10, "sender.one", 11, now)?;
    ledger
        .admit_received_candidate(
            &expired_attribution,
            expired_attribution.expires_at()? + chrono::Duration::seconds(1),
        )
        .expect_err("expired candidate attribution must not be renewed");
    Ok(())
}

fn verify_scope_and_endpoint_kats(fixture: &Value) -> Result<()> {
    let cases = fixture
        .pointer("/scope_and_endpoint_kats")
        .and_then(Value::as_array)
        .context("history-key fixture omits scope_and_endpoint_kats")?;
    for case in cases {
        for branch in ["realm", "circle"] {
            let Some(scope_case) = case.get(branch) else {
                continue;
            };
            let scope: HistoryEffectiveScope =
                serde_json::from_value(scope_case["effective_scope"].clone())?;
            let scope_key = match &scope {
                HistoryEffectiveScope::Realm { realm_id } => realm_id.as_str().as_bytes(),
                HistoryEffectiveScope::Circle { circle_id, .. } => circle_id.as_str().as_bytes(),
            };
            let declared_scope_key = hex::decode(
                scope_case["effective_scope_key_hex"]
                    .as_str()
                    .context("scope KAT omits effective_scope_key_hex")?,
            )?;
            let expected_group_id = scope_case["expected_mls_group_id"]
                .as_str()
                .context("scope KAT omits expected_mls_group_id")?;
            if declared_scope_key != scope_key
                || URL_SAFE_NO_PAD.encode(scope_key) != expected_group_id
                || scope.canonical_mls_group_id()? != expected_group_id
            {
                bail!(
                    "scope/group KAT {}.{branch} disagrees with the production canonical scope key",
                    case["name"].as_str().unwrap_or("unnamed")
                );
            }
        }
        if case["name"].as_str() == Some("standard_fresh_endpoint_floor") {
            let inputs = &case["inputs"];
            let expected = &case["expected"];
            let pre = inputs["pre_admission_epochs"]
                .as_array()
                .context("standard fresh endpoint KAT omits pre_admission_epochs")?;
            let winning = inputs["winning_add_epoch"]
                .as_u64()
                .context("standard fresh endpoint KAT omits winning_add_epoch")?;
            let post = inputs["post_admission_commit_epochs"]
                .as_array()
                .context("standard fresh endpoint KAT omits post-admission epochs")?;
            let mut decryptable = vec![winning];
            decryptable.extend(post.iter().filter_map(Value::as_u64));
            if case["content_scheme"].as_str() != Some("mls_rfc9420")
                || expected["decryptable_epochs"]
                    .as_array()
                    .context("standard fresh endpoint KAT omits decryptable_epochs")?
                    .iter()
                    .filter_map(Value::as_u64)
                    .ne(decryptable)
                || expected["rejected_pre_admission_epochs"].as_u64() != Some(pre.len() as u64)
                || pre
                    .iter()
                    .filter_map(Value::as_u64)
                    .any(|epoch| epoch >= winning)
                || expected["history_key_requests_allowed"].as_u64() != Some(0)
                || expected["foreign_active_mls_state_imports_allowed"].as_u64() != Some(0)
            {
                bail!("standard fresh endpoint floor KAT drifted");
            }
            let model = &case["deterministic_model"];
            if model["algorithm"].as_str() != Some("ak.standard-fresh-endpoint-model.v1")
                || model["initial_state"]["admitted"].as_bool() != Some(false)
                || !model["initial_state"]["current_epoch"].is_null()
            {
                bail!("standard fresh endpoint deterministic model is missing or changed");
            }
            let seed = hex::decode(
                case["seed_hex"]
                    .as_str()
                    .context("standard fresh endpoint KAT omits seed_hex")?,
            )?;
            for tag in model["transition_tags"]
                .as_array()
                .context("standard fresh endpoint KAT omits transition_tags")?
            {
                let operation = tag["operation"]
                    .as_str()
                    .context("fresh endpoint transition omits operation")?;
                let epoch = tag["epoch"]
                    .as_u64()
                    .context("fresh endpoint transition omits epoch")?;
                let mut preimage = seed.clone();
                preimage.push(0);
                preimage.extend_from_slice(operation.as_bytes());
                preimage.extend_from_slice(&epoch.to_be_bytes());
                if arkret_canonical::sha256_hex(preimage)
                    != tag["sha256_hex"].as_str().unwrap_or_default()
                {
                    bail!("standard fresh endpoint transition tag drifted at epoch {epoch}");
                }
            }
        }
    }
    Ok(())
}

fn verify_rrk_method_evaluator(fixture: &Value) -> Result<()> {
    use arkret_identity::history_recovery::resolve_realm_history_recovery_key;

    let kat = fixture
        .get("rrk_registration_rotation_kat")
        .context("history fixture omits rrk_registration_rotation_kat")?;
    let document = kat
        .pointer("/did_documents/register")
        .cloned()
        .context("RRK KAT omits register DID Document")?;
    let key_tuple = kat
        .pointer("/events/register/payload/new_key_tuple")
        .context("RRK KAT omits register key tuple")?;
    let principal_id = DidCoreId::new(
        key_tuple["holder_principal_id"]
            .as_str()
            .context("RRK tuple omits holder_principal_id")?,
    )?;
    let verification_method = DidUrl::new(
        key_tuple["key_agreement_ref"]
            .as_str()
            .context("RRK tuple omits key_agreement_ref")?,
    )
    .map_err(|err| anyhow::anyhow!(err))?;
    let expected_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            key_tuple["frozen_public_key_b64u"]
                .as_str()
                .context("RRK tuple omits frozen_public_key_b64u")?,
        )?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("RRK frozen key is {} bytes", bytes.len()))?;
    let resolved = resolve_realm_history_recovery_key(
        key_tuple["recovery_key_id"]
            .as_str()
            .unwrap_or("rrk-fixture"),
        &principal_id,
        &verification_method,
        &document,
    )?;
    if resolved.hpke_public_key != expected_key
        || resolved.principal_id != principal_id
        || resolved.verification_method != verification_method
    {
        bail!("RRK exact method evaluator returned a different recipient tuple");
    }

    let mutations = [
        (
            "wrong_controller",
            "/verificationMethod/0/controller",
            json!("ak:did_core:web:other.example"),
        ),
        ("missing_key_agreement", "/keyAgreement", json!([])),
        (
            "wrong_method_type",
            "/verificationMethod/0/type",
            json!("JsonWebKey2020"),
        ),
    ];
    for (name, pointer, replacement) in mutations {
        let mut mutated = document.clone();
        *mutated
            .pointer_mut(pointer)
            .with_context(|| format!("RRK mutation {name} pointer is absent"))? = replacement;
        if resolve_realm_history_recovery_key(
            key_tuple["recovery_key_id"]
                .as_str()
                .unwrap_or("rrk-fixture"),
            &principal_id,
            &verification_method,
            &mutated,
        )
        .is_ok()
        {
            bail!("RRK exact method evaluator accepted {name}");
        }
    }

    let mut duplicate_method = document.clone();
    let duplicate = duplicate_method["verificationMethod"][0].clone();
    duplicate_method["verificationMethod"]
        .as_array_mut()
        .context("RRK DID Document verificationMethod is not an array")?
        .push(duplicate);
    resolve_realm_history_recovery_key(
        key_tuple["recovery_key_id"]
            .as_str()
            .unwrap_or("rrk-fixture"),
        &principal_id,
        &verification_method,
        &duplicate_method,
    )
    .expect_err("RRK exact method evaluator must reject multiple matching methods");

    let mut wrong_curve = document.clone();
    let mut ed25519_key = vec![0xed, 0x01];
    ed25519_key.extend_from_slice(&expected_key);
    wrong_curve["verificationMethod"][0]["publicKeyMultibase"] = json!(
        arkret_canonical::multibase::encode_multibase_base58btc(ed25519_key)
    );
    resolve_realm_history_recovery_key(
        key_tuple["recovery_key_id"]
            .as_str()
            .unwrap_or("rrk-fixture"),
        &principal_id,
        &verification_method,
        &wrong_curve,
    )
    .expect_err("RRK exact method evaluator must reject a non-X25519 multicodec key");

    let mut wrong_length = document.clone();
    let mut short_x25519_key = vec![0xec, 0x01];
    short_x25519_key.extend_from_slice(&expected_key[..31]);
    wrong_length["verificationMethod"][0]["publicKeyMultibase"] = json!(
        arkret_canonical::multibase::encode_multibase_base58btc(short_x25519_key)
    );
    resolve_realm_history_recovery_key(
        key_tuple["recovery_key_id"]
            .as_str()
            .unwrap_or("rrk-fixture"),
        &principal_id,
        &verification_method,
        &wrong_length,
    )
    .expect_err("RRK exact method evaluator must reject a non-32-byte X25519 key");

    let mut unrelated_service = document;
    unrelated_service["service"] = json!([{"type": "UnrelatedService"}]);
    resolve_realm_history_recovery_key(
        key_tuple["recovery_key_id"]
            .as_str()
            .unwrap_or("rrk-fixture"),
        &principal_id,
        &verification_method,
        &unrelated_service,
    )
    .context("RRK DID service designation must not be required")?;

    let mutation_names = kat["negative_mutations"]
        .as_array()
        .context("RRK KAT omits negative_mutations")?
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect::<BTreeSet<_>>();
    for required in [
        "wrong_curve",
        "wrong_method_type",
        "wrong_key_length",
        "wrong_controller",
        "wrong_holder_proof_domain",
        "holder_tuple_mismatch",
        "register_before_realm_create",
        "rotate_before_register",
        "rotate_missing_head_eq",
        "rotate_stale_head_eq",
        "rotate_provenance_event_mismatch",
        "rotate_provenance_seal_mismatch",
    ] {
        if !mutation_names.contains(required) {
            bail!("RRK fixture omits required mutation {required}");
        }
    }
    Ok(())
}

const REPLAY_KAT_CREATED_AT: &str = "2026-08-22T12:00:00Z";

struct ReplayKatMaterial {
    request: DirectCutRequest,
    historical_descriptor: NotarySignerDescriptor,
    current_descriptor: NotarySignerDescriptor,
    genesis_event: Event,
    successor_event: Event,
    genesis_seal: Seal,
    successor_seal: Seal,
    current_seed: [u8; 32],
}

fn replay_kat_seed(value: &Value, pointer: &str) -> Result<[u8; 32]> {
    let encoded = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .with_context(|| format!("replay KAT omits {pointer}"))?;
    URL_SAFE_NO_PAD
        .decode(encoded)
        .context("replay KAT seed is not canonical base64url")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("replay KAT seed is {} bytes, expected 32", bytes.len()))
}

fn replay_kat_cell(family: &str) -> Result<CellRef> {
    Ok(CellRef::new(null_subject_cell(family))?)
}

fn replay_kat_set(cell: CellRef, value: Value) -> ProjectedCellWrite {
    let mut op = LatticeOp::empty();
    op.op_type = LatticeOpType::Set;
    op.value = Some(value);
    ProjectedCellWrite {
        cell,
        op: ProjectedOp::Direct(op),
    }
}

fn replay_kat_projection(
    event: &Event,
    _suite: arkret_canonical::DigestSuite,
) -> std::result::Result<Vec<ProjectedCellWrite>, String> {
    if event.kind != EventKind::RealmCreate {
        return Ok(Vec::new());
    }
    let notary = event
        .payload
        .get("object")
        .and_then(|object| object.get("notary"))
        .cloned()
        .ok_or_else(|| "replay KAT Genesis omits notary".to_owned())?;
    Ok(vec![
        replay_kat_set(
            replay_kat_cell(CellFamilyId::NOTARY_V1).map_err(|error| error.to_string())?,
            notary,
        ),
        replay_kat_set(
            replay_kat_cell(CellFamilyId::REALM_DIGEST_SUITE_V1)
                .map_err(|error| error.to_string())?,
            json!("sha256"),
        ),
    ])
}

fn attach_replay_kat_proof(event: &mut Event, verification_method: &DidUrl) -> Result<()> {
    let event_digest =
        Hash::new(event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?)?;
    let signer_evidence_digest = Hash::new(format!("sha256:{}", "91".repeat(32)))?;
    event.proofs = vec![ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        event_digest,
        signer_resolution_evidence_ref: Some(arkret_wire::SignerEvidenceRef::new(format!(
            "ak:signer_evidence:{}",
            signer_evidence_digest.as_str()
        ))?),
        signer_resolution_evidence_digest: Some(signer_evidence_digest),
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZDI1NTE5In0..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
    }
    .into()];
    Ok(())
}

fn sign_replay_kat_seal(seal: &mut Seal, seed: [u8; 32], method: &DidUrl) -> Result<()> {
    let body = seal.canonical_bytes_for_id()?;
    seal.id = Seal::id_from_canonical_bytes(&body, arkret_canonical::DigestSuite::Sha256)?;
    let protected = arkret_canonical::canonical::canonical_json_bytes(&json!({
        "alg": "Ed25519",
        "kid": method,
    }))?;
    let protected = URL_SAFE_NO_PAD.encode(protected);
    let signing_input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(&body));
    let signature = SigningKey::from_bytes(&seed).sign(signing_input.as_bytes());
    seal.notary_signature = NotarySig::Single(SealSignature {
        verification_method: method.clone(),
        payload_digest: Hash::new(arkret_canonical::digest(
            arkret_canonical::DigestSuite::Sha256,
            &body,
        ))?,
        jws: format!(
            "{protected}..{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
    });
    Ok(())
}

struct ReplayKatSealInput<'a> {
    realm_id: RealmId,
    predecessor_refs: Vec<SealId>,
    delta: Vec<Hash>,
    state_root: Hash,
    notary_seq: u64,
    seed: [u8; 32],
    method: &'a DidUrl,
}

fn replay_kat_seal(
    input: ReplayKatSealInput<'_>,
    covered_events: &[(Event, arkret_canonical::DigestSuite)],
) -> Result<Seal> {
    let ReplayKatSealInput {
        realm_id,
        predecessor_refs,
        delta,
        state_root,
        notary_seq,
        seed,
        method,
    } = input;
    let covered = covered_events
        .iter()
        .map(|(event, suite)| Ok(Hash::new(event.event_digest_with_digest_suite(*suite)?)?))
        .collect::<Result<BTreeSet<_>>>()?;
    let control_event_set_root =
        arkret_state::control_event_set_root(&covered, arkret_canonical::DigestSuite::Sha256)?;
    let completeness_root = arkret_state::control_event_completeness_root(
        covered_events,
        &covered,
        arkret_canonical::DigestSuite::Sha256,
    )?;
    let placeholder = Hash::new(format!("sha256:{}", "00".repeat(32)))?;
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))?,
        realm_id,
        predecessor_refs,
        delta,
        control_event_set_root,
        state_root,
        completeness_root,
        notary_seq,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: covered.into_iter().collect(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(SealSignature {
            verification_method: method.clone(),
            payload_digest: placeholder,
            jws: "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYjpyZXBsYXkta2F0LmV4YW1wbGUjbm90YXJ5LWtleS0xIn0..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        }),
        sealed_at: REPLAY_KAT_CREATED_AT.parse()?,
        hlc: Hlc::new("0198d35d9800-0000-a13f9c2e")?,
    };
    sign_replay_kat_seal(&mut seal, seed, method)?;
    Ok(seal)
}

fn build_replay_kat_material(kat: &Value) -> Result<ReplayKatMaterial> {
    let signing = kat
        .get("signing_inputs")
        .context("replay KAT omits signing_inputs")?;
    let historical_descriptor: NotarySignerDescriptor =
        serde_json::from_value(signing["historical_descriptor"].clone())?;
    let current_descriptor: NotarySignerDescriptor =
        serde_json::from_value(signing["current_same_method_descriptor"].clone())?;
    historical_descriptor.validate()?;
    current_descriptor.validate()?;
    if historical_descriptor.verification_method != current_descriptor.verification_method
        || historical_descriptor.frozen_public_key_b64u == current_descriptor.frozen_public_key_b64u
    {
        bail!("replay KAT must use one method id with two different keys");
    }
    let historical_seed = replay_kat_seed(kat, "/signing_inputs/historical_seed_b64u")?;
    let current_seed = replay_kat_seed(kat, "/signing_inputs/current_seed_b64u")?;
    let historical_key = SigningKey::from_bytes(&historical_seed).verifying_key();
    let current_key = SigningKey::from_bytes(&current_seed).verifying_key();
    if URL_SAFE_NO_PAD.encode(historical_key.to_bytes())
        != historical_descriptor.frozen_public_key_b64u
        || URL_SAFE_NO_PAD.encode(current_key.to_bytes())
            != current_descriptor.frozen_public_key_b64u
    {
        bail!("replay KAT seed does not derive its frozen public key");
    }

    let actor_full_id = DidFullId::new(
        signing["actor_full_id"]
            .as_str()
            .context("replay KAT omits actor_full_id")?
            .to_owned(),
    )?;
    let actor_id = DidCoreId::new(
        signing["actor_id"]
            .as_str()
            .context("replay KAT omits actor_id")?
            .to_owned(),
    )?;
    let method = historical_descriptor.verification_method.clone();
    let notary = NotaryValue::single_signer(historical_descriptor.clone());
    let created_at = DateTime::parse_from_rfc3339(REPLAY_KAT_CREATED_AT)?.with_timezone(&Utc);
    let mut genesis_event = arkret_wire::test_support::raw_event_at(
        EventKind::RealmCreate.to_string(),
        ScopeRef::RealmGenesis,
        actor_id.clone(),
        actor_id.clone(),
        0,
        Hlc::new("0198d35d9800-0000-a13f9c2e")?,
        json!({"object": {"digest_algorithm": "sha256", "notary": notary}}),
        created_at,
    )?;
    attach_replay_kat_proof(&mut genesis_event, &method)?;
    let realm_id = genesis_event.realm_id.clone();

    let notary_cell = replay_kat_cell(CellFamilyId::NOTARY_V1)?;
    let digest_suite_cell = replay_kat_cell(CellFamilyId::REALM_DIGEST_SUITE_V1)?;
    let state = BTreeMap::from([
        (
            notary_cell,
            CellState::Value(serde_json::to_value(&notary)?),
        ),
        (digest_suite_cell, CellState::Value(json!("sha256"))),
    ]);
    let state_root = compute_state_root(&state, arkret_canonical::DigestSuite::Sha256)?;
    let genesis_digest = Hash::new(
        genesis_event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
    )?;
    let genesis_seal = replay_kat_seal(
        ReplayKatSealInput {
            realm_id: realm_id.clone(),
            predecessor_refs: Vec::new(),
            delta: vec![genesis_digest],
            state_root: state_root.clone(),
            notary_seq: 0,
            seed: historical_seed,
            method: &method,
        },
        &[(genesis_event.clone(), arkret_canonical::DigestSuite::Sha256)],
    )?;

    let mut successor_event = arkret_wire::test_support::raw_event_at(
        EventKind::PolicySet.to_string(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id.clone(),
        actor_id,
        1,
        Hlc::new("0198d35d9800-0001-a13f9c2e")?,
        json!({"variant": "successor"}),
        created_at,
    )?;
    successor_event.prev_refs = vec![genesis_event.event_id.clone()];
    successor_event.seal_basis = Some(SealBasis {
        leaves: vec![genesis_seal.id.clone()],
    });
    successor_event
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    attach_replay_kat_proof(&mut successor_event, &method)?;
    let successor_digest = Hash::new(
        successor_event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
    )?;
    let successor_seal = replay_kat_seal(
        ReplayKatSealInput {
            realm_id: realm_id.clone(),
            predecessor_refs: vec![genesis_seal.id.clone()],
            delta: vec![successor_digest],
            state_root,
            notary_seq: 1,
            seed: historical_seed,
            method: &method,
        },
        &[
            (genesis_event.clone(), arkret_canonical::DigestSuite::Sha256),
            (
                successor_event.clone(),
                arkret_canonical::DigestSuite::Sha256,
            ),
        ],
    )?;
    let request = DirectCutRequest {
        realm_id,
        trusted_history_base_basis: SealBasis {
            leaves: vec![genesis_seal.id.clone()],
        },
        trusted_current_basis: SealBasis {
            leaves: vec![genesis_seal.id.clone()],
        },
        target_basis: SealBasis {
            leaves: vec![successor_seal.id.clone()],
        },
    };
    if actor_full_id.as_str()
        != method
            .as_str()
            .split_once('#')
            .map(|pair| pair.0)
            .unwrap_or("")
    {
        bail!("replay KAT method controller drifted from actor_full_id");
    }
    Ok(ReplayKatMaterial {
        request,
        historical_descriptor,
        current_descriptor,
        genesis_event,
        successor_event,
        genesis_seal,
        successor_seal,
        current_seed,
    })
}

fn replay_registry() -> MemoryCellRegistry {
    let mut registry = MemoryCellRegistry::empty();
    registry.register(
        CellFamilyId::NOTARY_V1,
        LatticeKind::CasRegister,
        BottomMode::Reject,
    );
    registry.register(
        CellFamilyId::REALM_DIGEST_SUITE_V1,
        LatticeKind::CasRegister,
        BottomMode::Reject,
    );
    registry
}

fn verify_direct_traversal_replay_kat(kat: &Value) -> Result<()> {
    let material = build_replay_kat_material(kat)?;
    let source = DirectCutMaterial::new(
        [
            material.genesis_seal.clone(),
            material.successor_seal.clone(),
        ],
        [
            material.genesis_event.clone(),
            material.successor_event.clone(),
        ]
        .into_iter()
        .map(|event| {
            Ok((
                Hash::new(
                    event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
                )?,
                event,
            ))
        })
        .collect::<Result<Vec<_>>>()?,
    )?;
    let mut replayed = 0_u64;
    let mut committed_successors = 0_u64;
    let verified = verify_direct_traversal_cut_with_registry(
        &material.request,
        &source,
        &mut BoundedDirectTraversalJournal::default(),
        &[],
        &replay_registry(),
        arkret_signatures::verify_frozen_notary_signature,
        |_event, _suite, _dependencies| Ok(()),
        |_seal, _notary, _context, _dependencies| Ok(()),
        replay_kat_projection,
        &mut |seal, _delta| {
            replayed += 1;
            if !seal.predecessor_refs.is_empty() {
                committed_successors += 1;
            }
            Ok(())
        },
    )?;
    if replayed != 2 || committed_successors != 1 {
        bail!(
            "historical-key positive replay committed {replayed} Seals/{committed_successors} successors"
        );
    }
    let notary_cell = replay_kat_cell(CellFamilyId::NOTARY_V1)?;
    let expected_notary = serde_json::to_value(NotaryValue::single_signer(
        material.historical_descriptor.clone(),
    ))?;
    if verified.effective_state.get(&notary_cell) != Some(&CellState::Value(expected_notary)) {
        bail!("positive replay did not derive the historical notary from Genesis state");
    }

    let ambiguous = kat["cases"]
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["name"] == "ambiguous_delta_resolver_response")
        })
        .context("replay KAT omits ambiguous_delta_resolver_response")?;
    let claimed = Hash::new(
        ambiguous["injection"]["claimed_digest"]
            .as_str()
            .context("ambiguous replay KAT omits claimed_digest")?,
    )?;
    let variant_a = material.successor_event.clone();
    let mut variant_b = variant_a.clone();
    variant_b.payload.insert("variant".to_owned(), json!("b"));
    let ambiguous_replayed = 0_u64;
    let error = DirectCutMaterial::new(
        Vec::<Seal>::new(),
        [(claimed.clone(), variant_a), (claimed, variant_b)],
    )
    .expect_err("ambiguous material must be rejected before replay");
    if !error
        .to_string()
        .contains("ambiguous direct traversal material")
        || ambiguous_replayed != 0
    {
        bail!("ambiguous material did not reject at ingestion with zero replay: {error}");
    }

    let mut substituted_successor = material.successor_seal.clone();
    sign_replay_kat_seal(
        &mut substituted_successor,
        material.current_seed,
        &material.current_descriptor.verification_method,
    )?;
    if substituted_successor.id != material.successor_seal.id {
        bail!("changing only a Seal signature changed the Seal id");
    }
    let substituted_source =
        DirectCutMaterial::new(
            [material.genesis_seal, substituted_successor],
            [material.genesis_event, material.successor_event]
                .into_iter()
                .map(|event| {
                    Ok((
                        Hash::new(event.event_digest_with_digest_suite(
                            arkret_canonical::DigestSuite::Sha256,
                        )?)?,
                        event,
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        )?;
    let mut substituted_replayed = 0_u64;
    let mut substituted_successors = 0_u64;
    let error = verify_direct_traversal_cut_with_registry(
        &material.request,
        &substituted_source,
        &mut BoundedDirectTraversalJournal::default(),
        &[],
        &replay_registry(),
        arkret_signatures::verify_frozen_notary_signature,
        |_event, _suite, _dependencies| Ok(()),
        |_seal, _notary, _context, _dependencies| Ok(()),
        replay_kat_projection,
        &mut |seal, _delta| {
            substituted_replayed += 1;
            if !seal.predecessor_refs.is_empty() {
                substituted_successors += 1;
            }
            Ok(())
        },
    )
    .expect_err("current same-method key must not verify a historical successor Seal");
    if substituted_replayed != 1
        || substituted_successors != 0
        || !error.to_string().contains("signature verification failed")
    {
        bail!(
            "current-key substitution did not fail after predecessor-only replay: replayed={substituted_replayed}, successors={substituted_successors}, error={error}"
        );
    }
    Ok(())
}

/// Fixture-declared reverse-traversal descriptor.
#[derive(Clone, Debug)]
struct DirectCutSeal {
    seal_ref: String,
    predecessor_refs: Vec<String>,
}

impl DirectCutSeal {
    fn into_descriptor(self) -> Result<SealPredecessorDescriptor> {
        Ok(SealPredecessorDescriptor {
            seal_ref: SealId::new(self.seal_ref)?,
            predecessor_refs: self
                .predecessor_refs
                .into_iter()
                .map(|value| Ok(SealId::new(value)?))
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

const UNREACHABLE_SEAL_REF: &str =
    "ak:seal:sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

const TRAVERSAL_REALM_ID: &str = "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN";

fn seal_basis(leaves: &[String]) -> Result<SealBasis> {
    let mut leaves = leaves
        .iter()
        .map(|value| Ok(SealId::new(value.clone())?))
        .collect::<Result<Vec<_>>>()?;
    leaves.sort();
    let basis = SealBasis { leaves };
    basis.validate_protocol_bounds()?;
    Ok(basis)
}

/// Run one cut through the SDK verifier and return its canonical error names.
fn cut_errors(
    base: &[String],
    current: &[String],
    target: &[String],
    seals: &[DirectCutSeal],
) -> Result<BTreeSet<String>> {
    let request = DirectCutRequest {
        realm_id: RealmId::new(TRAVERSAL_REALM_ID)?,
        trusted_history_base_basis: seal_basis(base)?,
        trusted_current_basis: seal_basis(current)?,
        target_basis: seal_basis(target)?,
    };
    let source = DirectCutDescriptorIndex::new(
        seals
            .iter()
            .cloned()
            .map(DirectCutSeal::into_descriptor)
            .collect::<Result<Vec<_>>>()?,
    )?;
    let mut journal = BoundedDirectTraversalJournal::default();
    Ok(discover_direct_cut(&request, &source, &mut journal)?
        .error_names()
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// Drive the SDK direct-traversal verifier against the fixture's canonical cut
/// and its five declared negative mutations. The assertion is equality with each
/// case's complete `actual_errors` set, not mere containment, so a verifier that
/// over- or under-reports fails here.
fn verify_direct_cut_graph_mutations(cut: &Value, negative_cases: &[Value]) -> Result<()> {
    let basis = |name: &str| -> Result<Vec<String>> {
        cut.pointer(&format!("/{name}/leaves"))
            .and_then(Value::as_array)
            .with_context(|| format!("direct cut omits {name}.leaves"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("direct cut {name} leaf is not text"))
            })
            .collect()
    };
    let base = basis("trusted_history_base_basis")?;
    let current = basis("trusted_current_basis")?;
    let target = basis("target_basis")?;
    let seals = cut
        .get("seals")
        .and_then(Value::as_array)
        .context("direct cut omits seals[]")?
        .iter()
        .map(|value| {
            Ok(DirectCutSeal {
                seal_ref: value["seal_ref"]
                    .as_str()
                    .context("direct cut seal_ref is not text")?
                    .to_owned(),
                predecessor_refs: value["predecessor_refs"]
                    .as_array()
                    .context("direct cut predecessor_refs is not an array")?
                    .iter()
                    .map(|predecessor| {
                        predecessor
                            .as_str()
                            .map(str::to_owned)
                            .context("direct cut predecessor ref is not text")
                    })
                    .collect::<Result<Vec<_>>>()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if !cut_errors(&base, &current, &target, &seals)?.is_empty() {
        bail!("canonical direct cut does not satisfy its closed interval");
    }

    let hidden_ref = current
        .first()
        .context("direct cut lacks a first current leaf")?
        .clone();

    // The responder simply omits one interval descriptor while its successor
    // still points at it.
    let mut hidden_predecessor = seals.clone();
    hidden_predecessor.retain(|seal| seal.seal_ref != hidden_ref);

    // The same branch is additionally truncated, so the surviving successor is
    // predecessor-free without being a base leaf.
    let mut branch_stops_before_base = hidden_predecessor.clone();
    for seal in &mut branch_stops_before_base {
        seal.predecessor_refs.retain(|value| *value != hidden_ref);
    }

    let mut extended_base = base.clone();
    extended_base.push(UNREACHABLE_SEAL_REF.to_owned());

    let mut surplus = seals.clone();
    surplus.push(DirectCutSeal {
        seal_ref: UNREACHABLE_SEAL_REF.to_owned(),
        predecessor_refs: Vec::new(),
    });

    let disjoint_current = vec![UNREACHABLE_SEAL_REF.to_owned()];

    type TraversalMutation<'a> = (
        &'a str,
        &'a [String],
        &'a [String],
        &'a [String],
        &'a [DirectCutSeal],
    );
    let mutations: [TraversalMutation<'_>; 5] = [
        (
            "hidden_predecessor",
            &base,
            &current,
            &target,
            &hidden_predecessor,
        ),
        (
            "target_does_not_dominate_current",
            &base,
            &disjoint_current,
            &target,
            &seals,
        ),
        (
            "branch_stops_before_base",
            &base,
            &current,
            &target,
            &branch_stops_before_base,
        ),
        (
            "base_leaf_not_consumed",
            &extended_base,
            &current,
            &target,
            &seals,
        ),
        ("surplus_descriptor", &base, &current, &target, &surplus),
    ];
    for (name, base, current, target, seals) in mutations {
        let case = negative_cases
            .iter()
            .find(|case| case["name"].as_str() == Some(name))
            .with_context(|| format!("history traversal fixture omits {name}"))?;
        let expected_error = case["expected_error"]
            .as_str()
            .with_context(|| format!("history traversal case {name} omits expected_error"))?;
        let expected_errors = case["actual_errors"]
            .as_array()
            .with_context(|| format!("history traversal case {name} omits actual_errors"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("history traversal case {name} error is not text"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let observed = cut_errors(base, current, target, seals)?;
        if observed != expected_errors {
            bail!(
                "SDK direct traversal for {name} produced {observed:?}, fixture declares {expected_errors:?}"
            );
        }
        if !observed.contains(expected_error) {
            bail!("SDK direct traversal for {name} did not produce {expected_error}");
        }
    }
    Ok(())
}

/// Check the fixture's `since_join` lineage against the only two admissible
/// `join_epoch` sources: the winning Commit that consumes the exact Add, and a
/// proven Genesis initial leaf. Local clocks and current epoch stay forbidden.
fn verify_since_join_lineage(lineage: &Value) -> Result<()> {
    let incarnation: AuthorizationIncarnation =
        serde_json::from_value(lineage["add_target_authorization_incarnation"].clone())?;
    let AuthorizationIncarnation::Realm {
        realm_membership_incarnation_ref,
    } = &incarnation
    else {
        bail!("since_join lineage fixture is not a Realm incarnation");
    };
    if lineage["membership_incarnation_ref"].as_str()
        != Some(realm_membership_incarnation_ref.as_str())
    {
        bail!("since_join lineage incarnation refs disagree");
    }
    let expected = lineage["expected_join_epoch"]
        .as_u64()
        .context("since_join lineage omits expected_join_epoch")?;
    if lineage["winning_commit_next_epoch"].as_u64() != Some(expected) {
        bail!("since_join lineage expected_join_epoch is not the winning Commit next_epoch");
    }
    let winning_commit_ref = lineage["winning_commit_ref"]
        .as_str()
        .context("since_join lineage omits winning_commit_ref")?;
    let add_proposal_ref = lineage["add_proposal_ref"]
        .as_str()
        .context("since_join lineage omits add_proposal_ref")?;
    if winning_commit_ref == add_proposal_ref
        || !lineage["winning_commit_proposal_refs"]
            .as_array()
            .context("since_join lineage omits winning_commit_proposal_refs")?
            .iter()
            .any(|value| value.as_str() == Some(add_proposal_ref))
    {
        bail!("since_join lineage winning Commit does not consume the exact Add proposal");
    }
    for forbidden in lineage["forbidden_derivations"]
        .as_array()
        .context("since_join lineage omits forbidden_derivations")?
    {
        let forbidden = forbidden
            .as_str()
            .context("since_join forbidden derivation is not text")?;
        if !matches!(
            forbidden,
            "joined_at" | "received_at" | "latest_epoch" | "current_session_device"
        ) {
            bail!("since_join lineage declares an unknown forbidden derivation {forbidden}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_traversal_suite_uses_the_shared_wire_types() {
        run_history_key_direct_traversal_suite().unwrap();
    }
}
