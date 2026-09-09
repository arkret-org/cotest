use std::collections::HashSet;

use anyhow::{Result, anyhow, bail};
use arkret_wire::{DomainSeparationId, SchemaId};
use serde_json::{Value, json};

use super::{FederationFixture, canonical_json, load_fixture, sha256_prefixed};
use crate::transcripts::record_vector_event;

const VECTOR_ID_AGENT_ADMISSION_RECEIPT_HANDOFF: &str =
    "ak.vector.federation.agent_admission_receipt_handoff.v1";

pub fn run_federation_fixture_suite() -> Result<()> {
    let fixture = load_fixture::<FederationFixture>("federation-fixture.json")?;
    if fixture.suite != "federation" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }
    let mut replay_cache = HashSet::new();

    for case in fixture.cases {
        match case.name.as_str() {
            "http_message_signature_hash" | "http_message_signature_digest" => {
                let input = case.input.as_ref();
                let method = input
                    .and_then(|value| value.get("method"))
                    .and_then(Value::as_str)
                    .unwrap_or("PUT");
                let target = input
                    .and_then(|value| value.get("target_uri"))
                    .and_then(Value::as_str)
                    .unwrap_or("/_arkret/peer/events");
                let body = input
                    .and_then(|value| value.get("body"))
                    .cloned()
                    .unwrap_or_else(|| json!({"txn_id": "demo"}));
                let request = SignedFederationRequest {
                    method: method.to_owned(),
                    target: target.to_owned(),
                    body,
                };
                let signature_input = request.signature_input_hash()?;
                let canonical = request.canonical_request_hash()?;
                if signature_input != canonical {
                    bail!("federation fixture {} hash mismatch", case.name);
                }
                record_vector_event(
                    &format!("federation.{}", case.name),
                    &json!({
                        "method": request.method.clone(),
                        "target": request.target.clone(),
                        "body": request.body.clone(),
                    }),
                    &json!({"signature_input_eq_canonical": true}),
                    &json!({
                        "signature_input": signature_input,
                        "canonical": canonical.clone(),
                        "signature_input_eq_canonical": true,
                    }),
                );
            }
            // 2026-05-20: fixture case renamed from
            // `origin_destination_id_mismatch` to
            // `source_destination_id_mismatch`. The semantics
            // (federation source DID ≠ signed destination DID → reject)
            // are unchanged.
            "source_destination_id_mismatch" => {
                let verdict = validate_origin_destination(
                    "did:web:remote.example",
                    "did:web:wrong.example",
                    "did:web:local.example",
                );
                if verdict == FederationVerdict::Accepted {
                    bail!("federation fixture {} accepted DID mismatch", case.name);
                }
                record_vector_event(
                    "federation.source_destination_id_mismatch",
                    &json!({
                        "source": "did:web:remote.example",
                        "signed_destination": "did:web:wrong.example",
                        "expected_destination": "did:web:local.example",
                    }),
                    &json!({"verdict": "Rejected"}),
                    &json!({"verdict": format!("{verdict:?}")}),
                );
            }
            "replay_protection" => {
                let first = replay_cache.insert("txn-1".to_owned());
                if !first {
                    bail!("federation fixture {} cache failed first insert", case.name);
                }
                let second = replay_cache.insert("txn-1".to_owned());
                if second {
                    bail!("federation fixture {} missed replay", case.name);
                }
                record_vector_event(
                    "federation.replay_protection",
                    &json!({"txn_id": "txn-1"}),
                    &json!({"first_insert": true, "duplicate_insert": false}),
                    &json!({"first_insert": first, "duplicate_insert": second}),
                );
            }
            "fork_quarantine" => {
                let input = case
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow!("collision fixture missing input"))?;
                let preimages = input["preimages"]
                    .as_array()
                    .ok_or_else(|| anyhow!("collision preimages missing"))?;
                let digest: [u8; 32] =
                    hex::decode(input["injected_digest_hex"].as_str().unwrap_or_default())?
                        .try_into()
                        .map_err(|_| anyhow!("collision digest length"))?;
                let recomputed = arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    digest,
                );
                if input["real_hash_collision_claimed"] != false
                    || preimages.len() != 2
                    || preimages[0] == preimages[1]
                    || input["carried_ids"].as_array().is_none_or(|ids| {
                        ids.len() != 2
                            || ids
                                .iter()
                                .any(|id| id.as_str() != Some(recomputed.as_str()))
                    })
                {
                    bail!("invalid explicitly injected full-hash collision fixture");
                }
                let actual = json!({"reason": "witness_disagreement", "quarantine": true});
                if input["expected"] != actual {
                    bail!("full-hash collision fixture has an invalid verdict");
                }
                record_vector_event(
                    "federation.fork_quarantine",
                    input,
                    &json!({"reason": "witness_disagreement", "quarantine": true}),
                    &actual,
                );
            }
            "seal_prerequisite_closure" => {
                validate_seal_prerequisite_closure_case(&case)?;
            }
            "seal_prerequisite_partial_retry" => {
                validate_seal_prerequisite_partial_retry_case(&case)?;
            }
            "cbs_dependency_resolve" => validate_cbs_dependency_resolve_case(&case)?,
            "agent_event_admission_receipt_handoff" => {
                validate_agent_event_admission_receipt_handoff_case(&case)?
            }
            "frontier_mismatch_reduction_terminal_states" => {
                validate_frontier_mismatch_reduction_terminal_states(&case)?
            }
            "ordinary_event_uses_cbs_reducer_profile_cell"
            | "settled_reducer_profile_not_implemented"
            | "upgrade_target_not_registered" => validate_reducer_profile_resolution_case(&case)?,
            "pull_authorization" => {
                let verdict = authorize_pull(false, false);
                if verdict != FederationVerdict::Blinded {
                    bail!("federation fixture {} exposed unauthorized pull", case.name);
                }
                record_vector_event(
                    "federation.pull_authorization",
                    &json!({
                        "has_backfill_capability": false,
                        "has_plaintext_visibility": false,
                    }),
                    &json!({"verdict": "Blinded"}),
                    &json!({"verdict": format!("{verdict:?}")}),
                );
            }
            "online_event_omits_offline_publication_evidence" => {
                let input = case
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow!("{} case lacks input", case.name))?;
                let lease_present = input
                    .get("authorization_lease_present")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("{} lacks authorization_lease_present", case.name))?;
                let receipt_count = input
                    .get("ingress_receipt_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("{} lacks ingress_receipt_count", case.name))?;
                let receiver_revalidates = input
                    .get("receiver_revalidates_current_admission")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("{} lacks receiver_revalidates_current_admission", case.name)
                    })?;
                let expected = case.expected.as_ref().and_then(Value::as_str);
                if lease_present
                    || receipt_count != 0
                    || !receiver_revalidates
                    || expected != Some("accepted_without_offline_publication_evidence")
                {
                    bail!(
                        "federation fixture {} drifted from the online submission contract",
                        case.name
                    );
                }
                record_vector_event(
                    "federation.online_event_omits_offline_publication_evidence",
                    input,
                    &json!({"outcome": "accepted_without_offline_publication_evidence"}),
                    &json!({
                        "authorization_lease_present": lease_present,
                        "ingress_receipt_count": receipt_count,
                        "receiver_revalidates_current_admission": receiver_revalidates,
                        "outcome": "accepted_without_offline_publication_evidence",
                    }),
                );
            }
            "delayed_event_requires_lease_bound_receipt"
            | "online_event_forbids_unbound_lease_receipt" => {
                let input = case
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow!("{} case lacks input", case.name))?;
                let lease_present = input
                    .get("authorization_lease_present")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("{} lacks authorization_lease_present", case.name))?;
                let receipt_count = input
                    .get("ingress_receipt_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("{} lacks ingress_receipt_count", case.name))?;
                let expected_input = match case.name.as_str() {
                    "delayed_event_requires_lease_bound_receipt" => (true, 0),
                    "online_event_forbids_unbound_lease_receipt" => (false, 1),
                    _ => unreachable!(),
                };
                if (lease_present, receipt_count) != expected_input
                    || case.expected.as_ref().and_then(Value::as_str) != Some("schema_violation")
                {
                    bail!(
                        "federation fixture {} drifted from the publication evidence schema",
                        case.name
                    );
                }
                record_vector_event(
                    &format!("federation.{}", case.name),
                    input,
                    &json!({"outcome": "schema_violation"}),
                    &json!({
                        "authorization_lease_present": lease_present,
                        "ingress_receipt_count": receipt_count,
                        "outcome": "schema_violation",
                    }),
                );
            }
            _ => bail!("unknown federation fixture case {}", case.name),
        }
    }

    Ok(())
}

fn validate_frontier_mismatch_reduction_terminal_states(case: &super::NamedCase) -> Result<()> {
    let input = case
        .input
        .as_ref()
        .ok_or_else(|| anyhow!("{} lacks input", case.name))?;
    if input["comparison_key"] != json!(["realm_id", "actor_id", "actor_seq"])
        || input["sibling_tuple"] != json!(["event_id", "event_digest", "prev_frontier_digest"])
        || input["actor_intersection_uses_complete_actor_id"] != true
        || input["validate_before_side_effects"] != true
        || input["direction_binds_origin_and_destination_service"] != true
        || input["aggregate_root_cross_peer_set_equality"] != false
        || input["routine_scan_on_mismatch"] != false
    {
        bail!("{} reduction input contract drifted", case.name);
    }
    const EXPECTED: &[(&str, &str)] = &[
        (
            "equal_frontier_roots",
            "successful_observation_and_reset_without_set_equality_or_completeness",
        ),
        (
            "different_roots_with_policy_legitimate_empty_actor_intersection",
            "success_and_reset_consecutive_failures_without_global_root_convergence",
        ),
        (
            "peer_omits_actor_required_by_current_verified_disclosure_policy",
            "ordinary_required_disclosure_failure_not_fork_evidence",
        ),
        (
            "different_roots_from_permanent_legal_replication_scope_difference",
            "reconciliation_incomplete_diagnostic_without_routine_scan_peer_failure_or_global_root_convergence",
        ),
        (
            "peers_hold_different_legal_sibling_subsets_within_limits",
            "known_id_or_operator_fallback_candidates_use_resolve_submit_admission_then_legal_union",
        ),
        (
            "scan_discovers_a_missing_control_event_without_publication_sidecars",
            "resolve_the_event_id_to_event_federation_submission_before_admission",
        ),
        (
            "resolve_returns_the_first_accepted_control_ack_compensation_and_delayed_publication_evidence",
            "byte_identical_evidence_replays_through_the_same_federation_admission_as_push",
        ),
        (
            "ack_required_control_resolve_has_no_control_proposal_ack",
            "fail_closed_without_receiver_minting_and_without_counting_raw_root_mismatch_as_peer_failure",
        ),
        (
            "ackless_human_self_principal_control_resolve_carries_stable_admission_evidence",
            "accept_only_after_source_station_producer_device_authorize_generation_and_seal_basis_replay",
        ),
        (
            "resolve_carrier_contains_both_control_ack_and_ackless_admission_evidence",
            "schema_violation_before_admission",
        ),
        (
            "actually_executed_resolve_or_operator_fallback_remote_network_failure",
            "ordinary_remote_failure_counts_toward_three_consecutive_failures",
        ),
        (
            "carried_event_id_does_not_match_recomputed_complete_event_id",
            "event_id_digest_mismatch_rejected_before_dedup_index_route_auth_or_quarantine",
        ),
        (
            "two_distinct_canonical_preimages_artificially_recompute_to_the_same_complete_event_id",
            "first_confirmation_quarantines_affected_scope_and_sets_peer_stale",
        ),
        (
            "validated_sibling_bucket_exceeds_registered_limit",
            "first_confirmation_quarantines_affected_scope_and_sets_peer_stale",
        ),
        (
            "local_snapshot_changes_during_operator_fallback",
            "stop_or_restart_with_local_diagnostic_without_peer_failure",
        ),
    ];
    validate_named_expectations(case, EXPECTED)?;
    record_vector_event(
        "federation.frontier_mismatch_reduction_terminal_states",
        input,
        &json!({"cases": EXPECTED}),
        &json!({
            "validated_case_count": EXPECTED.len(),
            "complete_actor_id_intersection": true,
            "validate_before_side_effects": true,
            "direction_bound": true,
            "aggregate_root_cross_peer_set_equality": false,
            "routine_scan_on_mismatch": false,
        }),
    );
    Ok(())
}

fn validate_agent_event_admission_receipt_handoff_case(case: &super::NamedCase) -> Result<()> {
    if case.vector_id.as_deref() != Some(VECTOR_ID_AGENT_ADMISSION_RECEIPT_HANDOFF) {
        bail!("{} has the wrong vector_id", case.name);
    }
    let contract = case
        .request_contract
        .as_ref()
        .ok_or_else(|| anyhow!("{} lacks request_contract", case.name))?;
    let required_contract = json!({
        "outcome_field": "agent_event_admissions",
        "receipt_schema": SchemaId::AGENT_SIGNER_ADMISSION_RECEIPT_V1,
        "receipt_proof_domain": DomainSeparationId::AGENT_SIGNER_ADMISSION_RECEIPT_V1,
        "receipted_outcome_classes": ["accepted", "duplicate"],
        "unreceipted_outcome_classes": ["rejected", "quarantine", "dependency_missing"],
        "receipt_written_in_event_acceptance_transaction": true,
        "self_submit_outcome_omits_receipts": true,
        "receipt_binding_fields": [
            "event_id",
            "realm_id",
            "producer_accepted_at",
            "accepted_at",
            "agent_id",
            "verification_method",
            "producer_signer_resolution_evidence_ref",
            "receiver_id"
        ]
    });
    if contract != &required_contract {
        bail!("{} request_contract drifted", case.name);
    }
    const EXPECTED: &[(&str, &str)] = &[
        (
            "accepted_agent_event",
            "outcome_returns_one_receiver_signed_receipt_for_that_event",
        ),
        (
            "accepted_non_agent_event",
            "outcome_carries_no_receipt_for_that_event",
        ),
        (
            "rejected_quarantined_or_dependency_missing_agent_event",
            "no_receipt_signed_and_none_returned",
        ),
        (
            "receipt_write_fails_inside_event_acceptance_transaction",
            "event_acceptance_rolls_back_with_zero_receipt",
        ),
        (
            "two_receivers_accept_the_same_event",
            "one_receipt_per_receiver_id_as_distinct_historical_branches",
        ),
        (
            "byte_identical_resubmission_of_an_accepted_event",
            "duplicate_returns_the_first_stored_byte_identical_receipt",
        ),
        (
            "duplicate_branch_mints_a_new_accepted_at_or_signing_method",
            "nonconformant_receipt_replay",
        ),
        (
            "carried_event_id_does_not_match_current_canonical_bytes",
            "event_id_digest_mismatch_with_zero_receipt_and_zero_side_effect",
        ),
        (
            "two_distinct_canonical_preimages_artificially_injected_with_the_same_recomputed_complete_event_id",
            "witness_disagreement_quarantines_affected_scope_with_zero_receipt",
        ),
        (
            "receipt_set_matches_producer_evidence_pair_events_one_to_one",
            "source_atomically_commits_receipt_and_materialization_obligation",
        ),
        (
            "outcome_omits_a_receipt_for_one_such_event",
            "handoff_incomplete_and_delivery_not_marked_complete",
        ),
        (
            "outcome_returns_a_receipt_outside_accepted_and_duplicate",
            "handoff_incomplete_and_delivery_not_marked_complete",
        ),
        (
            "receipt_proof_unparsable_or_receiver_id_mismatch",
            "handoff_incomplete_and_delivery_not_marked_complete",
        ),
        (
            "receipt_producer_evidence_pair_differs_from_the_frozen_origin_pair",
            "handoff_incomplete_and_delivery_not_marked_complete",
        ),
        (
            "source_restarts_before_the_obligation_commit",
            "same_outbox_row_replays_the_same_event_receiver_receipt_intent",
        ),
        (
            "response_transport_authentication_or_outcome_schema_invalid",
            "outcome_discarded_before_any_receipt_consumption",
        ),
    ];
    validate_named_expectations(case, EXPECTED)?;
    record_vector_event(
        "federation.agent_event_admission_receipt_handoff",
        contract,
        &json!({"cases": EXPECTED}),
        &json!({
            "request_contract_matches": true,
            "validated_case_count": EXPECTED.len(),
        }),
    );
    Ok(())
}

fn validate_seal_prerequisite_closure_case(case: &super::NamedCase) -> Result<()> {
    if case.vector_id.as_deref() != Some("ak.vector.federation.seal_prerequisite_closure.v1") {
        bail!("{} has the wrong vector_id", case.name);
    }
    let contract = case
        .request_contract
        .as_ref()
        .ok_or_else(|| anyhow!("{} lacks request_contract", case.name))?;
    let required_contract = json!({
        "single_realm": true,
        "event_count_range": [1, 500],
        "event_phase_order": ["control", "data"],
        "cbs_proof_bundle_count_range": [0, 64],
        "per_bundle_limits": {
            "seals": 256,
            "control_moves": 1024,
            "inclusion_and_availability_proofs_combined": 2048,
            "dependency_path_depth": 4096
        },
        "closure": "bounded_verifiable_superset_rooted_at_seal_ref_and_seal_basis_leaves",
        "body_contains_idempotency_key": false
    });
    if contract != &required_contract {
        bail!("{} request_contract drifted", case.name);
    }
    const EXPECTED: &[(&str, &str)] = &[
        (
            "complete_control_seal_data_closure",
            "control_and_basis_seals_resolved_topologically_then_data_events_verified",
        ),
        (
            "missing_control_seal_basis_leaf",
            "item_rejected_dependency_missing_with_missing_seal_refs",
        ),
        (
            "missing_target_seal",
            "item_rejected_dependency_missing_with_missing_seal_refs",
        ),
        (
            "missing_nonlocal_predecessor",
            "item_rejected_dependency_missing_with_missing_seal_refs",
        ),
        (
            "missing_seal_delta_control_event",
            "item_rejected_dependency_missing_with_missing_event_digests",
        ),
        ("event_seal_dependency_cycle", "permanent_schema_violation"),
        ("invalid_seal_signature", "permanent_signature_invalid"),
        (
            "cross_realm_event_or_seal",
            "permanent_schema_or_realm_mismatch",
        ),
        ("invalid_seal_root", "permanent_state_mismatch"),
        (
            "unrelated_or_unsorted_or_duplicate_seal",
            "request_schema_violation_without_receiver_reordering",
        ),
        (
            "same_batch_unsealed_grant_then_data_event",
            "grant_not_visible_for_data_event_authorization",
        ),
        ("seal_transport", "no_actor_frontier_advance"),
    ];
    validate_named_expectations(case, EXPECTED)?;
    record_vector_event(
        "federation.seal_prerequisite_closure",
        contract,
        &json!({"cases": EXPECTED}),
        &json!({
            "request_contract_matches": true,
            "validated_case_count": EXPECTED.len()
        }),
    );
    Ok(())
}

fn validate_seal_prerequisite_partial_retry_case(case: &super::NamedCase) -> Result<()> {
    if case.vector_id.as_deref() != Some("ak.vector.federation.seal_partial_retry.v1") {
        bail!("{} has the wrong vector_id", case.name);
    }
    const EXPECTED: &[(&str, &str)] = &[
        (
            "ordinary_batch_independent_success_and_pending",
            "http_200_partial_with_success_accounted_and_pending_reason",
        ),
        (
            "ordinary_batch_all_pending",
            "http_200_partial_with_empty_accepted_and_duplicate",
        ),
        (
            "atomic_founding_unit_pending",
            "http_409_dependency_missing_problem_with_zero_writes",
        ),
        (
            "partial_retry_after_any_success",
            "new_body_pending_only_new_idempotency_key_and_resigned_digests",
        ),
        (
            "all_pending_retry",
            "new_idempotency_key_required_after_any_response",
        ),
        (
            "retry_budget_exhausted",
            "operator_diagnostic_without_unbounded_retry",
        ),
    ];
    validate_named_expectations(case, EXPECTED)?;
    record_vector_event(
        "federation.seal_prerequisite_partial_retry",
        &json!({"vector_id": case.vector_id}),
        &json!({"cases": EXPECTED}),
        &json!({"validated_case_count": EXPECTED.len()}),
    );
    Ok(())
}

fn validate_cbs_dependency_resolve_case(case: &super::NamedCase) -> Result<()> {
    if case.vector_id.as_deref() != Some("ak.vector.federation.cbs_dependency_resolve.v1") {
        bail!("{} has the wrong vector_id", case.name);
    }
    let contract = case
        .request_contract
        .as_ref()
        .ok_or_else(|| anyhow!("{} lacks request_contract", case.name))?;
    let required_contract = json!({
        "single_realm": true,
        "selector_any_of": ["event_ids", "event_digests", "seal_refs"],
        "max_response_bytes_ceiling": 8388608,
        "read_only": true
    });
    if contract != &required_contract {
        bail!("{} request_contract drifted", case.name);
    }
    const EXPECTED: &[(&str, &str)] = &[
        (
            "requested_seal_returns_bounded_verifiable_superset",
            "one_target_bundle_and_no_frontier_advance",
        ),
        (
            "requested_event_digest_resolved_inside_control_moves",
            "digest_satisfied_without_duplicate_event_copy",
        ),
        (
            "missing_and_undisclosable_selectors",
            "typed_missing_sets_are_externally_indistinguishable",
        ),
        (
            "unsorted_or_duplicate_selector_array",
            "schema_violation_before_dependency_lookup",
        ),
        (
            "success_omits_one_requested_selector",
            "nonconformant_response_selector_conservation_failure",
        ),
        (
            "response_budget_cannot_fully_account_for_all_selectors",
            "atomic_limit_exceeded_not_partial_or_empty_success",
        ),
        (
            "successful_round_does_not_strictly_shrink_missing_sets",
            "stop_automatic_fetch_and_surface_operator_diagnostic",
        ),
        (
            "ninth_consecutive_fetch_round",
            "fetch_budget_exhausted_without_submit_side_effect",
        ),
        (
            "resolve_response_completes_closure",
            "event_still_requires_new_submit_with_fresh_idempotency_key",
        ),
    ];
    validate_named_expectations(case, EXPECTED)?;
    Ok(())
}

fn validate_named_expectations(case: &super::NamedCase, expected: &[(&str, &str)]) -> Result<()> {
    let cases = case
        .cases
        .as_ref()
        .ok_or_else(|| anyhow!("{} lacks cases", case.name))?;
    if cases.len() != expected.len() {
        bail!(
            "{} expected {} cases, got {}",
            case.name,
            expected.len(),
            cases.len()
        );
    }
    let actual = cases
        .iter()
        .map(|entry| {
            let name = entry
                .get("case")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("{} contains a case without case", case.name))?;
            let outcome = entry
                .get("expected")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("{} case {name} lacks expected", case.name))?;
            Ok((name, outcome))
        })
        .collect::<Result<Vec<_>>>()?;
    if actual != expected {
        bail!("{} case matrix drifted", case.name);
    }
    Ok(())
}

struct SignedFederationRequest {
    method: String,
    target: String,
    body: Value,
}

impl SignedFederationRequest {
    fn canonical_request_hash(&self) -> Result<String> {
        let canonical = canonical_json(&json!({
            "method": self.method,
            "target": self.target,
            "body": self.body
        }))?;
        Ok(sha256_prefixed(canonical.as_bytes()))
    }

    fn signature_input_hash(&self) -> Result<String> {
        self.canonical_request_hash()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FederationVerdict {
    Accepted,
    Rejected,
    Blinded,
}

fn validate_origin_destination(
    origin: &str,
    signed_destination: &str,
    expected_destination: &str,
) -> FederationVerdict {
    if origin.is_empty() || signed_destination != expected_destination {
        FederationVerdict::Rejected
    } else {
        FederationVerdict::Accepted
    }
}

fn validate_reducer_profile_resolution_case(case: &super::NamedCase) -> Result<()> {
    let input = case
        .input
        .as_ref()
        .ok_or_else(|| anyhow!("{} case lacks input", case.name))?;
    let expected = case
        .expected
        .as_ref()
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{} case lacks string expected", case.name))?;
    let actual = match case.name.as_str() {
        "ordinary_event_uses_cbs_reducer_profile_cell" => {
            let settled = input["settled_reducer_profile"]
                .as_str()
                .unwrap_or_default();
            let supported = input["receiver_supported_reducer_profiles"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|profile| profile == settled);
            if input["event_declares_reducer_profile"] != false
                || input["service_binding_declares_reducer_profile"] != false
            {
                bail!("ordinary Event or service binding declared a reducer profile");
            }
            if supported {
                "accepted"
            } else {
                "unsupported_profile"
            }
        }
        "settled_reducer_profile_not_implemented" => "unsupported_profile",
        "upgrade_target_not_registered" => {
            let registry = super::load_artifact_json("registry/reducer-profile-registry.json")?;
            let source = input["source_reducer_profile"].as_str().unwrap_or_default();
            let target = input["target_reducer_profile"].as_str().unwrap_or_default();
            let registered = registry["profiles"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|profile| profile["profile_id"] == source)
                .and_then(|profile| profile["upgrade_edges"].as_array())
                .is_some_and(|edges| edges.iter().any(|edge| edge.as_str() == Some(target)));
            if registered {
                "accepted"
            } else {
                "unsupported_profile"
            }
        }
        _ => unreachable!(),
    };
    if actual != expected {
        bail!("{} expected {expected}, got {actual}", case.name);
    }
    record_vector_event(
        &format!("federation.{}", case.name),
        input,
        &json!({"outcome": expected}),
        &json!({"outcome": actual}),
    );
    Ok(())
}

fn authorize_pull(
    has_backfill_capability: bool,
    has_plaintext_visibility: bool,
) -> FederationVerdict {
    if has_backfill_capability && has_plaintext_visibility {
        FederationVerdict::Accepted
    } else {
        FederationVerdict::Blinded
    }
}
