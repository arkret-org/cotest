use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{PrivacySecurityFixture, load_fixture_value, parse_fixture_value};
use crate::transcripts::record_vector_event;

pub fn run_privacy_security_fixture_suite() -> Result<()> {
    let value = load_fixture_value("privacy-security-fixture.json")?;
    let fixture: PrivacySecurityFixture =
        parse_fixture_value("privacy-security-fixture.json", value)?;
    if fixture.suite != "privacy_security" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }

    for case in fixture.cases {
        match case.name.as_str() {
            "private_blob_head_range_anti_enumeration" => {
                let hidden = anti_enumeration_blob_error(true);
                let missing = anti_enumeration_blob_error(false);
                if hidden != missing {
                    bail!(
                        "privacy fixture {} leaked distinguishable blob error",
                        case.name
                    );
                }
                record_vector_event(
                    "privacy.private_blob_head_range_anti_enumeration",
                    &json!({"hidden_request": true, "missing_request": false}),
                    &json!({"hidden_error": "not_found", "missing_error": "not_found"}),
                    &json!({"hidden_error": hidden, "missing_error": missing}),
                );
            }
            "push_blind_wakeup_payload" => {
                let payload = blind_wakeup_payload();
                if payload.get("body").is_some() || payload.get("members").is_some() {
                    bail!(
                        "privacy fixture {} leaked plaintext wakeup fields",
                        case.name
                    );
                }
                record_vector_event(
                    "privacy.push_blind_wakeup_payload",
                    &json!({}),
                    &json!({"body_present": false, "members_present": false}),
                    &json!({
                        "payload": payload.clone(),
                        "body_present": payload.get("body").is_some(),
                        "members_present": payload.get("members").is_some(),
                    }),
                );
            }
            // Round 2+3 (2026-05-20): fixture case renamed from
            // `hidden_space_resolve_indistinguishable` to
            // `hidden_realm_resolve_indistinguishable`; the directory
            // operation id is now canonical realm terminology.
            "hidden_realm_resolve_indistinguishable" => {
                let op_id = case.operation_id.as_deref();
                let same_http_ok = case
                    .expected
                    .as_ref()
                    .and_then(|expected| expected.get("same_http_status"))
                    .and_then(Value::as_u64)
                    == Some(404);
                let op_ok = matches!(op_id, Some("ak.find.directory.read.resolve_realm"));
                if !op_ok || !same_http_ok {
                    bail!(
                        "privacy fixture {} no longer proves indistinguishable resolve errors",
                        case.name
                    );
                }
                record_vector_event(
                    "privacy.hidden_realm_resolve_indistinguishable",
                    &json!({"operation_id": case.operation_id.clone()}),
                    &json!({
                        "operation_id": "ak.find.directory.read.resolve_realm",
                        "same_http_status": 404,
                    }),
                    &json!({
                        "operation_id": case.operation_id.clone(),
                        "same_http_status": case
                            .expected
                            .as_ref()
                            .and_then(|expected| expected.get("same_http_status"))
                            .cloned(),
                    }),
                );
            }
            // Round 4 (2026-06-24): directory resolve operations gained
            // failure-blinding vectors. Missing / hidden / unauthorized
            // resolutions MUST be indistinguishable — same 404 / not_found /
            // body shape / timing class — and MUST NOT leak the listed
            // binding fields.
            "resolve_handle_failure_blinding" => {
                validate_resolve_failure_blinding(&case, "ak.find.directory.read.resolve_handle")?;
            }
            "resolve_agent_selector_failure_blinding" => {
                validate_resolve_failure_blinding(
                    &case,
                    "ak.find.directory.read.resolve_agent_selector",
                )?;
            }
            "private_contact_discovery_padding_and_cardinality" => {
                let input = case
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing input", case.name))?;
                let blinded_count = input
                    .pointer("/blind_request/blinded_elements")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("privacy fixture {} missing blinded elements", case.name)
                    })?
                    .len();
                let derived_prefix_count = input
                    .pointer("/match_request/derived_prefixes")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("privacy fixture {} missing derived prefixes", case.name)
                    })?
                    .len();
                let provider_enforced_batch_item_count = input
                    .pointer("/private_contact_discovery_config/batch_item_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        anyhow!(
                            "privacy fixture {} missing provider-enforced batch size",
                            case.name
                        )
                    })?;
                let real_identifier_count = input
                    .get("local_real_identifier_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        anyhow!(
                            "privacy fixture {} missing real identifier count",
                            case.name
                        )
                    })?;
                if blinded_count == 0
                    || derived_prefix_count != blinded_count
                    || provider_enforced_batch_item_count != blinded_count as u64
                    || provider_enforced_batch_item_count <= real_identifier_count
                {
                    bail!(
                        "privacy fixture {} does not preserve and pad PSI cardinality",
                        case.name
                    );
                }
                let expected = case.expected.as_ref().ok_or_else(|| {
                    anyhow!("privacy fixture {} missing expected claims", case.name)
                })?;
                for claim in [
                    "wire_batch_cardinality_does_not_equal_real_identifier_count",
                    "evaluated_elements_same_length_and_order_as_blinded_elements",
                    "derived_prefixes_and_hit_bitmap_same_length_and_order",
                    "single_batched_dleq_proof_verified_with_described_public_key",
                    "result_count_does_not_reveal_match_count",
                    "no_raw_connection_identifier",
                    "handoff_stubs_if_present_same_cardinality_dummy_padded",
                    "per_target_policy_denied_and_no_match_byte_indistinguishable_in_hit_bitmap",
                ] {
                    if expected.get(claim).and_then(Value::as_bool) != Some(true) {
                        bail!(
                            "privacy fixture {} missing required claim {claim}",
                            case.name
                        );
                    }
                }
                record_vector_event(
                    "privacy.private_contact_discovery_padding_and_cardinality",
                    &json!({
                        "blinded_elements": blinded_count,
                        "derived_prefixes": derived_prefix_count,
                        "provider_enforced_batch_item_count": provider_enforced_batch_item_count,
                        "real_identifiers": real_identifier_count,
                    }),
                    &json!({
                        "derived_prefixes_match_blinded_elements": true,
                        "wire_cardinality_matches_advertised_batch_item_count": true,
                        "wire_cardinality_hides_real_identifier_count": true,
                    }),
                    &json!({
                        "derived_prefixes_match_blinded_elements": derived_prefix_count == blinded_count,
                        "wire_cardinality_matches_advertised_batch_item_count":
                            provider_enforced_batch_item_count == blinded_count as u64,
                        "wire_cardinality_hides_real_identifier_count":
                            provider_enforced_batch_item_count > real_identifier_count,
                    }),
                );
            }
            "private_contact_discovery_quota_blind_phase_denial" => {
                let input = case
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing input", case.name))?;
                let expected = case.expected.as_ref().ok_or_else(|| {
                    anyhow!("privacy fixture {} missing expected claims", case.name)
                })?;
                let maximum = input
                    .pointer("/quota_state/max_psi_queries_per_window")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        anyhow!("privacy fixture {} missing quota maximum", case.name)
                    })?;
                let already_charged = input
                    .pointer("/quota_state/queries_already_charged_in_window")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing quota usage", case.name))?;
                let seconds_until_roll = input
                    .pointer("/quota_state/seconds_until_window_roll")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        anyhow!("privacy fixture {} missing quota rollover", case.name)
                    })?;
                let retry_after = expected
                    .get("retry_after_seconds")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing retry-after", case.name))?;
                let retry_quantum = expected
                    .get("retry_after_quantum_seconds")
                    .and_then(Value::as_u64)
                    .filter(|quantum| *quantum > 0)
                    .ok_or_else(|| {
                        anyhow!("privacy fixture {} has invalid retry quantum", case.name)
                    })?;
                let rounded_retry_after =
                    seconds_until_roll.div_ceil(retry_quantum) * retry_quantum;
                let body_shape = expected
                    .get("body_shape")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing body shape", case.name))?;
                let required_body_fields = ["ok", "error.code", "error.message", "request_id"];
                let body_shape_matches = required_body_fields.iter().all(|required| {
                    body_shape
                        .iter()
                        .any(|field| field.as_str() == Some(required))
                });
                let blinded_elements_present = input
                    .pointer("/blind_request/blinded_elements")
                    .and_then(Value::as_array)
                    .is_some_and(|elements| !elements.is_empty());
                let required_true_claims = [
                    "content_encoding_header_absent",
                    "same_advertised_delay_distribution_as_success_path",
                    "not_disguised_as_no_match_outcome",
                    "admitted_batch_match_request_not_quota_denied",
                    "no_per_target_information_in_denial",
                    "exact_blind_retry_not_recharged_and_returns_cached_outcome",
                    "exact_match_retry_returns_cached_outcome",
                    "pinned_epoch_retained_for_full_completion_ttl",
                ];
                let claims_hold = required_true_claims
                    .iter()
                    .all(|claim| expected.get(claim).and_then(Value::as_bool) == Some(true));
                let valid = case.operation_id.as_deref()
                    == Some("ak.find.directory.read.private_contact_discovery")
                    && input
                        .pointer("/blind_request/phase")
                        .and_then(Value::as_str)
                        == Some("blind")
                    && input.get("match_request").is_none()
                    && blinded_elements_present
                    && already_charged >= maximum
                    && expected.get("denial_phase").and_then(Value::as_str) == Some("blind")
                    && expected.get("http_status").and_then(Value::as_u64) == Some(429)
                    && expected.get("error_code").and_then(Value::as_str)
                        == Some("psi_quota_exhausted")
                    && retry_after == rounded_retry_after
                    && expected.get("content_length_bytes").and_then(Value::as_u64)
                        == input
                            .pointer(
                                "/private_contact_discovery_config/blind_response_bucket_bytes",
                            )
                            .and_then(Value::as_u64)
                    && expected.get("cache_control").and_then(Value::as_str)
                        == Some("no-store, no-transform")
                    && expected
                        .get("different_digest_same_batch_id_error_code")
                        .and_then(Value::as_str)
                        == Some("duplicate_conflict")
                    && expected
                        .get("unknown_wrong_device_or_expired_batch_error_code")
                        .and_then(Value::as_str)
                        == Some("psi_batch_unavailable")
                    && body_shape_matches
                    && claims_hold;
                if !valid {
                    bail!(
                        "privacy fixture {} no longer proves blind-phase quota denial",
                        case.name
                    );
                }
                record_vector_event(
                    "privacy.private_contact_discovery_quota_blind_phase_denial",
                    input,
                    expected,
                    &json!({
                        "denial_phase": "blind",
                        "http_status": 429,
                        "error_code": "psi_quota_exhausted",
                        "retry_after_seconds": rounded_retry_after,
                        "body_shape_matches": body_shape_matches,
                        "privacy_claims_hold": claims_hold,
                    }),
                );
            }
            "directory_query_and_ingest_vector_closure" => {
                let operation_ids = case.operation_ids.as_ref().ok_or_else(|| {
                    anyhow!("privacy fixture {} missing operation_ids", case.name)
                })?;
                for required in [
                    "ak.find.directory.read.search_realms",
                    "ak.find.directory.read.resolve_realm",
                    "ak.find.directory.read.resolve_target",
                    "ak.find.directory.command.announce",
                    "ak.find.directory.command.withdraw",
                    "ak.find.directory.read.private_contact_discovery",
                ] {
                    if !operation_ids.iter().any(|operation| operation == required) {
                        bail!(
                            "privacy fixture {} missing operation id {required}",
                            case.name
                        );
                    }
                }
                let covers_vectors = case.covers_vectors.as_ref().ok_or_else(|| {
                    anyhow!("privacy fixture {} missing covers_vectors", case.name)
                })?;
                if covers_vectors.len() < 20 {
                    bail!(
                        "privacy fixture {} no longer closes the directory/PSI vector set",
                        case.name
                    );
                }
                let expected = case
                    .expected
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing expected", case.name))?;
                let common_fields = expected
                    .get("query_results_require_common_fields")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("privacy fixture {} missing common fields", case.name)
                    })?;
                for required in ["as_of", "source_refs", "policy_revision"] {
                    if !common_fields
                        .iter()
                        .any(|field| field.as_str() == Some(required))
                    {
                        bail!(
                            "privacy fixture {} missing common result field {required}",
                            case.name
                        );
                    }
                }
                for required_flag in [
                    "resolve_target_hidden_targets_are_indistinguishable",
                    "ingest_requires_resource_directory_opt_in",
                    "ingest_rejects_bad_signature_and_stale_signature",
                    "withdraw_and_takedown_have_blinded_external_responses",
                    "psi_is_set_membership_only",
                    "psi_denials_are_padded_and_timing_blinded",
                ] {
                    if expected.get(required_flag).and_then(Value::as_bool) != Some(true) {
                        bail!(
                            "privacy fixture {} flag {required_flag} is not true",
                            case.name
                        );
                    }
                }
                record_vector_event(
                    "privacy.directory_query_and_ingest_vector_closure",
                    &json!({
                        "operation_ids": operation_ids,
                        "covers_vectors": covers_vectors.len(),
                    }),
                    &json!({
                        "required_operation_ids_present": true,
                        "common_fields_present": true,
                        "directory_and_psi_guards_true": true,
                    }),
                    &json!({
                        "operation_ids": operation_ids,
                        "covers_vectors": covers_vectors.len(),
                        "common_fields": common_fields,
                    }),
                );
            }
            "plaintext_visible_service_required_for_private_body_processing" => {
                let expected = case
                    .expected
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing expected", case.name))?;
                if expected.get("decision").and_then(Value::as_str) != Some("deny")
                    || expected
                        .get("must_not_forward_plaintext")
                        .and_then(Value::as_bool)
                        != Some(true)
                {
                    bail!(
                        "privacy fixture {} no longer denies unauthorized plaintext processing",
                        case.name
                    );
                }
                record_vector_event(
                    "privacy.plaintext_visible_service_required_for_private_body_processing",
                    &json!({}),
                    &json!({"decision": "deny", "must_not_forward_plaintext": true}),
                    &json!({
                        "decision": expected.get("decision").cloned(),
                        "must_not_forward_plaintext": expected
                            .get("must_not_forward_plaintext")
                            .cloned(),
                    }),
                );
            }
            "blind_index_stale_posting_fail_closed" => {
                let inputs = case
                    .inputs
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing inputs", case.name))?;
                let expected = case
                    .expected
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing expected", case.name))?;
                for required_flag in [
                    "must_not_return_unauthorized_hit",
                    "may_omit_authorized_hit",
                    "stale_posting_rejected_or_filtered",
                ] {
                    if expected.get(required_flag).and_then(Value::as_bool) != Some(true) {
                        bail!(
                            "privacy fixture {} flag {required_flag} is not true",
                            case.name
                        );
                    }
                }
                if expected.get("audit_reason").and_then(Value::as_str)
                    != Some("search_stale_posting_filtered")
                {
                    bail!(
                        "privacy fixture {} missing stale posting audit reason",
                        case.name
                    );
                }
                if inputs.len() < 4 {
                    bail!(
                        "privacy fixture {} must cover revoked capability, visibility, redaction/expiry, and MLS epoch rotation",
                        case.name
                    );
                }

                let mut filtered = 0usize;
                for input in inputs {
                    let state_change = input
                        .get("state_change")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            anyhow!(
                                "privacy fixture {} stale posting input missing state_change",
                                case.name
                            )
                        })?;
                    let digest = input
                        .get("posting_digest")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            anyhow!(
                                "privacy fixture {} stale posting input missing posting_digest",
                                case.name
                            )
                        })?;
                    if !is_sha256_digest(digest) {
                        bail!(
                            "privacy fixture {} stale posting input has invalid digest {digest}",
                            case.name
                        );
                    }
                    if is_fail_closed_search_state_change(state_change) {
                        filtered += 1;
                    } else {
                        bail!(
                            "privacy fixture {} unexpected stale posting state_change {state_change}",
                            case.name
                        );
                    }
                }

                record_vector_event(
                    "privacy.blind_index_stale_posting_fail_closed",
                    &json!({"inputs": inputs, "input_count": inputs.len()}),
                    &json!({
                        "returned_hits": 0,
                        "audit_reason": "search_stale_posting_filtered",
                    }),
                    &json!({
                        "filtered_postings": filtered,
                        "returned_hits": 0,
                        "audit_reason": expected.get("audit_reason").cloned(),
                    }),
                );
            }
            "search_result_not_authorization_proof" => {
                let input = case
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing input", case.name))?;
                let expected = case
                    .expected
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing expected", case.name))?;
                for required_flag in [
                    "client_or_projection_revalidates_visibility",
                    "unauthorized_hit_omitted_or_stubbed",
                ] {
                    if expected.get(required_flag).and_then(Value::as_bool) != Some(true) {
                        bail!(
                            "privacy fixture {} flag {required_flag} is not true",
                            case.name
                        );
                    }
                }
                if input.get("post_query_visibility").and_then(Value::as_str)
                    != Some("not_authorized")
                {
                    bail!(
                        "privacy fixture {} must exercise post-query not_authorized visibility",
                        case.name
                    );
                }
                let hit_digest = input
                    .pointer("/candidate_hit/object_ref_digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("privacy fixture {} missing candidate hit digest", case.name)
                    })?;
                if !is_sha256_digest(hit_digest) {
                    bail!(
                        "privacy fixture {} candidate hit digest is invalid: {hit_digest}",
                        case.name
                    );
                }

                let stub = unauthorized_search_result_stub();
                if stub.get("visibility").and_then(Value::as_str) != Some("locked")
                    || stub.get("opaque_ref").and_then(Value::as_str) != Some("fixed_length")
                {
                    bail!(
                        "privacy fixture {} unauthorized stub shape drifted",
                        case.name
                    );
                }
                let forbidden = expected
                    .get("must_not_include")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("privacy fixture {} missing must_not_include", case.name)
                    })?;
                for field in forbidden {
                    let field = field.as_str().ok_or_else(|| {
                        anyhow!(
                            "privacy fixture {} must_not_include entry must be string",
                            case.name
                        )
                    })?;
                    if stub.get(field).is_some() {
                        bail!(
                            "privacy fixture {} unauthorized search stub leaked field {field}",
                            case.name
                        );
                    }
                }

                record_vector_event(
                    "privacy.search_result_not_authorization_proof",
                    &json!({"candidate_hit": input.get("candidate_hit").cloned()}),
                    &json!({"visibility": "locked", "opaque_ref": "fixed_length"}),
                    &json!({
                        "stub": stub,
                        "forbidden_field_count": forbidden.len(),
                    }),
                );
            }
            "search_surface_separation_no_plaintext_leakage" => {
                validate_search_surface_separation(&case)?;
            }
            "pairwise_did_resolve_proof" => {
                let no_proof = resolve_private_did(None);
                let with_proof = resolve_private_did(Some("holder-proof"));
                if no_proof.is_ok() || with_proof.is_err() {
                    bail!("privacy fixture {} proof requirement mismatch", case.name);
                }
                record_vector_event(
                    "privacy.pairwise_did_resolve_proof",
                    &json!({"no_proof_request": null, "with_proof_request": "holder-proof"}),
                    &json!({"no_proof_ok": false, "with_proof_ok": true}),
                    &json!({
                        "no_proof_ok": no_proof.is_ok(),
                        "with_proof_ok": with_proof.is_ok(),
                    }),
                );
            }
            "encrypted_payload_forwarding_without_plaintext" => {
                let forwarded = forwarded_encrypted_payload();
                if forwarded.get("plaintext").is_some()
                    || forwarded["ciphertext"] != "opaque-ciphertext"
                {
                    bail!(
                        "privacy fixture {} did not preserve ciphertext-only forwarding",
                        case.name
                    );
                }
                record_vector_event(
                    "privacy.encrypted_payload_forwarding_without_plaintext",
                    &json!({}),
                    &json!({
                        "plaintext_present": false,
                        "ciphertext": "opaque-ciphertext",
                    }),
                    &json!({
                        "forwarded": forwarded.clone(),
                        "plaintext_present": forwarded.get("plaintext").is_some(),
                        "ciphertext": forwarded["ciphertext"].clone(),
                    }),
                );
            }
            "prepare_and_validate_internationalized_identifiers" => {
                let input = case
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing input", case.name))?;
                let canonical_handles = input
                    .get("accepted_canonical_handles")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("privacy fixture {} missing canonical handles", case.name)
                    })?;
                for value in canonical_handles {
                    let value = value.as_str().ok_or_else(|| {
                        anyhow!("privacy fixture {} has non-string handle", case.name)
                    })?;
                    arkret_models_identity::handle::Handle::parse(value).map_err(|error| {
                        anyhow!("privacy fixture {} rejected {value}: {error}", case.name)
                    })?;
                }

                let slugs = input
                    .get("accepted_agent_slugs")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing agent slugs", case.name))?;
                for value in slugs {
                    arkret_wire::validate_canonical_agent_slug(value.as_str().ok_or_else(
                        || anyhow!("privacy fixture {} has non-string agent slug", case.name),
                    )?)?;
                }

                let display_texts = input
                    .get("accepted_single_line_display_text")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing display text", case.name))?;
                for value in display_texts {
                    arkret_wire::validate_single_line_display_text(
                        value.as_str().ok_or_else(|| {
                            anyhow!("privacy fixture {} has non-string display text", case.name)
                        })?,
                        256,
                    )?;
                }

                let acct_alias = input
                    .get("accepted_acct_alias")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing acct alias", case.name))?;
                arkret_models_identity::handle::Handle::from_acct(acct_alias)?;

                let mappings = input
                    .get("input_to_canonical")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing mappings", case.name))?;
                for mapping in mappings {
                    let source = mapping
                        .get("input")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            anyhow!("privacy fixture {} mapping missing input", case.name)
                        })?;
                    let expected = mapping
                        .get("canonical")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            anyhow!("privacy fixture {} mapping missing canonical", case.name)
                        })?;
                    let prepared = arkret_models_identity::handle::Handle::prepare(source)?;
                    if prepared.canonical() != expected {
                        bail!(
                            "privacy fixture {} prepared {source} as {}, expected {expected}",
                            case.name,
                            prepared.canonical()
                        );
                    }
                }

                for value in input
                    .get("rejected_identifiers")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("privacy fixture {} missing rejected identifiers", case.name)
                    })?
                {
                    let value = value.as_str().ok_or_else(|| {
                        anyhow!("privacy fixture {} has non-string rejection", case.name)
                    })?;
                    if arkret_models_identity::handle::Handle::parse(value).is_ok() {
                        bail!(
                            "privacy fixture {} unexpectedly accepted {value}",
                            case.name
                        );
                    }
                }
                for value in input
                    .get("rejected_single_line_display_text")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!(
                            "privacy fixture {} missing rejected display text",
                            case.name
                        )
                    })?
                {
                    let value = value.as_str().ok_or_else(|| {
                        anyhow!("privacy fixture {} has non-string rejection", case.name)
                    })?;
                    if arkret_wire::validate_single_line_display_text(value, 256).is_ok() {
                        bail!(
                            "privacy fixture {} unexpectedly accepted display text",
                            case.name
                        );
                    }
                }

                for pair in input
                    .get("external_identifier_pairs_not_generically_equal")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!(
                            "privacy fixture {} missing external identifier pairs",
                            case.name
                        )
                    })?
                {
                    let pair = pair.as_array().ok_or_else(|| {
                        anyhow!(
                            "privacy fixture {} has malformed identifier pair",
                            case.name
                        )
                    })?;
                    if pair.len() != 2 || pair[0].as_str() == pair[1].as_str() {
                        bail!(
                            "privacy fixture {} generic equality pair drifted",
                            case.name
                        );
                    }
                }

                let expected = case
                    .expected
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing expected", case.name))?;
                let checks = expected
                    .get("checks")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing checks", case.name))?;
                for required in [
                    "rfc8265_username_case_mapped",
                    "canonical_receiver_rejects_noncanonical_wire",
                    "uts46_nontransitional_std3_bidi_joiner_hyphen_dns_length",
                    "unicode_code_point_and_utf8_octet_limits",
                    "single_line_text_nfc_controls_and_whitespace",
                    "external_identifier_comparison_is_profile_specific",
                    "rfc7565_utf8_percent_encoding_without_port",
                ] {
                    if !checks.iter().any(|value| value.as_str() == Some(required)) {
                        bail!("privacy fixture {} missing check {required}", case.name);
                    }
                }
                if expected.get("unicode_data_upgrade").and_then(Value::as_str)
                    != Some("rebuild_derived_collision_index_without_rewriting_canonical_values")
                {
                    bail!(
                        "privacy fixture {} Unicode upgrade contract drifted",
                        case.name
                    );
                }
                record_vector_event(
                    "privacy.prepare_and_validate_internationalized_identifiers",
                    input,
                    expected,
                    expected,
                );
            }
            "uts39_skeleton_is_authority_local_derived_state" => {
                let input = case
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing input", case.name))?;
                let parse_handle = |field: &str| -> Result<arkret_models_identity::handle::Handle> {
                    let value = input
                        .get(field)
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("privacy fixture {} missing {field}", case.name))?;
                    Ok(arkret_models_identity::handle::Handle::parse(value)?)
                };
                let registered = parse_handle("registered")?;
                let candidate = parse_handle("confusable_candidate")?;
                let other_authority = parse_handle("same_skeleton_other_authority")?;
                let alias_value = input
                    .get("same_string_realm_alias_namespace")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing realm alias", case.name))?;
                arkret_models_collaboration::objects::realm_alias::RealmAlias::parse(alias_value)?;

                let registered_skeleton = registered.registration_skeleton()?;
                if registered_skeleton != candidate.registration_skeleton()?
                    || registered_skeleton != other_authority.registration_skeleton()?
                    || registered.domain() != candidate.domain()
                    || registered.domain() == other_authority.domain()
                {
                    bail!("privacy fixture {} collision scoping drifted", case.name);
                }
                let expected = case
                    .expected
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing expected", case.name))?;
                if expected
                    .get("canonical_equality_uses_skeleton")
                    .and_then(Value::as_bool)
                    != Some(false)
                    || expected
                        .get("skeleton_enters_wire_or_proof")
                        .and_then(Value::as_bool)
                        != Some(false)
                    || expected
                        .get("same_authority_handle_registration")
                        .and_then(Value::as_str)
                        != Some("handle_homograph_forbidden")
                    || expected
                        .get("other_authority_handle_registration")
                        .and_then(Value::as_str)
                        != Some("not_a_collision")
                    || expected
                        .get("realm_alias_registration")
                        .and_then(Value::as_str)
                        != Some("not_a_cross_namespace_collision")
                {
                    bail!(
                        "privacy fixture {} skeleton wire contract drifted",
                        case.name
                    );
                }
                record_vector_event(
                    "privacy.uts39_skeleton_is_authority_local_derived_state",
                    input,
                    expected,
                    expected,
                );
            }
            // §9.14 `ak.vector.identity_link.minimal_metadata_author_credential.v1`
            // — dedicated runner (the fixture's `runner` field names it);
            // executed here too so the suite covers every fixture case.
            super::privacy_security::MINIMAL_METADATA_AUTHOR_CREDENTIAL_CASE => {
                super::privacy_security::run_minimal_metadata_author_credential_vector()?;
            }
            super::privacy_security::ACTOR_ACCOUNTABILITY_GRANT_REQUIRED_CASE => {
                validate_actor_accountability_grant_required(&case)?;
                super::privacy_security::run_actor_accountability_grant_required_vector()?;
            }
            _ => bail!("unknown privacy fixture case {}", case.name),
        }
    }

    Ok(())
}

fn validate_actor_accountability_grant_required(case: &super::NamedCase) -> Result<()> {
    if case.vector_id.as_deref() != Some("ak.vector.actor.accountability_grant_required.v1") {
        bail!("{} has an unexpected vector_id", case.name);
    }
    let cases = case
        .cases
        .as_ref()
        .ok_or_else(|| anyhow!("{} is missing cases[]", case.name))?;
    let mut seen = BTreeSet::new();
    for subcase in cases {
        let name = subcase
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{} contains an unnamed case", case.name))?;
        if !seen.insert(name) {
            bail!("{} contains duplicate case {name}", case.name);
        }

        if let Some(accountable) = subcase
            .get("accountable_principal_ids")
            .and_then(Value::as_array)
        {
            let accountable = accountable
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| anyhow!("{name} accountable principal must be text"))
                })
                .collect::<Result<BTreeSet<_>>>()?;
            let active = subcase
                .get("matching_active_grants")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("{name} is missing matching_active_grants[]"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| anyhow!("{name} matching grant must be text"))
                })
                .collect::<Result<BTreeSet<_>>>()?;
            let accepted = accountable.is_subset(&active);
            let expected = subcase
                .pointer("/expected/decision")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("{name} is missing expected.decision"))?;
            if accepted != (expected == "accept") {
                bail!(
                    "{name} produced {}, expected {expected}",
                    if accepted {
                        "accept"
                    } else {
                        "failed_precondition"
                    }
                );
            }
            if !accepted {
                if subcase
                    .pointer("/expected/reason_code")
                    .and_then(Value::as_str)
                    != Some("accountability_grant_missing")
                    || subcase
                        .pointer("/expected/profile_cell_unchanged")
                        .and_then(Value::as_bool)
                        != Some(true)
                {
                    bail!("{name} does not pin atomic accountability rejection");
                }
            } else if subcase
                .pointer("/expected/stored_accountable_principal_ids_equal_signed_payload")
                .and_then(Value::as_bool)
                != Some(true)
            {
                bail!("{name} does not preserve the exact signed profile value");
            }
        } else {
            if subcase
                .get("profile_write_was_valid_when_accepted")
                .and_then(Value::as_bool)
                != Some(true)
                || subcase
                    .get("grant_status_after_acceptance")
                    .and_then(Value::as_str)
                    != Some("revoked")
                || subcase
                    .pointer("/expected/profile_event_remains_in_log")
                    .and_then(Value::as_bool)
                    != Some(true)
                || subcase
                    .pointer("/expected/projection_trust_state")
                    .and_then(Value::as_str)
                    != Some("unverified")
                || subcase
                    .pointer("/expected/next_profile_update_with_revoked_entry")
                    .and_then(Value::as_str)
                    != Some("accountability_grant_missing")
            {
                bail!("{name} does not pin post-accept revocation presentation semantics");
            }
        }
    }
    for required in [
        "create_missing_grant_rejects_whole_event",
        "update_missing_one_of_multiple_grants_rejects_whole_event",
        "all_grants_active_accepts_exact_signed_value",
        "later_revoke_marks_existing_projection_unverified",
    ] {
        if !seen.contains(required) {
            bail!("{} is missing required case {required}", case.name);
        }
    }
    record_vector_event(
        "privacy.actor_profile_accountability_grant_is_deterministic",
        &json!({"case_names": seen}),
        &json!({"all_accountability_checks_executed": true}),
        &json!({"all_accountability_checks_executed": true}),
    );
    Ok(())
}

/// Vectors `ak.vector.directory.resolve_handle_failure_blinding.v1` and
/// `ak.vector.directory.resolve_agent_selector_failure_blinding.v1`.
///
/// A directory resolve over a missing, hidden, or unauthorized target MUST be
/// externally indistinguishable: identical HTTP status (404), identical error
/// code (`not_found`), identical body shape, identical timing class, and the
/// response MUST NOT include any of the binding/identity fields that would let
/// a probe distinguish "hidden" from "missing".
fn validate_resolve_failure_blinding(case: &super::NamedCase, expected_op: &str) -> Result<()> {
    let op_id = case.operation_id.as_deref();
    if op_id != Some(expected_op) {
        bail!(
            "privacy fixture {} operation_id {:?} drifted from {expected_op}",
            case.name,
            op_id
        );
    }
    let inputs = case
        .inputs
        .as_ref()
        .ok_or_else(|| anyhow!("privacy fixture {} missing inputs", case.name))?;
    if inputs.len() < 3 {
        bail!(
            "privacy fixture {} must cover missing/hidden/unauthorized inputs",
            case.name
        );
    }
    let expected = case
        .expected
        .as_ref()
        .ok_or_else(|| anyhow!("privacy fixture {} missing expected", case.name))?;

    if expected.get("same_http_status").and_then(Value::as_u64) != Some(404) {
        bail!("privacy fixture {} same_http_status is not 404", case.name);
    }
    if expected.get("same_error_code").and_then(Value::as_str) != Some("not_found") {
        bail!(
            "privacy fixture {} same_error_code is not not_found",
            case.name
        );
    }
    if expected
        .get("timing_equivalence_group")
        .and_then(Value::as_str)
        != Some("directory_hidden_not_found")
    {
        bail!(
            "privacy fixture {} timing_equivalence_group drifted",
            case.name
        );
    }
    let body_shape = expected
        .get("same_body_shape")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("privacy fixture {} missing same_body_shape", case.name))?;
    if body_shape.is_empty() {
        bail!(
            "privacy fixture {} same_body_shape must not be empty",
            case.name
        );
    }
    let must_not_include = expected
        .get("must_not_include")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("privacy fixture {} missing must_not_include", case.name))?;
    if must_not_include.is_empty() {
        bail!(
            "privacy fixture {} must_not_include must not be empty",
            case.name
        );
    }

    // `must_not_include` constrains the blinded *response*: the single shared
    // 404 body shape must NOT carry any of these fields, regardless of the
    // underlying failure reason (missing / hidden / unauthorized). The query
    // inputs legitimately contain the looked-up selector fields (e.g.
    // `controller_subject`), so the check is against `same_body_shape` — the
    // declared response field set — not the request inputs.
    let body_shape_fields: Vec<&str> = body_shape.iter().filter_map(Value::as_str).collect();
    for field in must_not_include {
        let field = field.as_str().ok_or_else(|| {
            anyhow!(
                "privacy fixture {} must_not_include entry must be string",
                case.name
            )
        })?;
        if body_shape_fields.contains(&field) {
            bail!(
                "privacy fixture {} blinded response body shape leaks forbidden field {field}",
                case.name
            );
        }
    }

    record_vector_event(
        "privacy.resolve_failure_blinding",
        &json!({
            "operation_id": expected_op,
            "input_count": inputs.len(),
        }),
        &json!({
            "same_http_status": 404,
            "same_error_code": "not_found",
            "timing_equivalence_group": "directory_hidden_not_found",
        }),
        &json!({
            "operation_id": case.operation_id.clone(),
            "same_http_status": expected.get("same_http_status").cloned(),
            "must_not_include_count": must_not_include.len(),
        }),
    );
    Ok(())
}

fn validate_search_surface_separation(case: &super::NamedCase) -> Result<()> {
    let input = case
        .input
        .as_ref()
        .ok_or_else(|| anyhow!("privacy fixture {} missing input", case.name))?;
    let expected = case
        .expected
        .as_ref()
        .ok_or_else(|| anyhow!("privacy fixture {} missing expected", case.name))?;
    if expected
        .get("must_not_confuse_surfaces")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!(
            "privacy fixture {} must require surface separation",
            case.name
        );
    }

    let required_surfaces = string_set(
        expected
            .get("required_surfaces")
            .ok_or_else(|| anyhow!("privacy fixture {} missing required_surfaces", case.name))?,
    )?;
    let forbidden_fields = string_set(
        expected
            .get("forbidden_fields")
            .ok_or_else(|| anyhow!("privacy fixture {} missing forbidden_fields", case.name))?,
    )?;
    let forbidden_literals = string_set(
        expected
            .get("forbidden_literals")
            .ok_or_else(|| anyhow!("privacy fixture {} missing forbidden_literals", case.name))?,
    )?;
    let surfaces = input
        .get("surfaces")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("privacy fixture {} missing surfaces", case.name))?;
    let mut seen = BTreeSet::new();
    for surface_case in surfaces {
        let surface = required_value_str(surface_case, "surface")?;
        if !seen.insert(surface.to_owned()) {
            bail!("privacy fixture {} repeats surface {surface}", case.name);
        }
        let profile = required_value_str(surface_case, "profile")?;
        let payload = surface_case
            .get("payload")
            .ok_or_else(|| anyhow!("surface {surface} missing payload"))?;
        validate_no_forbidden_payload(surface, payload, &forbidden_fields, &forbidden_literals)?;
        validate_search_surface_contract(surface, profile, surface_case, payload)?;
    }

    if seen != required_surfaces {
        bail!(
            "privacy fixture {} surfaces {:?} do not match required {:?}",
            case.name,
            seen,
            required_surfaces
        );
    }

    record_vector_event(
        "privacy.search_surface_separation_no_plaintext_leakage",
        &json!({
            "surface_count": surfaces.len(),
            "required_surfaces": required_surfaces,
        }),
        &json!({
            "surfaces_separated": true,
            "plaintext_leaked": false,
        }),
        &json!({
            "surfaces": seen,
            "forbidden_fields": forbidden_fields,
            "forbidden_literals": forbidden_literals,
        }),
    );
    Ok(())
}

fn validate_search_surface_contract(
    surface: &str,
    profile: &str,
    surface_case: &Value,
    payload: &Value,
) -> Result<()> {
    match surface {
        "directory_search" => {
            if profile != "ak.profile.directory_service.v1" {
                bail!("directory_search must use directory_service profile");
            }
            if required_value_str(surface_case, "operation_id")?
                != "ak.find.directory.read.search_realms"
            {
                bail!("directory_search operation_id drifted");
            }
            for forbidden in ["query_tokens", "candidate_digest", "payload_digest"] {
                if contains_key_recursive(payload, forbidden) {
                    bail!("directory_search leaked {forbidden}");
                }
            }
        }
        "privacy_preserving_search" => {
            if profile != "ak.profile.search.blind_index.v1" {
                bail!("privacy_preserving_search must use blind_index profile");
            }
            if payload.get("title").is_some()
                || payload.get("summary").is_some()
                || payload.get("room_id").is_some()
            {
                bail!("privacy_preserving_search mixed directory or bridge fields");
            }
            let scope = payload
                .get("effective_scope")
                .ok_or_else(|| anyhow!("privacy_preserving_search missing effective_scope"))?;
            if scope.get("kind").and_then(Value::as_str) != Some("realm") {
                bail!("privacy_preserving_search effective_scope must be realm-scoped");
            }
            let tokens = payload
                .get("query_tokens")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("privacy_preserving_search missing query_tokens"))?;
            if tokens.is_empty() {
                bail!("privacy_preserving_search query_tokens must not be empty");
            }
            for token in tokens {
                let token = token
                    .as_str()
                    .ok_or_else(|| anyhow!("privacy_preserving_search token must be string"))?;
                if !is_sha256_digest(token) {
                    bail!("privacy_preserving_search token is not a sha256 digest");
                }
            }
            let candidate_digest = required_value_str(payload, "candidate_digest")?;
            if !is_sha256_digest(candidate_digest) {
                bail!("privacy_preserving_search candidate_digest is invalid");
            }
        }
        "bridge_interop" => {
            if profile != "ak.profile.mimi_interop.v1" {
                bail!("bridge_interop must use mimi_interop profile");
            }
            if required_value_str(surface_case, "operation_id")? != "ak.open.mimi.command.notify" {
                bail!("bridge_interop operation_id drifted");
            }
            for forbidden in ["query_tokens", "candidate_digest", "title", "summary"] {
                if contains_key_recursive(payload, forbidden) {
                    bail!("bridge_interop mixed search or directory field {forbidden}");
                }
            }
            let payload_digest = required_value_str(payload, "payload_digest")?;
            if !is_sha256_digest(payload_digest) {
                bail!("bridge_interop payload_digest is invalid");
            }
        }
        other => bail!("unknown search surface {other}"),
    }
    Ok(())
}

fn validate_no_forbidden_payload(
    surface: &str,
    payload: &Value,
    forbidden_fields: &BTreeSet<String>,
    forbidden_literals: &BTreeSet<String>,
) -> Result<()> {
    for field in forbidden_fields {
        if contains_key_recursive(payload, field) {
            bail!("surface {surface} leaked forbidden field {field}");
        }
    }
    for literal in forbidden_literals {
        if contains_literal_recursive(payload, literal) {
            bail!("surface {surface} leaked forbidden literal {literal}");
        }
    }
    Ok(())
}

fn anti_enumeration_blob_error(_hidden: bool) -> &'static str {
    "not_found"
}

fn blind_wakeup_payload() -> Value {
    json!({
        "device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
        "wakeup": true
    })
}

fn resolve_private_did(proof: Option<&str>) -> Result<&'static str> {
    match proof {
        Some("holder-proof") => Ok("resolved"),
        _ => bail!("resolve_requires_holder_approved_proof"),
    }
}

fn forwarded_encrypted_payload() -> Value {
    json!({
        "ciphertext": "opaque-ciphertext",
        "content_type": "ak.mls.application"
    })
}

fn unauthorized_search_result_stub() -> Value {
    json!({
        "visibility": "locked",
        "opaque_ref": "fixed_length"
    })
}

fn is_fail_closed_search_state_change(state_change: &str) -> bool {
    matches!(
        state_change,
        "capability_revoked"
            | "history_access_private"
            | "redaction_or_expiry"
            | "mls_epoch_rotate"
    )
}

fn is_sha256_digest(digest: &str) -> bool {
    digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn required_value_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn string_set(value: &Value) -> Result<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("expected string array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("expected string array item"))
        })
        .collect::<Result<BTreeSet<_>>>()
}

fn contains_key_recursive(value: &Value, needle: &str) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| key == needle || contains_key_recursive(value, needle)),
        Value::Array(items) => items
            .iter()
            .any(|item| contains_key_recursive(item, needle)),
        _ => false,
    }
}

fn contains_literal_recursive(value: &Value, needle: &str) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| key.contains(needle) || contains_literal_recursive(value, needle)),
        Value::Array(items) => items
            .iter()
            .any(|item| contains_literal_recursive(item, needle)),
        Value::String(raw) => raw.contains(needle),
        _ => false,
    }
}
