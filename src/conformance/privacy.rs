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
                let op_ok = matches!(op_id, Some("ck.find.directory.query.resolve_realm"));
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
                        "operation_id": "ck.find.directory.query.resolve_realm",
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
                validate_resolve_failure_blinding(
                    &case,
                    "ck.find.directory.query.resolve_handle",
                )?;
            }
            "resolve_agent_selector_failure_blinding" => {
                validate_resolve_failure_blinding(
                    &case,
                    "ck.find.directory.query.resolve_agent_selector",
                )?;
            }
            "private_contact_discovery_padding_and_cardinality" => {
                let input = case
                    .input
                    .as_ref()
                    .ok_or_else(|| anyhow!("privacy fixture {} missing input", case.name))?;
                let contact_count = input
                    .get("contacts")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                let target_batch_size = input
                    .pointer("/padding/target_batch_size")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("privacy fixture {} missing target batch", case.name))?;
                if target_batch_size <= contact_count as u64 {
                    bail!(
                        "privacy fixture {} does not pad contact discovery",
                        case.name
                    );
                }
                record_vector_event(
                    "privacy.private_contact_discovery_padding_and_cardinality",
                    &json!({
                        "contacts": contact_count,
                        "target_batch_size": target_batch_size,
                    }),
                    &json!({"target_batch_size_gt_contacts": true}),
                    &json!({
                        "target_batch_size": target_batch_size,
                        "contact_count": contact_count,
                        "target_batch_size_gt_contacts": target_batch_size > contact_count as u64,
                    }),
                );
            }
            "directory_query_and_ingest_vector_closure" => {
                let operation_ids = case.operation_ids.as_ref().ok_or_else(|| {
                    anyhow!("privacy fixture {} missing operation_ids", case.name)
                })?;
                for required in [
                    "ck.find.directory.query.search_realms",
                    "ck.find.directory.query.resolve_realm",
                    "ck.find.directory.query.resolve_target",
                    "ck.find.directory.command.announce",
                    "ck.find.directory.command.withdraw",
                    "ck.find.directory.query.private_contact_discovery",
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
            _ => bail!("unknown privacy fixture case {}", case.name),
        }
    }

    Ok(())
}

/// Vectors `ck.vector.directory.resolve_handle_failure_blinding.v1` and
/// `ck.vector.directory.resolve_agent_selector_failure_blinding.v1`.
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
        bail!(
            "privacy fixture {} same_http_status is not 404",
            case.name
        );
    }
    if expected.get("same_error_code").and_then(Value::as_str) != Some("not_found") {
        bail!(
            "privacy fixture {} same_error_code is not not_found",
            case.name
        );
    }
    if expected.get("same_timing_class").and_then(Value::as_str) != Some("directory_hidden_not_found")
    {
        bail!(
            "privacy fixture {} same_timing_class drifted",
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
            "same_timing_class": "directory_hidden_not_found",
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
            if profile != "ck.profile.directory_service.v1" {
                bail!("directory_search must use directory_service profile");
            }
            if required_value_str(surface_case, "operation_id")?
                != "ck.find.directory.query.search_realms"
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
            if profile != "ck.profile.search.blind_index.v1" {
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
            if profile != "ck.profile.mimi_interop.v1" {
                bail!("bridge_interop must use mimi_interop profile");
            }
            if required_value_str(surface_case, "operation_id")? != "ck.open.mimi.command.notify" {
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
        "device_id": "ck:device:01904100-0000-7000-8000-0000000000a1",
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
        "content_type": "ck.mls.application"
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
            | "history_visibility_private"
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
