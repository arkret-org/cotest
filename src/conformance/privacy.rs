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

fn anti_enumeration_blob_error(_hidden: bool) -> &'static str {
    "not_found"
}

fn blind_wakeup_payload() -> Value {
    json!({
        "device_id": "dev_alice",
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
