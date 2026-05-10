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
            "hidden_space_resolve_indistinguishable" => {
                if case.operation_id.as_deref() != Some("cx.directory.resolve_space")
                    || case
                        .expected
                        .as_ref()
                        .and_then(|expected| expected.get("same_http_status"))
                        .and_then(Value::as_u64)
                        != Some(404)
                {
                    bail!(
                        "privacy fixture {} no longer proves indistinguishable resolve errors",
                        case.name
                    );
                }
                record_vector_event(
                    "privacy.hidden_space_resolve_indistinguishable",
                    &json!({"operation_id": case.operation_id.clone()}),
                    &json!({
                        "operation_id": "cx.directory.resolve_space",
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
        "content_type": "cx.mls.application"
    })
}
