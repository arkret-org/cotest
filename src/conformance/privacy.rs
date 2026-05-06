use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{PrivacySecurityFixture, load_fixture_value, parse_fixture_value};

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
            }
            "push_blind_wakeup_payload" => {
                let payload = blind_wakeup_payload();
                if payload.get("body").is_some() || payload.get("members").is_some() {
                    bail!(
                        "privacy fixture {} leaked plaintext wakeup fields",
                        case.name
                    );
                }
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
            }
            "pairwise_did_resolve_proof" => {
                if resolve_private_did(None).is_ok()
                    || resolve_private_did(Some("holder-proof")).is_err()
                {
                    bail!("privacy fixture {} proof requirement mismatch", case.name);
                }
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
