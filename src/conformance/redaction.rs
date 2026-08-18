use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use sha2::Digest;

use super::schema_validation_fixture::SchemaEnv;
use super::{RedactionFixture, load_artifact_json, load_fixture};
use crate::transcripts::record_vector_event;

const DIGEST64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub fn run_redaction_fixture_suite() -> Result<()> {
    let fixture = load_fixture::<RedactionFixture>("redaction-fixture.json")?;
    if fixture.suite != "redaction" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }
    let target = sample_event();

    for case in fixture.cases {
        match case.name.as_str() {
            "preserved_fields" => {
                let redacted = redact_event(
                    &target,
                    "ak:event:AVT646YSuJEmqd74GGTJeNPstd7RiLkX4UvuFWM_F23V",
                )?;
                let preserve = case.preserve.clone().unwrap_or_default();
                for field in &preserve {
                    if redacted.get(field).is_none() {
                        bail!("redaction fixture {} did not preserve {}", case.name, field);
                    }
                }
                if redacted.get("content").is_some() {
                    bail!("redaction fixture {} leaked content", case.name);
                }
                record_vector_event(
                    "redaction.preserved_fields",
                    &json!({"target": target.clone()}),
                    &json!({"preserve": preserve, "content_present": false}),
                    &json!({"redacted": redacted, "content_present": redacted.get("content").is_some()}),
                );
            }
            "dangling_redaction" => {
                let mut tracker = RedactionTracker::default();
                let state = tracker.push_redaction(
                    "ak:event:AWczqrLO-ACCcf4Qm89_zjDMtCDLF9U0yvLh7ubvYcM_",
                    "ak:event:AVT646YSuJEmqd74GGTJeNPstd7RiLkX4UvuFWM_F23V",
                );
                if state != RedactionState::Pending {
                    bail!("redaction fixture {} expected pending state", case.name);
                }
                record_vector_event(
                    "redaction.dangling_redaction",
                    &json!({
                        "target_event_id": "ak:event:AWczqrLO-ACCcf4Qm89_zjDMtCDLF9U0yvLh7ubvYcM_",
                        "redaction_event_id": "ak:event:AVT646YSuJEmqd74GGTJeNPstd7RiLkX4UvuFWM_F23V",
                    }),
                    &json!({"state": "Pending"}),
                    &json!({"state": format!("{state:?}")}),
                );
            }
            "late_target_event" => {
                let mut tracker = RedactionTracker::default();
                tracker.push_redaction(
                    "ak:event:ASBAmAp_QXah5xLOjP7jPyhUl9mH1PoRG4gDzpWyx9oN",
                    "ak:event:AVT646YSuJEmqd74GGTJeNPstd7RiLkX4UvuFWM_F23V",
                );
                let materialized = tracker.materialize_target(&sample_event_with_id(
                    "ak:event:ASBAmAp_QXah5xLOjP7jPyhUl9mH1PoRG4gDzpWyx9oN",
                ))?;
                if materialized.get("content").is_some() {
                    bail!(
                        "redaction fixture {} failed to materialize as redacted",
                        case.name
                    );
                }
                if materialized["redacted_because"]
                    != "ak:event:AVT646YSuJEmqd74GGTJeNPstd7RiLkX4UvuFWM_F23V"
                {
                    bail!("redaction fixture {} lost redaction reference", case.name);
                }
                record_vector_event(
                    "redaction.late_target_event",
                    &json!({
                        "target_event_id": "ak:event:ASBAmAp_QXah5xLOjP7jPyhUl9mH1PoRG4gDzpWyx9oN",
                        "redaction_event_id": "ak:event:AVT646YSuJEmqd74GGTJeNPstd7RiLkX4UvuFWM_F23V",
                    }),
                    &json!({
                        "content_present": false,
                        "redacted_because": "ak:event:AVT646YSuJEmqd74GGTJeNPstd7RiLkX4UvuFWM_F23V",
                    }),
                    &json!({
                        "materialized": materialized.clone(),
                        "redacted_because": materialized["redacted_because"].clone(),
                    }),
                );
            }
            "audit_visibility" => {
                let redacted = redact_event(
                    &target,
                    "ak:event:AVT646YSuJEmqd74GGTJeNPstd7RiLkX4UvuFWM_F23V",
                )?;
                let audit = audit_tombstone(&redacted)?;
                if audit.get("content").is_some() {
                    bail!(
                        "redaction fixture {} leaked content to audit view",
                        case.name
                    );
                }
                if audit["redaction_target"] != target["event_id"] {
                    bail!("redaction fixture {} lost target reference", case.name);
                }
                record_vector_event(
                    "redaction.audit_visibility",
                    &json!({"target": target.clone()}),
                    &json!({
                        "audit_content_present": false,
                        "redaction_target": target["event_id"].clone(),
                    }),
                    &json!({
                        "audit": audit.clone(),
                        "redaction_target": audit["redaction_target"].clone(),
                    }),
                );
            }
            "snapshot_pruning_stub" => {
                let redacted = redact_event(
                    &target,
                    "ak:event:AVT646YSuJEmqd74GGTJeNPstd7RiLkX4UvuFWM_F23V",
                )?;
                // After redaction, snapshot should retain verification stub
                if redacted.get("content").is_some() {
                    bail!(
                        "redaction fixture {} leaked content after redaction",
                        case.name
                    );
                }
                if redacted.get("proofs").is_some() {
                    bail!(
                        "redaction fixture {} retained proofs after redaction",
                        case.name
                    );
                }
                if redacted["redaction_target"] != target["event_id"] {
                    bail!("redaction fixture {} lost redaction reference", case.name);
                }
                record_vector_event(
                    "redaction.snapshot_pruning_stub",
                    &json!({"target": target.clone()}),
                    &json!({
                        "content_present": false,
                        "proofs_present": false,
                        "redaction_target": target["event_id"].clone(),
                    }),
                    &json!({
                        "redacted": redacted.clone(),
                        "content_present": redacted.get("content").is_some(),
                        "proofs_present": redacted.get("proofs").is_some(),
                        "redaction_target": redacted["redaction_target"].clone(),
                    }),
                );
            }
            "space_target_ref_schema" => {
                assert_space_target_ref_schema()?;
                record_vector_event(
                    "redaction.space_target_ref_schema",
                    &json!({
                        "target_ref": "ak:space:AdouNWm0_Osk7GwYrppoMcCJUjPlKufC8wapFR7Bj4eN",
                        "reason": "privacy_cleanup",
                    }),
                    &json!({
                        "schema_accepts_ak_space_target_ref": true,
                        "rejects_malformed_space_target_ref": true,
                    }),
                    &json!({
                        "schema_accepts_ak_space_target_ref": true,
                        "rejects_malformed_space_target_ref": true,
                    }),
                );
            }
            "message_target_exclusive_kind" => {
                assert_message_target_exclusive_kind()?;
                record_vector_event(
                    "redaction.message_target_exclusive_kind",
                    &json!({
                        "cross_object_message_target_ref": "ak:message:AVEbR6LJe9T0RIh43YEQxR-vov-d4AbPcHIDId501TNw",
                        "cross_object_message_id_member": "ak:message:AVEbR6LJe9T0RIh43YEQxR-vov-d4AbPcHIDId501TNw",
                    }),
                    &json!({
                        "cross_object_rejects_message_target_ref": true,
                        "cross_object_rejects_message_id_member": true,
                        "message_redact_accepts_message_id": true,
                    }),
                    &json!({
                        "cross_object_rejects_message_target_ref": true,
                        "cross_object_rejects_message_id_member": true,
                        "message_redact_accepts_message_id": true,
                    }),
                );
            }
            "policy_scope" => {
                let outcome = assert_policy_scope_projection()?;
                record_vector_event(
                    "redaction.policy_scope",
                    &outcome.input,
                    &outcome.expected,
                    &outcome.actual,
                );
            }
            "hard_erasure_receipt" => {
                assert_hard_erasure_receipt()?;
                record_vector_event(
                    "redaction.hard_erasure_receipt",
                    &json!({"input": "hard_erasure_with_verification_stub"}),
                    &json!({
                        "receipt_conforms_schema": true,
                        "stub_conforms_schema": true,
                        "rejects_standalone_content_fingerprint": true,
                        "rejects_stub_digest_mismatch": true,
                        "rejects_empty_proofs": true,
                        "legal_hold_requires_evidence": true,
                    }),
                    &json!({
                        "receipt_conforms_schema": true,
                        "stub_conforms_schema": true,
                        "rejects_standalone_content_fingerprint": true,
                        "rejects_stub_digest_mismatch": true,
                        "rejects_empty_proofs": true,
                        "legal_hold_requires_evidence": true,
                    }),
                );
            }
            _ => bail!("unknown redaction fixture case {}", case.name),
        }
    }

    Ok(())
}

/// Vector `ak.vector.redaction.space_target_ref_schema.v1` (conformance §3.2.1).
///
/// The cross-object redaction payload class MUST accept a `ak:space:*`
/// `target_ref` and MUST reject a malformed space ref, so a Space cleanup is
/// never downgraded to an implementation-private extension by a schema gap.
fn assert_space_target_ref_schema() -> Result<()> {
    let env = SchemaEnv::load()?;
    let schema_ref = "schemas/event-payload.schema.json#/$defs/cross_object_redaction_payload";
    let validator = env.compile(schema_ref)?;

    let accepted = json!({
        "target_ref": "ak:space:AdouNWm0_Osk7GwYrppoMcCJUjPlKufC8wapFR7Bj4eN",
        "reason": "privacy_cleanup",
    });
    if !validator.is_valid(&accepted) {
        let detail = validator
            .iter_errors(&accepted)
            .next()
            .map(|error| format!("{error}"))
            .unwrap_or_else(|| "<no error reported>".to_string());
        bail!(
            "space_target_ref_schema: cross_object_redaction_payload rejected a ak:space target_ref: {detail}"
        );
    }

    let malformed = json!({
        "target_ref": "ak:space:not-a-uuid",
        "reason": "privacy_cleanup",
    });
    if validator.is_valid(&malformed) {
        bail!(
            "space_target_ref_schema: cross_object_redaction_payload accepted a malformed ak:space target_ref"
        );
    }

    Ok(())
}

/// Vector `ak.vector.redaction.message_target_exclusive_kind.v1`.
///
/// A Message reaches `state=redacted` only through the object-scoped
/// `ak.message.redact`, so the cross-object `ak.redaction` payload class MUST
/// reject both Message spellings before any cell write
/// (`common-fields.md` §5.1 Message exemption).
fn assert_message_target_exclusive_kind() -> Result<()> {
    let env = SchemaEnv::load()?;
    let cross =
        env.compile("schemas/event-payload.schema.json#/$defs/cross_object_redaction_payload")?;
    let message_redact =
        env.compile("schemas/event-payload.schema.json#/$defs/message_redact_payload")?;

    let message_id = "ak:message:AVEbR6LJe9T0RIh43YEQxR-vov-d4AbPcHIDId501TNw";
    for rejected in [
        json!({"target_ref": message_id}),
        json!({"message_id": message_id}),
    ] {
        if cross.is_valid(&rejected) {
            bail!(
                "message_target_exclusive_kind: cross_object_redaction_payload accepted a Message target {rejected}"
            );
        }
    }

    let accepted = json!({"message_id": message_id});
    if !message_redact.is_valid(&accepted) {
        let detail = message_redact
            .iter_errors(&accepted)
            .next()
            .map(|error| format!("{error}"))
            .unwrap_or_else(|| "<no error reported>".to_string());
        bail!(
            "message_target_exclusive_kind: message_redact_payload rejected its own Message target: {detail}"
        );
    }

    Ok(())
}

struct PolicyScopeOutcome {
    input: Value,
    expected: Value,
    actual: Value,
}

/// Vector `ak.vector.redaction.policy_scope.v1` (conformance §3.3).
///
/// After message -> moderation quarantine -> redaction, the projection MUST
/// strip the redacted content while retaining audit evidence, MUST keep the
/// timeline position (no physical delete), and MUST retain the quarantine
/// decision and its target mapping (quarantine is a display constraint, not a
/// delete). Moderation and redaction each address the Message through the one
/// target carrier their payload class registers.
fn assert_policy_scope_projection() -> Result<PolicyScopeOutcome> {
    let message_event_id = "ak:event:AbTJRA159xoBFUoYTOIMDQve32eQFpWkEb-dThX1wCmA";
    let message_id = "ak:message:AbTJRA159xoBFUoYTOIMDQve32eQFpWkEb-dThX1wCmA";
    let policy_id = "ak:event:AT7Zffi_RUZ2cAwFmu6haQQ20EMcxBP6Cy4u6j-Rka4M";
    let redaction_id = "ak:event:AShdBYxb70La6cHO6cmyp4Dek52Otp3Tshr8pw5HapWi";

    let timeline = json!([
        {
            "event_id": message_event_id,
            "kind": "ak.message.create",
            "content": {"kind": "ak.content.text", "body": "bad link: spam.example/phish"},
        },
        {
            "event_id": policy_id,
            "kind": "ak.moderation.decision",
            "actor_id": "ak:did_core:web:policy-bot.example.com",
            "payload": {
                "target_ref": message_id,
                "decision": "quarantine",
                "issuer": "ak:did_core:web:policy-bot.example.com",
                "request_canonical_digest": "sha256:5f8b3c2ad4e1907664bb2f0c9d1e3a57c48d6b02fe971a35c8d40b7e9a2f6c1d",
                "action": "quarantine_message",
            },
        },
        {
            "event_id": redaction_id,
            "kind": "ak.message.redact",
            "actor_id": "ak:did_core:web:policy-admin.example",
            "payload": {"message_id": message_id, "reason": "policy_recall"},
        },
    ]);

    let projected = project_policy_scope_timeline(&timeline)?;
    let entries = projected
        .as_array()
        .ok_or_else(|| anyhow!("policy_scope projection must be an array"))?;

    if entries.len() != 3 {
        bail!(
            "policy_scope: timeline entry removed after redaction (len={})",
            entries.len()
        );
    }
    let message = &entries[0];
    if message["event_id"] != json!(message_event_id) {
        bail!("policy_scope: redacted event lost its timeline position");
    }
    if message.get("content").is_some() {
        bail!("policy_scope: redacted content is still visible in the projection");
    }
    if message["redaction_target"] != json!(message_id) {
        bail!("policy_scope: stripped audit evidence (redaction target) missing");
    }

    let policy = &entries[1];
    if policy["payload"]["decision"] != json!("quarantine") {
        bail!("policy_scope: quarantine decision was lost or downgraded to delete");
    }
    if policy["payload"]["target_ref"] != json!(message_id) {
        bail!("policy_scope: quarantine target mapping was lost");
    }

    Ok(PolicyScopeOutcome {
        input: timeline,
        expected: json!({
            "timeline_len": 3,
            "redacted_content_present": false,
            "redaction_target": message_id,
            "quarantine_decision": "quarantine",
            "quarantine_target_ref": message_id,
        }),
        actual: json!({
            "timeline_len": entries.len(),
            "redacted_content_present": message.get("content").is_some(),
            "redaction_target": message["redaction_target"].clone(),
            "quarantine_decision": policy["payload"]["decision"].clone(),
            "quarantine_target_ref": policy["payload"]["target_ref"].clone(),
        }),
    })
}

fn project_policy_scope_timeline(timeline: &Value) -> Result<Value> {
    let entries = timeline
        .as_array()
        .ok_or_else(|| anyhow!("policy_scope timeline must be an array"))?;

    // `ak.message.redact` addresses the Message through payload.message_id; the
    // timeline is keyed by the create Event id, which carries the same
    // 33-octet token (common-fields.md 6.0).
    let mut redactions: HashMap<String, (String, String)> = HashMap::new();
    for entry in entries {
        if entry["kind"] == json!("ak.message.redact") {
            let target = entry["payload"]["message_id"]
                .as_str()
                .ok_or_else(|| anyhow!("redaction event missing payload.message_id"))?;
            let target_event_id = match target.strip_prefix("ak:message:") {
                Some(token) => format!("ak:event:{token}"),
                None => target.to_owned(),
            };
            let redaction_event_id = entry["event_id"]
                .as_str()
                .ok_or_else(|| anyhow!("redaction event missing event_id"))?;
            redactions.insert(
                target_event_id,
                (target.to_owned(), redaction_event_id.to_owned()),
            );
        }
    }

    let mut projected = Vec::with_capacity(entries.len());
    for entry in entries {
        let event_id = entry["event_id"]
            .as_str()
            .ok_or_else(|| anyhow!("timeline event missing event_id"))?;
        match redactions.get(event_id) {
            Some((target, redaction_event_id)) if entry["kind"] != json!("ak.message.redact") => {
                projected.push(json!({
                    "event_id": event_id,
                    "kind": entry["kind"].clone(),
                    "redaction_target": target,
                    "redacted_because": redaction_event_id,
                }));
            }
            _ => projected.push(entry.clone()),
        }
    }

    Ok(Value::Array(projected))
}

/// Vector `ak.vector.redaction.hard_erasure_receipt.v1` (conformance §3.4).
///
/// Hard erasure retains a verification stub and a signed receipt that MUST
/// conform to `ak.schema.erasure_receipt.v1`; the stub MUST NOT retain a
/// standalone content hash of the erased plaintext (additionalProperties:false
/// enforces this), and a `blocked_by_legal_hold` outcome MUST carry the legal
/// hold evidence rather than being silently downgraded to a completed erasure.
fn assert_hard_erasure_receipt() -> Result<()> {
    let env = SchemaEnv::load()?;
    let receipt_validator = env.compile("schemas/erasure-receipt.schema.json")?;
    let carrier_validator = env.compile(
        "schemas/erasure-receipt-operations.schema.json#/$defs/erasure_receipt_submit_request_body",
    )?;
    let stub_validator = env.compile("schemas/erasure-verification-stub.schema.json")?;

    let original_event_id = "ak:event:AagGd6PB1SqZp__DzubMh3BTpUU-oWosY3NoR_k38pxq";
    let redaction_event_id = "ak:event:AVT646YSuJEmqd74GGTJeNPstd7RiLkX4UvuFWM_F23V";
    let receipt_id = "ak:receipt:01970e58-0004-7000-8000-000000000010";
    let event_digest = format!("sha256:{DIGEST64}");

    let stub = json!({
        "stub_schema": "ak.schema.erasure_verification_stub.v1",
        "trigger": {"kind": "event", "event_id": redaction_event_id},
        "subject": {"kind": "event", "subject_ref": original_event_id},
        "scope": {"storage_boundary": "canonical_log_minimization"},
        "receipt_id": receipt_id,
        "completed_at": "2026-04-29T00:00:00.000Z",
        "event_digest": event_digest,
        "redaction_authorization_ref": redaction_event_id,
    });
    let digest = arkret_canonical::canonical_sha256(&stub)
        .map_err(|err| anyhow!("hard_erasure_receipt: canonical stub digest failed: {err}"))?;
    if !stub_validator.is_valid(&stub) {
        let detail = stub_validator
            .iter_errors(&stub)
            .next()
            .map(|error| format!("{error}"))
            .unwrap_or_else(|| "<no error reported>".to_string());
        bail!("hard_erasure_receipt: verification stub rejected by schema: {detail}");
    }

    let mut leaky_stub = stub.clone();
    leaky_stub["content_hash"] = json!(digest);
    if stub_validator.is_valid(&leaky_stub) {
        bail!(
            "hard_erasure_receipt: verification stub with a standalone content_hash was accepted (must reject plaintext fingerprints)"
        );
    }

    let mut receipt = json!({
        "schema": "ak.schema.erasure_receipt.v1",
        "receipt_id": receipt_id,
        "trigger": {"kind": "event", "event_id": redaction_event_id},
        "issuer": "ak:did_core:web:erasure.example.com",
        "subject": {"kind": "event", "subject_ref": original_event_id},
        "scope": {"storage_boundary": "canonical_log_minimization"},
        "outcome": "completed",
        "erased_classes": ["canonical_payload_bytes", "derived_plaintext"],
        "retained_stub_digest": digest,
        "retained_stub": stub,
        "completed_at": "2026-04-29T00:00:00.000Z",
        "proofs": [{
            "verification_method": "did:web:erasure.example.com#erasure-key-1",
            "payload_digest": digest,
            "signature": "z3erasurereceiptsignatureplaceholder",
        }],
    });
    let mut proof_input = receipt.clone();
    proof_input
        .as_object_mut()
        .ok_or_else(|| anyhow!("hard_erasure_receipt: receipt must be an object"))?
        .remove("proofs");
    receipt["proofs"][0]["payload_digest"] = Value::String(
        arkret_canonical::canonical_sha256(&proof_input)
            .map_err(|err| anyhow!("hard_erasure_receipt: proof digest failed: {err}"))?,
    );
    if !receipt_validator.is_valid(&receipt) {
        let detail = receipt_validator
            .iter_errors(&receipt)
            .next()
            .map(|error| format!("{error}"))
            .unwrap_or_else(|| "<no error reported>".to_string());
        bail!("hard_erasure_receipt: completed receipt rejected by schema: {detail}");
    }
    verify_erasure_receipt_stub_digest(&receipt, &stub)?;

    let canonical_receipt = arkret_canonical::canonical_json_bytes(&receipt)
        .map_err(|err| anyhow!("hard_erasure_receipt: package digest input failed: {err}"))?;
    let mut package_preimage = b"ak.erasure-receipt.v1\n".to_vec();
    package_preimage.extend_from_slice(&canonical_receipt);
    let receipt_digest = format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(package_preimage))
    );
    let package = json!({
        "receipt": receipt.clone(),
        "receipt_digest": receipt_digest,
        "retained_stub": stub.clone(),
    });
    let carrier_request = json!({"package": package});
    if !carrier_validator.is_valid(&carrier_request) {
        let detail = carrier_validator
            .iter_errors(&carrier_request)
            .next()
            .map(|error| format!("{error}"))
            .unwrap_or_else(|| "<no error reported>".to_owned());
        bail!("hard_erasure_receipt: standard carrier rejected by schema: {detail}");
    }
    let typed_package = serde_json::from_value::<
        arkret_models_collaboration::governance::erasure::ErasureReceiptSubmitRequestBody,
    >(carrier_request.clone())?;
    typed_package.package.validate_bindings()?;
    let mut tampered_package = typed_package.package.clone();
    tampered_package.receipt_digest = arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?;
    if tampered_package.validate_bindings().is_ok() {
        bail!("hard_erasure_receipt: tampered package digest was accepted");
    }
    assert_erasure_receipt_operations_registered()?;

    let tampered_stub = json!({
        "stub_schema": "ak.schema.erasure_verification_stub.v1",
        "trigger": {"kind": "event", "event_id": redaction_event_id},
        "subject": {"kind": "event", "subject_ref": "ak:event:AY-zO3iRTy2WzTOhIUEixuzlytHijHJIELYTSNj4ZNwH"},
        "scope": {"storage_boundary": "canonical_log_minimization"},
        "receipt_id": receipt_id,
        "completed_at": "2026-04-29T00:00:00.000Z",
        "event_digest": event_digest,
        "redaction_authorization_ref": redaction_event_id,
    });
    if verify_erasure_receipt_stub_digest(&receipt, &tampered_stub).is_ok() {
        bail!("hard_erasure_receipt: tampered retained_stub digest was accepted");
    }

    let mut without_proofs = receipt.clone();
    without_proofs["proofs"] = json!([]);
    if verify_erasure_receipt_stub_digest(&without_proofs, &stub).is_ok() {
        bail!("hard_erasure_receipt: receipt with empty proofs was accepted");
    }

    let mut blocked = receipt.clone();
    blocked["outcome"] = json!("blocked_by_legal_hold");
    if receipt_validator.is_valid(&blocked) {
        bail!(
            "hard_erasure_receipt: blocked_by_legal_hold receipt without legal_hold_ref was accepted (legal hold must be evidenced)"
        );
    }
    blocked["legal_hold_ref"] = json!("ak:policy:0196417d-8400-7000-8000-000000000000");
    if !receipt_validator.is_valid(&blocked) {
        let detail = receipt_validator
            .iter_errors(&blocked)
            .next()
            .map(|error| format!("{error}"))
            .unwrap_or_else(|| "<no error reported>".to_string());
        bail!(
            "hard_erasure_receipt: blocked_by_legal_hold receipt with legal_hold_ref rejected: {detail}"
        );
    }

    Ok(())
}

fn assert_erasure_receipt_operations_registered() -> Result<()> {
    let registry = load_artifact_json("registry/operation-registry.json")?;
    let operations = registry
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation registry missing operations[]"))?;
    for (operation_id, http, response_ref) in [
        (
            "ak.peer.erasure_receipt.command.submit",
            "POST /_arkret/peer/erasure-receipts",
            "schemas/erasure-receipt-operations.schema.json#/$defs/erasure_receipt_submit_outcome",
        ),
        (
            "ak.peer.erasure_receipt.resource.get",
            "GET /_arkret/peer/erasure-receipts/{receipt_id}",
            "schemas/erasure-receipt-operations.schema.json#/$defs/erasure_receipt_resource",
        ),
    ] {
        let operation = operations
            .iter()
            .find(|row| row.get("operation_id").and_then(Value::as_str) == Some(operation_id))
            .ok_or_else(|| anyhow!("operation registry missing {operation_id}"))?;
        if operation.get("http").and_then(Value::as_str) != Some(http)
            || operation.get("response_schema_ref").and_then(Value::as_str) != Some(response_ref)
        {
            bail!("standard erasure receipt operation binding drifted for {operation_id}");
        }
    }
    Ok(())
}

fn verify_erasure_receipt_stub_digest(receipt: &Value, retained_stub: &Value) -> Result<()> {
    let digest = receipt
        .get("retained_stub_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("erasure receipt missing retained_stub_digest"))?;
    let proofs = receipt
        .get("proofs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("erasure receipt missing proofs"))?;
    if proofs.is_empty() {
        bail!("erasure receipt proofs must not be empty");
    }
    let recomputed = arkret_canonical::canonical_sha256(retained_stub)
        .map_err(|err| anyhow!("erasure receipt retained_stub canonicalization failed: {err}"))?;
    if recomputed != digest {
        bail!("erasure_receipt_stub_digest_mismatch");
    }
    Ok(())
}

fn sample_event() -> Value {
    sample_event_with_id("ak:event:AagGd6PB1SqZp__DzubMh3BTpUU-oWosY3NoR_k38pxq")
}

fn sample_event_with_id(event_id: &str) -> Value {
    json!({
        "event_id": event_id,
        "created_at": "2026-04-29T00:00:00.000Z",
        "actor_id": "ak:did_core:web:alice.example",
        "kind": "ak.message.create",
        "content": {"kind": "ak.content.text", "body": "secret"},
        "proofs": [{"fixture_marker": "not_covered"}]
    })
}

fn redact_event(target: &Value, redaction_event_id: &str) -> Result<Value> {
    let target = target
        .as_object()
        .ok_or_else(|| anyhow!("target event must be an object"))?;
    let event_id = target
        .get("event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("target event missing event_id"))?;
    let created_at = target
        .get("created_at")
        .cloned()
        .ok_or_else(|| anyhow!("target event missing created_at"))?;
    let actor_id = target
        .get("actor_id")
        .cloned()
        .ok_or_else(|| anyhow!("target event missing actor_id"))?;
    Ok(json!({
        "event_id": event_id,
        "created_at": created_at,
        "actor_id": actor_id,
        "redaction_target": event_id,
        "redacted_because": redaction_event_id
    }))
}

fn audit_tombstone(redacted: &Value) -> Result<Value> {
    let object = redacted
        .as_object()
        .ok_or_else(|| anyhow!("redacted event must be an object"))?;
    Ok(json!({
        "event_id": object["event_id"],
        "actor_id": object["actor_id"],
        "created_at": object["created_at"],
        "redaction_target": object["redaction_target"],
        "redaction": true
    }))
}

#[derive(Default)]
struct RedactionTracker {
    pending: HashMap<String, String>,
}

#[derive(Debug, Eq, PartialEq)]
enum RedactionState {
    Pending,
}

impl RedactionTracker {
    fn push_redaction(
        &mut self,
        target_event_id: &str,
        redaction_event_id: &str,
    ) -> RedactionState {
        self.pending
            .insert(target_event_id.to_owned(), redaction_event_id.to_owned());
        RedactionState::Pending
    }

    fn materialize_target(&mut self, target: &Value) -> Result<Value> {
        let target_id = target["event_id"]
            .as_str()
            .ok_or_else(|| anyhow!("target event missing event_id"))?;
        if let Some(redaction_event_id) = self.pending.remove(target_id) {
            redact_event(target, &redaction_event_id)
        } else {
            Ok(target.clone())
        }
    }
}
