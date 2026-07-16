use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::schema_validation_fixture::SchemaEnv;
use super::{RedactionFixture, load_fixture};
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
                let redacted =
                    redact_event(&target, "ak:event:01970e58-0004-7000-8000-000000000001")?;
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
                    "ak:event:01970e58-0004-7000-8000-000000000002",
                    "ak:event:01970e58-0004-7000-8000-000000000001",
                );
                if state != RedactionState::Pending {
                    bail!("redaction fixture {} expected pending state", case.name);
                }
                record_vector_event(
                    "redaction.dangling_redaction",
                    &json!({
                        "target_event_id": "ak:event:01970e58-0004-7000-8000-000000000002",
                        "redaction_event_id": "ak:event:01970e58-0004-7000-8000-000000000001",
                    }),
                    &json!({"state": "Pending"}),
                    &json!({"state": format!("{state:?}")}),
                );
            }
            "late_target_event" => {
                let mut tracker = RedactionTracker::default();
                tracker.push_redaction(
                    "ak:event:01970e58-0004-7000-8000-000000000003",
                    "ak:event:01970e58-0004-7000-8000-000000000001",
                );
                let materialized = tracker.materialize_target(&sample_event_with_id(
                    "ak:event:01970e58-0004-7000-8000-000000000003",
                ))?;
                if materialized.get("content").is_some() {
                    bail!(
                        "redaction fixture {} failed to materialize as redacted",
                        case.name
                    );
                }
                if materialized["redacted_because"]
                    != "ak:event:01970e58-0004-7000-8000-000000000001"
                {
                    bail!("redaction fixture {} lost redaction reference", case.name);
                }
                record_vector_event(
                    "redaction.late_target_event",
                    &json!({
                        "target_event_id": "ak:event:01970e58-0004-7000-8000-000000000003",
                        "redaction_event_id": "ak:event:01970e58-0004-7000-8000-000000000001",
                    }),
                    &json!({
                        "content_present": false,
                        "redacted_because": "ak:event:01970e58-0004-7000-8000-000000000001",
                    }),
                    &json!({
                        "materialized": materialized.clone(),
                        "redacted_because": materialized["redacted_because"].clone(),
                    }),
                );
            }
            "audit_visibility" => {
                let redacted =
                    redact_event(&target, "ak:event:01970e58-0004-7000-8000-000000000001")?;
                let audit = audit_tombstone(&redacted)?;
                if audit.get("content").is_some() {
                    bail!(
                        "redaction fixture {} leaked content to audit view",
                        case.name
                    );
                }
                if audit["redacts"] != target["event_id"] {
                    bail!("redaction fixture {} lost target reference", case.name);
                }
                record_vector_event(
                    "redaction.audit_visibility",
                    &json!({"target": target.clone()}),
                    &json!({
                        "audit_content_present": false,
                        "redacts": target["event_id"].clone(),
                    }),
                    &json!({
                        "audit": audit.clone(),
                        "redacts": audit["redacts"].clone(),
                    }),
                );
            }
            "snapshot_pruning_stub" => {
                let redacted =
                    redact_event(&target, "ak:event:01970e58-0004-7000-8000-000000000001")?;
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
                if redacted["redacts"] != target["event_id"] {
                    bail!("redaction fixture {} lost redaction reference", case.name);
                }
                record_vector_event(
                    "redaction.snapshot_pruning_stub",
                    &json!({"target": target.clone()}),
                    &json!({
                        "content_present": false,
                        "proofs_present": false,
                        "redacts": target["event_id"].clone(),
                    }),
                    &json!({
                        "redacted": redacted.clone(),
                        "content_present": redacted.get("content").is_some(),
                        "proofs_present": redacted.get("proofs").is_some(),
                        "redacts": redacted["redacts"].clone(),
                    }),
                );
            }
            "space_target_ref_schema" => {
                assert_space_target_ref_schema()?;
                record_vector_event(
                    "redaction.space_target_ref_schema",
                    &json!({
                        "target_ref": "ak:space:019640b6-8000-7000-8000-000000000000",
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
/// The redaction object-lifecycle payload schema MUST accept a `ak:space:*`
/// `target_ref` and MUST reject a malformed space ref, so a Space cleanup is
/// never downgraded to an implementation-private extension by a schema gap.
fn assert_space_target_ref_schema() -> Result<()> {
    let env = SchemaEnv::load()?;
    let schema_ref = "schemas/event-payload.schema.json#/$defs/object_lifecycle_payload";
    let validator = env.compile(schema_ref)?;

    let accepted = json!({
        "target_ref": "ak:space:019640b6-8000-7000-8000-000000000000",
        "reason": "privacy_cleanup",
    });
    if !validator.is_valid(&accepted) {
        let detail = validator
            .iter_errors(&accepted)
            .next()
            .map(|error| format!("{error}"))
            .unwrap_or_else(|| "<no error reported>".to_string());
        bail!(
            "space_target_ref_schema: object_lifecycle_payload rejected a ak:space target_ref: {detail}"
        );
    }

    let malformed = json!({
        "target_ref": "ak:space:not-a-uuid",
        "reason": "privacy_cleanup",
    });
    if validator.is_valid(&malformed) {
        bail!(
            "space_target_ref_schema: object_lifecycle_payload accepted a malformed ak:space target_ref"
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
/// After message -> policy quarantine -> redaction, the projection MUST strip
/// the redacted content while retaining audit evidence, MUST keep the timeline
/// position (no physical delete), and MUST retain the quarantine decision and
/// its `event_id` fingerprint mapping (quarantine is a display constraint, not
/// a delete).
fn assert_policy_scope_projection() -> Result<PolicyScopeOutcome> {
    let message_id = "ak:event:0196417d-8400-7000-8000-000000000000";
    let policy_id = "ak:event:0196417d-8980-7000-8000-000000000000";
    let redaction_id = "ak:event:0196417d-8f00-7000-8000-000000000000";

    let timeline = json!([
        {
            "event_id": message_id,
            "kind": "ak.message.create",
            "content": {"kind": "ak.content.text", "body": "bad link: spam.example/phish"},
        },
        {
            "event_id": policy_id,
            "kind": "ak.policy.action",
            "actor_id": "did:web:policy-bot.example.com",
            "payload": {"target_id": message_id, "policy_scope": "public", "decision": "quarantine"},
        },
        {
            "event_id": redaction_id,
            "kind": "ak.redaction",
            "actor_id": "did:web:policy-admin.example",
            "payload": {"redacts": message_id, "reason_code": "policy_recall"},
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
    if message["event_id"] != json!(message_id) {
        bail!("policy_scope: redacted event lost its timeline position");
    }
    if message.get("content").is_some() {
        bail!("policy_scope: redacted content is still visible in the projection");
    }
    if message["redacts"] != json!(message_id) {
        bail!("policy_scope: stripped audit evidence (redacts reference) missing");
    }

    let policy = &entries[1];
    if policy["payload"]["decision"] != json!("quarantine") {
        bail!("policy_scope: quarantine decision was lost or downgraded to delete");
    }
    if policy["payload"]["target_id"] != json!(message_id) {
        bail!("policy_scope: quarantine event_id fingerprint mapping was lost");
    }

    Ok(PolicyScopeOutcome {
        input: timeline,
        expected: json!({
            "timeline_len": 3,
            "redacted_content_present": false,
            "redacts": message_id,
            "quarantine_decision": "quarantine",
            "quarantine_target_id": message_id,
        }),
        actual: json!({
            "timeline_len": entries.len(),
            "redacted_content_present": message.get("content").is_some(),
            "redacts": message["redacts"].clone(),
            "quarantine_decision": policy["payload"]["decision"].clone(),
            "quarantine_target_id": policy["payload"]["target_id"].clone(),
        }),
    })
}

fn project_policy_scope_timeline(timeline: &Value) -> Result<Value> {
    let entries = timeline
        .as_array()
        .ok_or_else(|| anyhow!("policy_scope timeline must be an array"))?;

    let mut redactions: HashMap<String, String> = HashMap::new();
    for entry in entries {
        if entry["kind"] == json!("ak.redaction") {
            let target = entry["payload"]["redacts"]
                .as_str()
                .ok_or_else(|| anyhow!("redaction event missing payload.redacts"))?;
            let redaction_event_id = entry["event_id"]
                .as_str()
                .ok_or_else(|| anyhow!("redaction event missing event_id"))?;
            redactions.insert(target.to_owned(), redaction_event_id.to_owned());
        }
    }

    let mut projected = Vec::with_capacity(entries.len());
    for entry in entries {
        let event_id = entry["event_id"]
            .as_str()
            .ok_or_else(|| anyhow!("timeline event missing event_id"))?;
        match redactions.get(event_id) {
            Some(redaction_event_id) if entry["kind"] != json!("ak.redaction") => {
                projected.push(json!({
                    "event_id": event_id,
                    "kind": entry["kind"].clone(),
                    "redacts": event_id,
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
    let stub_validator =
        env.compile("schemas/erasure-receipt.schema.json#/$defs/verification_stub")?;

    let original_event_id = "ak:event:01970e58-0004-7000-8000-000000000004";
    let redaction_event_id = "ak:event:01970e58-0004-7000-8000-000000000001";
    let receipt_id = "ak:receipt:01970e58-0004-7000-8000-000000000010";
    let event_digest = format!("sha256:{DIGEST64}");

    let stub = json!({
        "stub_schema": "ak.schema.erasure_verification_stub.v1",
        "subject": {"kind": "event", "subject_ref": original_event_id},
        "scope": {"storage_boundary": "canonical_log_minimization"},
        "receipt_id": receipt_id,
        "completed_at": "2026-04-29T00:00:00Z",
        "event_digest": event_digest,
        "redaction_authorization_ref": redaction_event_id,
    });
    let digest = arkret_core::canonical::canonical_sha256(&stub)
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

    let receipt = json!({
        "schema": "ak.schema.erasure_receipt.v1",
        "receipt_id": receipt_id,
        "issuer": "did:web:erasure.example.com",
        "subject": {"kind": "event", "subject_ref": original_event_id},
        "scope": {"storage_boundary": "canonical_log_minimization"},
        "outcome": "completed",
        "erased_classes": ["canonical_payload_bytes", "derived_plaintext"],
        "retained_stub_digest": digest,
        "retained_stub": stub,
        "completed_at": "2026-04-29T00:00:00Z",
        "proofs": [{
            "verification_method": "did:web:erasure.example.com#erasure-key-1",
            "payload_digest": digest,
            "signature": "z3erasurereceiptsignatureplaceholder",
        }],
    });
    if !receipt_validator.is_valid(&receipt) {
        let detail = receipt_validator
            .iter_errors(&receipt)
            .next()
            .map(|error| format!("{error}"))
            .unwrap_or_else(|| "<no error reported>".to_string());
        bail!("hard_erasure_receipt: completed receipt rejected by schema: {detail}");
    }
    verify_erasure_receipt_stub_digest(&receipt, &stub)?;

    let tampered_stub = json!({
        "stub_schema": "ak.schema.erasure_verification_stub.v1",
        "subject": {"kind": "event", "subject_ref": "ak:event:01970e58-0004-7000-8000-0000000000ff"},
        "scope": {"storage_boundary": "canonical_log_minimization"},
        "receipt_id": receipt_id,
        "completed_at": "2026-04-29T00:00:00Z",
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
    let recomputed = arkret_core::canonical::canonical_sha256(retained_stub)
        .map_err(|err| anyhow!("erasure receipt retained_stub canonicalization failed: {err}"))?;
    if recomputed != digest {
        bail!("erasure_receipt_stub_digest_mismatch");
    }
    Ok(())
}

fn sample_event() -> Value {
    sample_event_with_id("ak:event:01970e58-0004-7000-8000-000000000004")
}

fn sample_event_with_id(event_id: &str) -> Value {
    json!({
        "event_id": event_id,
        "created_at": "2026-04-29T00:00:00Z",
        "actor_id": "did:web:alice.example",
        "kind": "ak.message.create",
        "content": {"kind": "ak.content.text", "body": "secret"},
        "proofs": [{"alg": "none"}]
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
        "redacts": event_id,
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
        "redacts": object["redacts"],
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
