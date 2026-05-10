use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{RedactionFixture, load_fixture};
use crate::transcripts::record_vector_event;

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
                    redact_event(&target, "cx:event:01970e58-0004-7000-8000-000000000001")?;
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
                    "cx:event:01970e58-0004-7000-8000-000000000002",
                    "cx:event:01970e58-0004-7000-8000-000000000001",
                );
                if state != RedactionState::Pending {
                    bail!("redaction fixture {} expected pending state", case.name);
                }
                record_vector_event(
                    "redaction.dangling_redaction",
                    &json!({
                        "target_event_id": "cx:event:01970e58-0004-7000-8000-000000000002",
                        "redaction_event_id": "cx:event:01970e58-0004-7000-8000-000000000001",
                    }),
                    &json!({"state": "Pending"}),
                    &json!({"state": format!("{state:?}")}),
                );
            }
            "late_target_event" => {
                let mut tracker = RedactionTracker::default();
                tracker.push_redaction(
                    "cx:event:01970e58-0004-7000-8000-000000000003",
                    "cx:event:01970e58-0004-7000-8000-000000000001",
                );
                let materialized = tracker.materialize_target(&sample_event_with_id(
                    "cx:event:01970e58-0004-7000-8000-000000000003",
                ))?;
                if materialized.get("content").is_some() {
                    bail!(
                        "redaction fixture {} failed to materialize as redacted",
                        case.name
                    );
                }
                if materialized["redacted_because"]
                    != "cx:event:01970e58-0004-7000-8000-000000000001"
                {
                    bail!("redaction fixture {} lost redaction reference", case.name);
                }
                record_vector_event(
                    "redaction.late_target_event",
                    &json!({
                        "target_event_id": "cx:event:01970e58-0004-7000-8000-000000000003",
                        "redaction_event_id": "cx:event:01970e58-0004-7000-8000-000000000001",
                    }),
                    &json!({
                        "content_present": false,
                        "redacted_because": "cx:event:01970e58-0004-7000-8000-000000000001",
                    }),
                    &json!({
                        "materialized": materialized.clone(),
                        "redacted_because": materialized["redacted_because"].clone(),
                    }),
                );
            }
            "audit_visibility" => {
                let redacted =
                    redact_event(&target, "cx:event:01970e58-0004-7000-8000-000000000001")?;
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
                    redact_event(&target, "cx:event:01970e58-0004-7000-8000-000000000001")?;
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
            _ => bail!("unknown redaction fixture case {}", case.name),
        }
    }

    Ok(())
}

fn sample_event() -> Value {
    sample_event_with_id("cx:event:01970e58-0004-7000-8000-000000000004")
}

fn sample_event_with_id(event_id: &str) -> Value {
    json!({
        "event_id": event_id,
        "created_at": "2026-04-29T00:00:00Z",
        "actor_id": "did:web:alice.example",
        "kind": "cx.message.create",
        "content": {"body": "secret"},
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

    #[allow(dead_code)]
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
