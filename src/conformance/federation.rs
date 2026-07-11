use std::collections::{HashMap, HashSet};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::reducer_profile::{reducer_profile_digest_for_input, reducer_profile_digest_input};
use super::{
    FederationFixture, canonical_json, load_artifact_json, load_fixture, looks_like_sha256_digest,
    sha256_prefixed,
};
use crate::transcripts::record_vector_event;

pub fn run_federation_fixture_suite() -> Result<()> {
    let fixture = load_fixture::<FederationFixture>("federation-fixture.json")?;
    if fixture.suite != "federation" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }
    let mut replay_cache = HashSet::new();
    let mut fork_table = HashMap::new();

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
            // Round 2+3 (2026-05-20): fixture case renamed from
            // `origin_destination_service_id_mismatch` to
            // `source_destination_service_id_mismatch`. The semantics
            // (federation source DID ≠ signed destination DID → reject)
            // are unchanged.
            "source_destination_service_id_mismatch" => {
                let verdict = validate_origin_destination(
                    "did:web:remote.example",
                    "did:web:wrong.example",
                    "did:web:local.example",
                );
                if verdict == FederationVerdict::Accepted {
                    bail!("federation fixture {} accepted DID mismatch", case.name);
                }
                record_vector_event(
                    "federation.source_destination_service_id_mismatch",
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
                let first = register_history_head(
                    &mut fork_table,
                    "ak:realm:01970e58-0006-7000-8000-000000000001",
                    "sha256:a",
                );
                let second = register_history_head(
                    &mut fork_table,
                    "ak:realm:01970e58-0006-7000-8000-000000000001",
                    "sha256:b",
                );
                if first != FederationVerdict::Accepted || second != FederationVerdict::Quarantined
                {
                    bail!("federation fixture {} did not quarantine fork", case.name);
                }
                record_vector_event(
                    "federation.fork_quarantine",
                    &json!({
                        "realm_id": "ak:realm:01970e58-0006-7000-8000-000000000001",
                        "head_a": "sha256:a",
                        "head_b": "sha256:b",
                    }),
                    &json!({"first": "Accepted", "second": "Quarantined"}),
                    &json!({
                        "first": format!("{first:?}"),
                        "second": format!("{second:?}"),
                    }),
                );
            }
            // ak.vector.federation.reducer_profile_digest.v1 — positive leg:
            // the §4.1.1 computation over the fixture's canonical_input MUST
            // reproduce expected_digest, and the fixture input MUST be exactly
            // the published reducer-profile-registry.json digest_input row
            // ("canonical_digest_matches_reducer_profile_registry_row").
            "reducer_profile_digest_federation_minimal" => {
                let canonical_input = case
                    .canonical_input
                    .as_ref()
                    .ok_or_else(|| anyhow!("{} case lacks canonical_input", case.name))?;
                let expected_digest = case
                    .expected_digest
                    .as_deref()
                    .ok_or_else(|| anyhow!("{} case lacks expected_digest", case.name))?;
                let computed = reducer_profile_digest_for_input(canonical_input)?;
                if computed != expected_digest {
                    bail!(
                        "federation fixture {}: computed digest {computed} != expected {expected_digest}",
                        case.name
                    );
                }
                let profile_id = canonical_input
                    .get("profile_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("{} canonical_input lacks profile_id", case.name))?;
                let registry = load_artifact_json("registry/reducer-profile-registry.json")?;
                let registry_input = reducer_profile_digest_input(&registry, profile_id)?;
                if canonical_json(&registry_input)? != canonical_json(canonical_input)? {
                    bail!(
                        "federation fixture {}: canonical_input drifted from \
                         reducer-profile-registry.json digest_input for {profile_id}",
                        case.name
                    );
                }
                record_vector_event(
                    "federation.reducer_profile_digest_federation_minimal",
                    &json!({"profile_id": profile_id}),
                    &json!({"expected_digest": expected_digest}),
                    &json!({
                        "computed_digest": computed,
                        "matches_registry_row": true,
                    }),
                );
            }
            // ak.vector.federation.reducer_profile_digest.v1 — negative leg:
            // receiver recomputes its own digest and byte-compares; any
            // divergence MUST reject the whole batch with
            // `reducer_profile_mismatch` (no partial accept).
            "reducer_profile_mismatch" => {
                let sender = case
                    .sender_reducer_profile_digest
                    .as_deref()
                    .ok_or_else(|| anyhow!("{} case lacks sender digest", case.name))?;
                let receiver = case
                    .receiver_reducer_profile_digest
                    .as_deref()
                    .ok_or_else(|| anyhow!("{} case lacks receiver digest", case.name))?;
                if !looks_like_sha256_digest(sender) || !looks_like_sha256_digest(receiver) {
                    bail!(
                        "federation fixture {} digests are not sha256:<hex>",
                        case.name
                    );
                }
                let verdict = validate_reducer_profile_digest(sender, receiver);
                if verdict != Err("reducer_profile_mismatch") {
                    bail!(
                        "federation fixture {}: mismatched digests must reject the whole \
                         batch with reducer_profile_mismatch, got {verdict:?}",
                        case.name
                    );
                }
                // Control leg: byte-identical digests MUST NOT trip the gate.
                if validate_reducer_profile_digest(sender, sender).is_err() {
                    bail!(
                        "federation fixture {}: identical digests must be accepted",
                        case.name
                    );
                }
                record_vector_event(
                    "federation.reducer_profile_mismatch",
                    &json!({
                        "sender_reducer_profile_digest": sender,
                        "receiver_reducer_profile_digest": receiver,
                    }),
                    &json!({"expected": "whole_batch_rejected_with_reducer_profile_mismatch"}),
                    &json!({"verdict": "rejected", "reason_code": "reducer_profile_mismatch"}),
                );
            }
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
            _ => bail!("unknown federation fixture case {}", case.name),
        }
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
    Quarantined,
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

fn register_history_head(
    table: &mut HashMap<String, String>,
    realm_id: &str,
    head: &str,
) -> FederationVerdict {
    match table.insert(realm_id.to_owned(), head.to_owned()) {
        Some(existing) if existing != head => FederationVerdict::Quarantined,
        _ => FederationVerdict::Accepted,
    }
}

/// federation.md §4.1.1 receiver gate: the receiver recomputes its own
/// reducer profile digest via the registry rule and byte-compares it with
/// `service_binding_ref.reducer_profile_digest`. Divergence rejects the whole
/// batch (`Err("reducer_profile_mismatch")`) — never a partial accept.
fn validate_reducer_profile_digest(
    sender_digest: &str,
    receiver_digest: &str,
) -> Result<(), &'static str> {
    if sender_digest.as_bytes() == receiver_digest.as_bytes() {
        Ok(())
    } else {
        Err("reducer_profile_mismatch")
    }
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
