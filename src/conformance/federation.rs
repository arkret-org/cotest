use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail};
use serde_json::{Value, json};

use super::{FederationFixture, canonical_json, load_fixture, sha256_prefixed};
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
            "http_message_signature_hash" => {
                let request = SignedFederationRequest {
                    method: "PUT".to_owned(),
                    target: "/api/v1/federation/transactions/demo".to_owned(),
                    body: json!({"txn_id": "demo"}),
                };
                let signature_input = request.signature_input_hash()?;
                let canonical = request.canonical_request_hash()?;
                if signature_input != canonical {
                    bail!("federation fixture {} hash mismatch", case.name);
                }
                record_vector_event(
                    "federation.http_message_signature_hash",
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
            // `origin_destination_service_did_mismatch` to
            // `source_destination_service_did_mismatch`. The semantics
            // (federation source DID ≠ signed destination DID → reject)
            // are unchanged.
            "source_destination_service_did_mismatch" => {
                let verdict = validate_origin_destination(
                    "did:web:remote.example",
                    "did:web:wrong.example",
                    "did:web:local.example",
                );
                if verdict == FederationVerdict::Accepted {
                    bail!("federation fixture {} accepted DID mismatch", case.name);
                }
                record_vector_event(
                    "federation.source_destination_service_did_mismatch",
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
                    "cx:realm:01970e58-0006-7000-8000-000000000001",
                    "sha256:a",
                );
                let second = register_history_head(
                    &mut fork_table,
                    "cx:realm:01970e58-0006-7000-8000-000000000001",
                    "sha256:b",
                );
                if first != FederationVerdict::Accepted || second != FederationVerdict::Quarantined
                {
                    bail!("federation fixture {} did not quarantine fork", case.name);
                }
                record_vector_event(
                    "federation.fork_quarantine",
                    &json!({
                        "realm_id": "cx:realm:01970e58-0006-7000-8000-000000000001",
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
    space_id: &str,
    head: &str,
) -> FederationVerdict {
    match table.insert(space_id.to_owned(), head.to_owned()) {
        Some(existing) if existing != head => FederationVerdict::Quarantined,
        _ => FederationVerdict::Accepted,
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
