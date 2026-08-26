use anyhow::Result;
use arkret_identifiers::Hash;
use arkret_wire::{Audience, ProducerEventProof};
use chrono::{DateTime, Utc};
use serde_json::Value;

pub(crate) fn candidate_payload_proof(
    digest: &str,
    audience: &str,
    jws: &str,
) -> Result<ProducerEventProof> {
    Ok(ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: crate::fixture_did_url("did:web:principal.acme.example#key-1"),
        event_digest: Hash::new(digest.to_owned())?,
        signer_resolution_evidence_ref: None,
        signer_resolution_evidence_digest: None,
        created_at: DateTime::parse_from_rfc3339("2026-05-19T00:00:00.000Z")?.with_timezone(&Utc),
        domain: None,
        audience: Some(Audience::Single(audience.to_owned())),
        proof_purpose: None,
        jws: jws.to_owned(),
    })
}

pub(crate) fn submitted_event_id(response: &Value) -> Option<&str> {
    response
        .get("accepted")
        .and_then(Value::as_array)
        .and_then(|accepted| accepted.first())
        .and_then(Value::as_str)
        .or_else(|| {
            response
                .get("duplicate")
                .and_then(Value::as_array)
                .and_then(|duplicate| duplicate.first())
                .and_then(Value::as_str)
        })
}
