//! Exact known-answer runners for the three DID verified-binding digests.

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::load_fixture_value;

pub const VECTOR_ID_DID_BINDING_DOCUMENT_DIGEST_KAT: &str =
    "ak.vector.did_binding.document_digest_kat.v1";
pub const VECTOR_ID_DID_BINDING_EVIDENCE_RECEIPT_KAT: &str =
    "ak.vector.did_binding.evidence_receipt_kat.v1";
pub const VECTOR_ID_DID_BINDING_POLICY_SNAPSHOT_KAT: &str =
    "ak.vector.did_binding.policy_snapshot_kat.v1";
pub const ALL_DID_BINDING_DIGEST_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_DID_BINDING_DOCUMENT_DIGEST_KAT,
    VECTOR_ID_DID_BINDING_EVIDENCE_RECEIPT_KAT,
    VECTOR_ID_DID_BINDING_POLICY_SNAPSHOT_KAT,
];

const FIXTURE: &str = "did-binding-digest-fixture.json";

fn run_vector(vector_id: &str) -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    if fixture.get("suite").and_then(Value::as_str) != Some("did_binding_digests") {
        bail!("DID binding digest fixture suite drifted");
    }
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("DID binding digest fixture missing cases[]"))?;
    let mut matched = 0usize;
    for case in cases
        .iter()
        .filter(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
    {
        matched += 1;
        let input = case
            .get("input")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("{vector_id} case input must be an object"))?;
        if input.len() != 1 {
            bail!("{vector_id} KAT input must contain exactly one canonical object");
        }
        let value = input.values().next().expect("one KAT input");
        let expected = case
            .get("expected")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("{vector_id} case missing expected object"))?;
        let expected_digest = expected
            .iter()
            .find(|(key, _)| key.ends_with("_digest"))
            .and_then(|(_, value)| value.as_str())
            .ok_or_else(|| anyhow!("{vector_id} case missing expected digest"))?;
        let actual = arkret_canonical::canonical_sha256(value)?;
        if actual != expected_digest {
            bail!("{vector_id} digest KAT drifted: expected {expected_digest}, got {actual}");
        }
        if let Some(expected_jcs) = expected.get("jcs_utf8").and_then(Value::as_str) {
            let bytes = arkret_canonical::canonical_json_bytes(value)?;
            if std::str::from_utf8(&bytes)? != expected_jcs {
                bail!("{vector_id} canonical JSON KAT drifted");
            }
        }
        if case
            .get("assertions")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            bail!("{vector_id} KAT case has no asserted contract");
        }
    }
    if matched == 0 {
        bail!("DID binding digest fixture has no case for {vector_id}");
    }
    Ok(())
}

pub fn run_did_binding_document_digest_kat_vector() -> Result<()> {
    run_vector(VECTOR_ID_DID_BINDING_DOCUMENT_DIGEST_KAT)
}

pub fn run_did_binding_evidence_receipt_kat_vector() -> Result<()> {
    run_vector(VECTOR_ID_DID_BINDING_EVIDENCE_RECEIPT_KAT)
}

pub fn run_did_binding_policy_snapshot_kat_vector() -> Result<()> {
    run_vector(VECTOR_ID_DID_BINDING_POLICY_SNAPSHOT_KAT)
}

pub fn run_did_binding_digest_kat_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("DID binding digest fixture missing covers_vectors[]"))?;
    for vector_id in ALL_DID_BINDING_DIGEST_VECTOR_IDS {
        if !covers
            .iter()
            .any(|value| value.as_str() == Some(*vector_id))
        {
            bail!("DID binding digest fixture missing {vector_id}");
        }
    }
    run_did_binding_document_digest_kat_vector()?;
    run_did_binding_evidence_receipt_kat_vector()?;
    run_did_binding_policy_snapshot_kat_vector()
}

#[cfg(test)]
mod tests {
    #[test]
    fn did_binding_digest_kats_run_clean() {
        super::run_did_binding_digest_kat_suite().unwrap();
    }
}
