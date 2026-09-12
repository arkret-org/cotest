//! Near-current MLS governance-frontier conformance vectors.

use anyhow::{Context, Result, anyhow, bail};
use arkret_models_crypto::mls_governance_proof::{
    MlsGovernanceProofBundle, MlsGovernanceProofRequestBody,
};
use serde_json::Value;

use crate::conformance::{load_fixture_value, validate_profile};

const FIXTURE: &str = "mls-governance-proof-fixture.json";
const PROFILE: &str = "ak.profile.mls_governance_binding.full.v1";

/// Replays the canonical near-current fixture through the public DTO
/// validators. Full state replay is covered by the SDK verifier tests; this
/// cross-repository runner pins the exact query/outcome/page-digest contract.
pub fn run_mls_security_frontier_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    validate_profile(&fixture, PROFILE)?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("MLS governance proof fixture missing cases[]"))?;
    if cases.is_empty() {
        bail!("MLS governance proof fixture has no positive cases");
    }

    let mut saw_genesis = false;
    let mut saw_successor = false;
    let mut saw_multi_leaf_frontier = false;
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("MLS governance proof case has no name"))?;
        let request: MlsGovernanceProofRequestBody = serde_json::from_value(
            case.get("query")
                .cloned()
                .ok_or_else(|| anyhow!("MLS governance proof case {name} has no query"))?,
        )
        .with_context(|| format!("decoding MLS governance proof query {name}"))?;
        let outcome: MlsGovernanceProofBundle = serde_json::from_value(
            case.get("outcome")
                .cloned()
                .ok_or_else(|| anyhow!("MLS governance proof case {name} has no outcome"))?,
        )
        .with_context(|| format!("decoding MLS governance proof outcome {name}"))?;
        outcome
            .validate_for_request(&request)
            .with_context(|| format!("validating MLS governance proof outcome {name}"))?;
        if outcome.page_digest != outcome.recompute_page_digest()? {
            bail!("MLS governance proof case {name} has a stale page digest");
        }
        saw_genesis |= request.previous_epoch == 0 && request.next_epoch == 0;
        saw_successor |= request.previous_epoch.checked_add(1) == Some(request.next_epoch);
        saw_multi_leaf_frontier |= request.proof_target_basis.leaves.len() > 1;
    }
    if !(saw_genesis && saw_successor && saw_multi_leaf_frontier) {
        bail!(
            "MLS governance proof positives must cover genesis, successor and multi-leaf targets"
        );
    }
    Ok(())
}
