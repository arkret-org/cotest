//! Exact reviewer authority-pair conformance.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};

use super::load_fixture_value;

const FIXTURE: &str = "reviewer-authority-pair-fixture.json";
const VECTOR: &str = "ak.vector.authz.reviewer_authority_pair.v1";
const REQUIRED_CASES: [&str; 5] = [
    "effective_grants_isolated_by_exact_authority_pair",
    "missing_or_wrong_principal_server_selector_fails_closed",
    "review_receipt_closes_grant_receipt_and_signer_pair",
    "cross_pair_replay_and_signer_substitution_fail_closed",
    "quorum_deduplicates_same_actor_across_principal_servers",
];

pub fn run_reviewer_authority_pair_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    if fixture["suite"] != "reviewer_authority_pair"
        || fixture["runner"]["kind"] != "named_suite"
        || fixture["runner"]["entrypoint"] != "ak.suite.authz.reviewer_authority_pair.v1"
        || fixture["covers_vectors"] != serde_json::json!([VECTOR])
    {
        bail!("reviewer authority-pair fixture identity drifted");
    }

    let transcript = &fixture["proof_transcript"];
    if transcript["context"] != "ak.join-application-review-receipt-proof-v1"
        || transcript["ordered_fields"]
            != serde_json::json!([
                "receipt_digest",
                "realm_id",
                "application_ref",
                "application_revision_digest",
                "actor_id",
                "principal_server_id",
                "verification_method",
                "created_at"
            ])
        || transcript["receipt_mapping"]["principal_server_id"] != "reviewer_principal_server_id"
    {
        bail!("review receipt proof transcript lost its authority-pair binding");
    }

    let cases = fixture["semantic_cases"]
        .as_array()
        .context("reviewer authority-pair semantic_cases")?;
    let names = cases
        .iter()
        .map(|case| {
            case["name"]
                .as_str()
                .context("reviewer authority-pair semantic case name")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if names != BTreeSet::from(REQUIRED_CASES) {
        bail!("reviewer authority-pair fixture is not the closed five-case set");
    }
    if cases.iter().any(|case| {
        case["invariants"]
            .as_array()
            .is_none_or(|invariants| invariants.is_empty())
    }) {
        bail!("every reviewer authority-pair case must carry invariants");
    }
    Ok(())
}
