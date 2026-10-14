//! Canonical longevity reports completion only after every live obligation.

use super::*;

pub async fn run_agent_longevity_production() -> Result<crate::conformance::SuiteExecutionResult> {
    run_agent_same_key_renewal_boundary().await?;
    run_agent_capability_longevity_live().await?;
    run_agent_longevity_session_boundary().await?;
    let root = crate::scenarios::_helpers::external_binary::workspace_root()
        .context("binding source workspace")?;
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(
        root.join("arkret-spec/spec/v1/artifacts/fixtures/agent-vectors-fixture.json"),
    )?)?;
    let declared = fixture["cases"]
        .as_array()
        .context("canonical Agent cases")?
        .iter()
        .filter(|case| case["name"] == "agent_longevity_no_expiry")
        .collect::<Vec<_>>();
    let [case] = declared.as_slice() else {
        bail!("longevity is not uniquely declared");
    };
    let expected = [
        "agent key authorization without expires_at is accepted and remains valid until revoked",
        "same-key re-authorization atomically removes all observed authorization dots and adds one replacement dot",
        "same-key re-authorizations are commit-ordered: at most one replacement based on the same old revision succeeds, stale basis is rejected, and concurrent permission heads are never merged",
        "accountability grant without expires_at is accepted and verifies accountable_principal_ids",
        "agent grants at every risk tier without temporal constraints are accepted unless the action registry required_constraints list expires_at",
        "session issuance long after provisioning succeeds while the chain is unrevoked",
        "pause fails closed new sessions and invalidates issued sessions within an independent freshness window of at most 60 seconds",
        "agent grants at every risk tier are admitted under the same grant rules as every other subject, with no agent-only resource selector, expiry, or evidence requirement",
    ];
    let observations = case["assertions"]
        .as_array()
        .context("canonical longevity obligations")?
        .iter()
        .map(|value| value.as_str().context("obligation text"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        observations == expected,
        "longevity obligations changed; review the complete live conjunction"
    );
    println!(
        "[agent-longevity-conjunction] nonexpiring_key_revoke_and_no_resurrection=1 same_key_exact_basis_one_winner=1 indefinite_accountability_actual_profile=1 real_risk_tier_grants_same_subject_rules=1 actual_wall_clock_real_issuer=1 actual_pause_freshness_within_60s=1 canonical_case_completion_claim=1 observations=8"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "agent_longevity_no_expiry".to_owned(),
            assertions: 8,
        }],
    })
}
