//! Canonical attribution evidence requires every live confirmation and scope gate.

use super::*;

pub async fn run_agent_act_on_behalf_production() -> Result<crate::conformance::SuiteExecutionResult>
{
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let cases = fixture["cases"]
        .as_array()
        .context("canonical Agent cases")?;
    let declared = cases
        .iter()
        .filter(|case| case["name"] == "agent_act_on_behalf")
        .collect::<Vec<_>>();
    let [case] = declared.as_slice() else {
        bail!("act-on-behalf is not uniquely declared");
    };
    let expected = [
        "controller approvals are single-use",
        "exact approval retry returns the original Commit; nonce rebinding fails with approval_nonce_reused",
        "act-on-behalf without authorization_ref, participation, matching grant scope, or fresh approval fails closed",
        "unauthorised sidecar creation fails with sidecar_create_denied",
    ];
    let actual = case["assertions"]
        .as_array()
        .context("canonical attribution obligations")?
        .iter()
        .map(|item| item.as_str().context("obligation text"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        actual == expected,
        "review the changed attribution obligations"
    );
    run_agent_act_on_behalf_boundary().await?;
    println!(
        "[agent-act-conjunction] real_issuer_and_actual_producer=1 confirmation_single_use_and_exact_retry=1 nonce_rebinding_zero_effect=1 authorization_participation_scope_and_fresh_approval_independently_refused=1 sidecar_create_denied=1 canonical_case_completion_claim=1 observations=4"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "agent_act_on_behalf".to_owned(),
            assertions: 4,
        }],
    })
}
