//! A canonical lifecycle case is reported only after every live gate finishes.

use super::*;

pub async fn run_agent_controller_lifecycle_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    run_agent_controller_lifecycle_boundary().await?;
    run_agent_keypackage_terminal_live().await?;
    let issuer = run_agent_session_grant_replay_production().await?;
    ensure!(
        issuer.cases.len() == 1
            && issuer.cases[0].case_id == "agent_session_grant_replay"
            && issuer.cases[0].assertions == 4,
        "real lifecycle issuer did not complete its canonical live case"
    );
    let root = crate::scenarios::_helpers::external_binary::workspace_root()
        .context("binding source workspace")?;
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(
        root.join("arkret-spec/spec/v1/artifacts/fixtures/agent-vectors-fixture.json"),
    )?)?;
    let declared = fixture["cases"]
        .as_array()
        .context("canonical Agent cases")?
        .iter()
        .filter(|case| case["name"] == "agent_controller_lifecycle")
        .collect::<Vec<_>>();
    let [case] = declared.as_slice() else {
        bail!("lifecycle case is not uniquely declared");
    };
    let expected = [
        "agent lifecycle operation ids retain canonical namespaces",
        "active to paused to active to deactivated is accepted",
        "deactivated is terminal and resume fails with agent_deactivated",
        "pause while paused fails with agent_paused",
        "deactivation accepts one lifecycle Event and rejects client-authored key or grant revocation bundles",
        "deactivated is a mandatory AND gate for every runtime key, session, pairing handle, grant, KeyPackage, presence and new Event path within sixty seconds",
        "agent views expose lifecycle, readiness blockers and expiring presence as three orthogonal axes",
        "offline never means deactivated, unpaired or direct-conversation missing",
    ];
    let observations = case["assertions"]
        .as_array()
        .context("canonical lifecycle observations")?
        .iter()
        .map(|value| value.as_str().context("canonical observation text"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        observations == expected,
        "lifecycle assertions changed; review the entire live conjunction before reporting completion"
    );
    println!(
        "[agent-lifecycle-conjunction] canonical_registry=1 actual_controller_transitions=1 terminal_keys_sessions_pairing_grants_packages_presence_events=1 orthogonal_views=1 real_direct_mls=1 verified_presence_real_expiry_offline=1 real_issuer_conjunction=1 canonical_case_completion_claim=1 observations=8"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "agent_controller_lifecycle".to_owned(),
            assertions: 8,
        }],
    })
}
