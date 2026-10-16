#[tokio::test(flavor = "multi_thread")]
async fn attributed_agent_requires_a_real_narrow_scope_and_selected_confirmation()
-> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_act_on_behalf_production().await?;
    println!("[agent-payload-approval-cases] {result:#?}");
    anyhow::ensure!(
        result.cases.len() == 2
            && result.cases[0].case_id == "agent_act_on_behalf"
            && result.cases[0].assertions == 4
            && result.cases[1].case_id == "approval_missing"
            && result.cases[1].assertions == 1
    );
    Ok(())
}
