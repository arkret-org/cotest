#[tokio::test(flavor = "multi_thread")]
async fn attributed_agent_requires_a_real_narrow_scope_and_selected_confirmation()
-> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_act_on_behalf_production().await?;
    anyhow::ensure!(
        result.cases.len() == 1
            && result.cases[0].case_id == "agent_act_on_behalf"
            && result.cases[0].assertions == 4
    );
    Ok(())
}
