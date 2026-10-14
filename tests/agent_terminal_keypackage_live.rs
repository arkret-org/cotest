#[tokio::test(flavor = "multi_thread")]
async fn terminal_agent_cannot_supply_current_keys_packages_or_new_events() -> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_keypackage_terminal_live().await
}
