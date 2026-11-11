#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn native_agent_signal_survives_restart_and_rejects_old_runtime() -> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_signal_native().await
}
