use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn same_account_devices_use_independent_signal_domains_on_real_stations() -> Result<()> {
    cotest::scenarios::signal_live::run_same_actor().await
}
