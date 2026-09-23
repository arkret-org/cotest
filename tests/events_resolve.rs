use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn retired_events_resolve_and_seal_endpoints_are_closed() -> Result<()> {
    cotest::scenarios::events_resolve::events_resolve_selector_budget_run().await
}
