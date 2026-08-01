use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn events_resolve_honours_typed_selectors_and_merged_budget() -> Result<()> {
    cotest::scenarios::events_resolve::events_resolve_selector_budget_run().await
}
