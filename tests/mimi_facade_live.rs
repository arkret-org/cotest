use anyhow::Result;
use serial_test::serial;
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mimi_provider_signature_and_observer_have_no_bearer_shortcut_or_effects() -> Result<()> {
    cotest::scenarios::mimi_facade_live::run().await
}
