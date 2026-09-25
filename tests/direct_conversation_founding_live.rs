use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn contact_round_founds_direct_conversation() -> Result<()> {
    cotest::scenarios::direct_conversation_founding_live::contact_round_founds_direct_conversation()
        .await
}
