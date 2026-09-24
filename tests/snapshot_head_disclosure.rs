use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn narrow_snapshot_head_discloses_only_complete_creator_cut() -> Result<()> {
    cotest::scenarios::protocol_payloads::narrow_snapshot_head_discloses_only_complete_creator_cut()
        .await
}
