use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn cold_recipient_fetches_origin_signed_evidence_through_two_real_stations() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::run_current_signer_evidence_live().await
}
