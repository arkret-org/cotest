use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn narrow_snapshot_head_discloses_only_complete_creator_cut() -> Result<()> {
    cotest::scenarios::protocol_payloads::narrow_snapshot_head_discloses_only_complete_creator_cut()
        .await
}

#[tokio::test]
#[serial]
async fn exact_snapshot_by_ref_reads_through_garth_with_historical_station_key() -> Result<()> {
    cotest::scenarios::protocol_payloads::exact_snapshot_by_ref_reads_through_garth_with_historical_station_key()
        .await
}
