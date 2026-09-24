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

#[tokio::test]
#[serial]
async fn limited_account_window_names_issued_basis_or_is_preview_only() -> Result<()> {
    cotest::scenarios::protocol_payloads::limited_account_window_names_issued_basis_or_is_preview_only()
        .await
}

#[tokio::test]
#[serial]
async fn preview_account_window_backfills_without_failing_its_sibling_realm() -> Result<()> {
    cotest::scenarios::protocol_payloads::preview_account_window_backfills_without_failing_its_sibling_realm()
        .await
}
