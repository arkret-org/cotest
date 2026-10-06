use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn preview_account_window_backfills_without_failing_its_sibling_realm() -> Result<()> {
    cotest_inkson_client_tests::scenarios::protocol_payloads::preview_account_window_backfills_without_failing_its_sibling_realm()
        .await
}

#[tokio::test]
#[serial]
async fn limited_window_strand_tail_verifies_with_same_cut_current_through_inkson() -> Result<()> {
    cotest_inkson_client_tests::scenarios::protocol_payloads::limited_window_strand_tail_verifies_with_same_cut_current_through_inkson()
        .await
}

#[tokio::test]
#[serial]
async fn message_tail_window_beyond_twenty_commits_verifies_through_inkson() -> Result<()> {
    cotest_inkson_client_tests::scenarios::protocol_payloads::message_tail_window_beyond_twenty_commits_verifies_through_inkson()
        .await
}

#[tokio::test]
#[serial]
async fn restricted_join_policy_floor_verifies_through_inkson() -> Result<()> {
    cotest_inkson_client_tests::scenarios::protocol_payloads::restricted_join_policy_floor_verifies_through_inkson()
        .await
}
