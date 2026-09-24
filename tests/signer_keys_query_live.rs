use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn recipient_station_resolves_current_admitted_sender_key_through_two_real_stations()
-> Result<()> {
    cotest::scenarios::fanout_route_miss_live::run_signer_keys_query_live().await
}
