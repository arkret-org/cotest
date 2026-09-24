use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn live_authority_bundle_and_scan_verify_through_garth() -> Result<()> {
    cotest::scenarios::protocol_payloads::live_authority_bundle_and_scan_verify_through_garth()
        .await
}
