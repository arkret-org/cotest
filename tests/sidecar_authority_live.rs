//! Real signed Sidecar atomic ensure, private native scans and snapshots.
use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sidecar_ensure_replay_and_private_native_disclosure_are_real() -> Result<()> {
    cotest::scenarios::sidecar_authority_live::run().await
}
