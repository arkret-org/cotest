//! Live acceptance for service-authored actor-private Invite updates.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn invite_notification_wakes_account_subscribe() -> Result<()> {
    let _guard = init_transcript_writer("invite_notification_wakeup_live", None)?;
    cotest::scenarios::invite_service_fanout_live::invite_notification_wakeup_live_run().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "requires an advertised principal-server device-pairing handoff bundle"]
async fn invite_service_fanout_matches_account_data_cas() -> Result<()> {
    let _guard = init_transcript_writer("invite_service_fanout_live", None)?;
    cotest::scenarios::invite_service_fanout_live::invite_service_fanout_live_run().await
}
