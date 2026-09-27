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
async fn invite_service_fanout_matches_account_data_cas() -> Result<()> {
    let _guard = init_transcript_writer("invite_service_fanout_live", None)?;
    cotest::scenarios::invite_service_fanout_live::invite_service_fanout_live_run().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn consent_current_grant_read_revoke_changes_invite_gate() -> Result<()> {
    let _guard = init_transcript_writer("consent_current_invite_gate_live", None)?;
    cotest::scenarios::invite_service_fanout_live::consent_current_and_invite_gate_live_run().await
}
