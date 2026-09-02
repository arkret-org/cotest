//! Live acceptance for the invite quarantine per-holder new-source quota.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn new_source_quota_admits_within_ceiling_and_drops_over_it() -> Result<()> {
    let _guard = init_transcript_writer("invite_new_source_quota_admission", None)?;
    cotest::scenarios::invite_new_source_quota_live::new_source_quota_holder_admission_run().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn require_explicit_consent_profile_has_no_quarantine_face() -> Result<()> {
    let _guard = init_transcript_writer("invite_new_source_quota_require_explicit_consent", None)?;
    cotest::scenarios::invite_new_source_quota_live::new_source_quota_require_explicit_consent_run()
        .await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn new_source_quota_holder_override_only_narrows() -> Result<()> {
    let _guard = init_transcript_writer("invite_new_source_quota_bounds", None)?;
    cotest::scenarios::invite_new_source_quota_live::new_source_quota_effective_bounds_run().await
}
