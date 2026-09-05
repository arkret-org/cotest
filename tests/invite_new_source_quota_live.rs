//! Live acceptance for the holder quarantine per-holder new-source quota.

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

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn consent_request_writes_its_own_quarantine_branch() -> Result<()> {
    let _guard = init_transcript_writer("holder_quarantine_consent_request_branch", None)?;
    cotest::scenarios::invite_new_source_quota_live::consent_request_quarantine_branch_run().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn contact_first_contact_bills_the_quota_without_a_quarantine_entry() -> Result<()> {
    let _guard = init_transcript_writer("holder_quarantine_contact_shares_the_chokepoint", None)?;
    cotest::scenarios::invite_new_source_quota_live::contact_first_contact_bills_the_shared_quota_run(
    )
    .await
}
