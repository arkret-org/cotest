//! COT-STATE-02 — live Invite frozen-pre-state acceptance across SDK, Coland
//! and the Inkson producer.

use anyhow::Result;
use cotest_inkson_client_tests::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn invite_frozen_prestate_is_enforced_before_acceptance() -> Result<()> {
    let _guard = init_transcript_writer("invite_frozen_prestate", None)?;
    cotest_inkson_client_tests::scenarios::invite_frozen_prestate_live::invite_frozen_prestate_is_enforced_before_acceptance()
        .await
}
