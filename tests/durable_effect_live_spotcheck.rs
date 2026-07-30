//! COT-STATE-05 — live spot-check of the operation registry's `durable_effect`
//! declarations against the real Event producers.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn declared_durable_effects_match_live_producers() -> Result<()> {
    let _guard = init_transcript_writer("durable_effect_live_spotcheck", None)?;
    cotest::scenarios::durable_effect_live_spotcheck::declared_durable_effects_match_live_producers(
    )
    .await
}
