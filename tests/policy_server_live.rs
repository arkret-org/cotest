//! COT-STATE-01 — live `ak.realm.policy_server` binding contract against a real
//! Soland. The restart case additionally needs the pre-built Soland binary plus
//! `COTEST_POLICY_LIVE_DATABASE_URL` and skips itself otherwise.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn policy_server_binding_contract_is_live() -> Result<()> {
    let _guard = init_transcript_writer("policy_server_live", None)?;
    cotest::scenarios::policy_server_live::policy_server_binding_contract_is_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn policy_server_declaration_survives_restart() -> Result<()> {
    let _guard = init_transcript_writer("policy_server_live_restart", None)?;
    cotest::scenarios::policy_server_live::policy_server_declaration_survives_restart().await
}
