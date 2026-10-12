use anyhow::Result;
use cotest::scenarios::fanout_route_miss_live::frozen_authority_live;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn signed_scope_and_plaintext_policy_revoke_frozen_delivery_before_send() -> Result<()> {
    frozen_authority_live::scope_and_policy_withdrawal().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn terminal_frozen_intent_cancels_after_canonical_byte_withdrawal() -> Result<()> {
    frozen_authority_live::terminal_disclosure(true).await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn terminal_frozen_intent_delivers_while_complete_disclosure_remains() -> Result<()> {
    frozen_authority_live::terminal_disclosure(false).await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn remaining_original_witness_delivers_but_rejoin_never_revives_old_intent() -> Result<()> {
    frozen_authority_live::remaining_witness_and_rejoin().await
}
