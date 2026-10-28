#[test]
fn realm_invite_link_proofs_and_private_codec_match_independent_kats() -> anyhow::Result<()> {
    cotest::conformance::run_realm_invite_link_proof_suite()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn realm_invite_links_retain_real_acceptance_and_atomic_usage() -> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::realm_invite_links().await
}
