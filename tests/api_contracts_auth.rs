use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn framework_errors_and_invalid_json_use_cokret_envelopes() -> Result<()> {
    cotest::scenarios::api_contracts_auth::framework_errors_and_invalid_json_use_cokret_envelopes()
        .await
}

#[tokio::test]
#[serial]
async fn account_auth_and_session_edges_are_enforced() -> Result<()> {
    cotest::scenarios::api_contracts_auth::account_auth_and_session_edges_are_enforced().await
}

#[tokio::test]
#[serial]
async fn contact_edges_are_rejected() -> Result<()> {
    cotest::scenarios::api_contracts_auth::contact_edges_are_rejected().await
}
