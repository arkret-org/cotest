//! Describe discovery and root-path DPoP with a canonically founded principal.

use anyhow::{Context, Result, ensure};
use reqwest::StatusCode;
use serde_json::json;

pub async fn canonical_oidc_login_chain_api_migration() -> Result<()> {
    let fixture = super::_helpers::canonical_api::fixture("oidc-chain").await?;
    let client = &fixture.client;
    let describe = serde_json::to_value(client.sdk().describe().await?)?;
    let metadata = &describe["authentication_metadata"];
    let oidc = metadata["methods"]
        .as_array()
        .context("describe auth methods")?
        .iter()
        .find(|method| method["method"] == "oidc")
        .context("configured Station must advertise OIDC")?;
    let client_id = std::env::var("COTEST_OIDC_CLIENT_ID").context("canonical OIDC client id")?;
    ensure!(
        !client_id.is_empty() && oidc["client_id"] == client_id,
        "describe OIDC client id mismatch"
    );
    ensure!(
        oidc["grant_exchange"] == json!({"kind":"account_handoff"}),
        "OIDC grant exchange mismatch"
    );
    let coauth = url::Url::parse(&std::env::var("COTEST_COAUTH_BASE_URL")?)?;
    let origin = coauth.origin().ascii_serialization();
    for value in [
        &metadata["account_authority"]["origin"],
        &oidc["issuer_uri"],
        &oidc["openid_configuration_url"],
    ] {
        ensure!(
            url::Url::parse(value.as_str().context("Account Authority origin")?)?
                .origin()
                .ascii_serialization()
                == origin,
            "OIDC discovery does not bind the configured Account Authority"
        );
    }
    ensure!(
        metadata["account_authority"]["gate_account_base_url"]
            == format!("{origin}/_arkret/gate/account"),
        "gate origin mismatch"
    );
    let path = "/_arkret/root/identity/recovery-policy";
    let active: arkret_models_crypto::RecoveryPolicyStatusView = client.sdk().get(path).await?;
    ensure!(
        serde_json::to_value(active)?.get("active_policy").is_some(),
        "root recovery read omitted active_policy"
    );
    // The two old bare-Standard-grant probes asserted the same exact binding.
    // Keep their stricter 401/Problem assertion on the actual canonical grant.
    let problem = crate::harness::expect_api_error(
        fixture
            .server
            .http()
            .get(client.url(path))
            .bearer_auth(client.session().credential()),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    ensure!(
        problem.problem_type == "https://arkret.org/problems/unauthenticated",
        "bare grant Problem type mismatch"
    );
    println!(
        "{}",
        json!({"phase":"oidc_login_chain", "describe":true, "dpop_root_read":true, "bare_standard_grant_rejected":true})
    );
    Ok(())
}
