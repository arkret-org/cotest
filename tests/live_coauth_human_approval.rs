use anyhow::{Context, Result, bail};
use cotest::conformance::validate_agent_human_approval_http_response;
use reqwest::header::WWW_AUTHENTICATE;
use serde_json::Value;

/// Exercises the real coauth session-grant endpoint with a fully prepared
/// agent request. The request must already contain a valid fresh agent key
/// proof and a scope whose policy requires controller approval.
/// Gating: requires a live coauth instance and
/// `COTEST_COAUTH_AGENT_APPROVAL_REQUEST_JSON`.
/// Tier: live
#[tokio::test]
#[ignore = "requires a live coauth instance and COTEST_COAUTH_AGENT_APPROVAL_REQUEST_JSON"]
async fn live_coauth_returns_closed_human_approval_error() -> Result<()> {
    let base_url = std::env::var("COTEST_COAUTH_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned());
    let raw_request = std::env::var("COTEST_COAUTH_AGENT_APPROVAL_REQUEST_JSON").context(
        "set COTEST_COAUTH_AGENT_APPROVAL_REQUEST_JSON to a fresh agent session-grant request",
    )?;
    let request: Value = serde_json::from_str(&raw_request)
        .context("COTEST_COAUTH_AGENT_APPROVAL_REQUEST_JSON must be JSON")?;
    if request.pointer("/proof/proof_kind").and_then(Value::as_str) != Some("agent_key_proof") {
        bail!("live request must use proof.proof_kind=agent_key_proof");
    }

    let response = reqwest::Client::new()
        .post(format!(
            "{}/_arkret/gate/account/session-grants",
            base_url.trim_end_matches('/')
        ))
        .json(&request)
        .send()
        .await
        .context("call live coauth session-grant endpoint")?;
    let status = response.status();
    if response.headers().contains_key(WWW_AUTHENTICATE) {
        bail!("human-approval response must not carry WWW-Authenticate");
    }
    let body: Value = response
        .json()
        .await
        .context("decode live coauth human-approval response")?;
    validate_agent_human_approval_http_response(status.as_u16(), &body)?;
    Ok(())
}
