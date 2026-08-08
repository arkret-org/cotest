//! Live Coauth issuer-ledger recovery after a committed response is lost.
//!
//! The scenario owns a real Coauth child and PostgreSQL database. Coauth pauses
//! only after its issuer-ledger transaction commits; Cotest kills the process,
//! restarts it from the same config/key material, and sends the exact same
//! canonical request twice. The two replay responses must be byte-identical.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use crate::harness::NonProtocolTestBody;
use crate::scenarios::_helpers::coauth_bootstrap::{CoauthChaosConfig, spawn_coauth_with_db_chaos};

const BREAKPOINT: &str = "session_grant_issue_post_commit_pre_response";

/// Run the destructive, opt-in live fault scenario.
pub async fn coauth_session_grant_response_loss_run() -> Result<()> {
    let marker_dir = tempfile::tempdir().context("create Coauth chaos marker directory")?;
    let marker = marker_dir.path().join("post-commit.reached");
    let mut coauth = spawn_coauth_with_db_chaos(CoauthChaosConfig {
        breakpoint: BREAKPOINT.to_owned(),
        request_identity: None,
        delay_ms: 30_000,
        reached_file: Some(marker.clone()),
    })
    .await?
    .context("Coauth binary and PostgreSQL are required for response-loss recovery")?;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(40))
        .build()
        .context("build Coauth fault-test client")?;
    let actor_id = "did:web:coauth-ledger-chaos.example";
    let audience = "did:web:principal-ledger-chaos.example";
    let bind_url = format!(
        "{}/_coauth/account/test/debug/bind-principal",
        coauth.base_url()
    );
    let bind_response = http
        .post(&bind_url)
        .json(&NonProtocolTestBody::new(json!({
            "actor_id": actor_id,
            "audience": audience,
            "key_log_head": format!("sha256:{}", "1".repeat(64)),
            "account_handle": "coauth-ledger-chaos",
        })))
        .send()
        .await
        .context("bind live debug principal")?;
    ensure_success(bind_response, "bind live debug principal").await?;

    let holder = SigningKey::from_bytes(&[0x5a; 32]);
    let issue_body = json!({
        "actor_id": actor_id,
        "device_id": "ak:device:019b0000-0000-7000-8000-00000000f001",
        "dpop_jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(holder.verifying_key().as_bytes()),
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "Ed25519"
        },
        "audience": audience,
    });
    let canonical_request = arkret_canonical::canonical_json_bytes(&issue_body)?;
    let issue_url = format!(
        "{}/_coauth/account/test/debug/issue-dpop-grant",
        coauth.base_url()
    );
    let first_attempt = tokio::spawn({
        let http = http.clone();
        let issue_url = issue_url.clone();
        let canonical_request = canonical_request.clone();
        async move {
            http.post(issue_url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(canonical_request)
                .send()
                .await
        }
    });

    wait_for_marker(&marker, Duration::from_secs(20)).await?;
    coauth.kill_immediately()?;
    let first_result = first_attempt
        .await
        .context("join interrupted Coauth issue request")?;
    if let Ok(response) = first_result {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("post-commit response unexpectedly escaped process kill: {status} {body}");
    }

    coauth.restart_same_config().await?;
    let replay_one = post_exact(&http, &issue_url, &canonical_request).await?;
    let replay_two = post_exact(&http, &issue_url, &canonical_request).await?;
    ensure!(
        replay_one == replay_two,
        "issuer-ledger replay changed canonical response bytes after restart"
    );
    let outcome: Value =
        serde_json::from_slice(&replay_one).context("decode replayed debug grant outcome")?;
    ensure!(
        outcome
            .get("grant_id")
            .and_then(Value::as_str)
            .is_some_and(|value| value.starts_with("ak:session_grant:")),
        "replayed outcome omitted a canonical SessionGrantId"
    );
    ensure!(
        outcome
            .get("grant_jwt")
            .and_then(Value::as_str)
            .is_some_and(|value| value.split('.').count() == 3),
        "replayed outcome omitted the committed signed credential"
    );
    Ok(())
}

async fn wait_for_marker(path: &std::path::Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(marker) = std::fs::read_to_string(path)
            && marker.contains(&format!("breakpoint={BREAKPOINT}"))
            && marker.contains("request_identity=")
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    bail!(
        "Coauth never reached the durable post-commit breakpoint at {}",
        path.display()
    )
}

async fn post_exact(
    http: &reqwest::Client,
    url: &str,
    canonical_request: &[u8],
) -> Result<Vec<u8>> {
    let response = http
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(canonical_request.to_vec())
        .send()
        .await
        .context("replay exact Coauth request")?;
    let status = response.status();
    let body = response.bytes().await?.to_vec();
    ensure!(
        status.is_success(),
        "Coauth exact replay returned {status}: {}",
        String::from_utf8_lossy(&body)
    );
    Ok(body)
}

async fn ensure_success(response: reqwest::Response, context: &str) -> Result<()> {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    ensure!(status.is_success(), "{context} returned {status}: {body}");
    Ok(())
}
