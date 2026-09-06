//! Coauth's private account product API.
//!
//! Deliberately separate from the standard gate operations in this module's
//! sibling. These endpoints live under `/_coauth/`, they are Coauth's own
//! product surface rather than an Arkret protocol surface, and there is no SDK
//! client for them by design — dressing them up as spec operations would put a
//! deployment's account product into the protocol.
//!
//! What lives here is exactly steps 1, 1a and 1b of
//! `docs/canonical-provisioning-operations.md`: start an account-first
//! registration, satisfy the email verification when the deployment asks for
//! it, and finish. Nothing here authors a principal — that begins at the gate.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use super::http::{json_object, post_json};

/// A Coauth account that exists but is not yet bound to a principal.
#[derive(Clone, Debug)]
pub struct UnboundAccount {
    pub handle: String,
    pub email: String,
    pub password: String,
    pub display_name: String,
}

/// Where the verification code for a registration can be read.
///
/// Only the harness mock is supported: a deployment that sends real mail has no
/// place in an automated provisioning path, and pretending otherwise would make
/// the failure look like a protocol error instead of a missing service.
#[derive(Clone, Debug)]
pub struct MockEmailInbox {
    pub base_url: String,
}

/// Register an account and carry it to the point where it can authenticate.
///
/// Fails closed on a deployment that asks for email verification without a mock
/// inbox configured: continuing would leave a half-registered account and
/// surface later as an authentication failure with no obvious cause.
pub async fn register_unbound_account(
    http: &reqwest::Client,
    coauth_base: &str,
    account: &UnboundAccount,
    inbox: Option<&MockEmailInbox>,
) -> Result<()> {
    let base = format!(
        "{}/_coauth/account/auth/register",
        coauth_base.trim_end_matches('/')
    );
    let started = post_json(
        http,
        &base,
        &json!({
            "handle": account.handle,
            "email": account.email,
            "password": account.password,
            "password_confirm": account.password,
        }),
    )
    .await
    .context("start Coauth account-first registration")?;
    let started = json_object(&started, "Coauth registration start")?;
    if started.get("status").and_then(Value::as_str) != Some("success") {
        bail!("Coauth account-first registration was rejected: {started:?}");
    }
    let registration_id = started
        .get("id")
        .and_then(Value::as_str)
        .context("Coauth registration omitted its id")?;

    let mut next_step = started
        .get("next_step")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if next_step.as_deref() == Some("verify_email") {
        let inbox = inbox.context(
            "this deployment requires email verification, but no mock inbox was configured; \
             start the harness with -StartMocks",
        )?;
        let code = await_verification_code(http, inbox, &account.email).await?;
        let verified = post_json(
            http,
            &format!("{base}/{registration_id}/verify-email"),
            &json!({ "code": code }),
        )
        .await
        .context("verify Coauth registration email")?;
        let verified = json_object(&verified, "Coauth email verification")?;
        next_step = verified
            .get("next_step")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }

    if next_step.as_deref() == Some("display_name") {
        let named = post_json(
            http,
            &format!("{base}/{registration_id}/display-name"),
            &json!({ "display_name": account.display_name }),
        )
        .await
        .context("set Coauth registration display name")?;
        let named = json_object(&named, "Coauth display name")?;
        next_step = named
            .get("next_step")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }

    if next_step.is_some() && next_step.as_deref() != Some("finish") {
        bail!(
            "Coauth registration asked for an unsupported step {:?}; the provisioning path \
             covers verify_email, display_name and finish",
            next_step
        );
    }

    let finished = post_json(
        http,
        &format!("{base}/{registration_id}/finish"),
        &json!({}),
    )
    .await
    .context("finish Coauth registration")?;
    let finished = json_object(&finished, "Coauth registration finish")?;
    if finished.get("status").and_then(Value::as_str) != Some("success") {
        bail!("Coauth registration did not finish: {finished:?}");
    }
    Ok(())
}

/// Authenticate an existing account so the gate handoff can authorize.
pub async fn login(
    http: &reqwest::Client,
    coauth_base: &str,
    handle: &str,
    password: &str,
) -> Result<()> {
    let outcome = post_json(
        http,
        &format!(
            "{}/_coauth/account/auth/login",
            coauth_base.trim_end_matches('/')
        ),
        &json!({ "handle": handle, "password": password }),
    )
    .await
    .context("authenticate Coauth account")?;
    let outcome = json_object(&outcome, "Coauth login")?;
    if outcome.get("status").and_then(Value::as_str) != Some("success") {
        bail!("Coauth password authentication failed: {outcome:?}");
    }
    Ok(())
}

/// Wait for the code Coauth mails asynchronously.
///
/// The registration response comes back before the mail lands, so a single read
/// is a race. The TypeScript helper polls for thirty seconds; so does this. A
/// timeout is an error, never a skip.
async fn await_verification_code(
    http: &reqwest::Client,
    inbox: &MockEmailInbox,
    email: &str,
) -> Result<String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut last_error = None;
    while std::time::Instant::now() < deadline {
        match verification_code(http, inbox, email).await {
            Ok(code) => return Ok(code),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err(last_error.unwrap_or_else(|| {
        anyhow::anyhow!("mock inbox produced no verification code for {email} within 30s")
    }))
}

async fn verification_code(
    http: &reqwest::Client,
    inbox: &MockEmailInbox,
    email: &str,
) -> Result<String> {
    let url = format!(
        "{}/mock/email/verification/inbox?to={}",
        inbox.base_url.trim_end_matches('/'),
        urlencoding(email)
    );
    let response = http
        .get(&url)
        .send()
        .await
        .context("read mock email verification inbox")?;
    let status = response.status();
    let body = response.text().await.context("read mock inbox body")?;
    if !status.is_success() {
        bail!("mock email inbox returned {status}: {body}");
    }
    let body: Value = serde_json::from_str(&body).context("parse mock inbox body")?;
    // The mock returns `{ messages: [ { token, ... } ] }`, newest last, and the
    // code is the `token` field. The first live run of this module looked for a
    // top-level `code` and found nothing — a shape mistake that reads as
    // "Coauth never sent the mail", which is a much more alarming story than
    // the truth.
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .with_context(|| format!("mock inbox returned no messages array: {body}"))?;
    messages
        .iter()
        .rev()
        .find_map(|message| message.get("token").and_then(Value::as_str))
        .map(str::to_owned)
        .with_context(|| format!("mock inbox held no verification token for {email}"))
}

fn urlencoding(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}
