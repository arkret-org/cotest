//! The standard Arkret gate operations of the canonical chain.
//!
//! Steps 3, 5 and 7 of `docs/canonical-provisioning-operations.md`, plus the
//! OAuth authorization that step 3 consumes. Everything here is a registered
//! operation with an operation id, in contrast to the Coauth product API in
//! `super::coauth_account`.
//!
//! Protocol material is not built here. The handoff body, the challenge request
//! and the register body come from [`crate::wire`] — the same functions the
//! TypeScript suite reaches through the `cotest-wire` CLI — so the two sides
//! cannot drift on what a registration looks like.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::http::{json_object, post_json};

/// A completed OAuth authorization, ready to be exchanged for a handoff.
#[derive(Clone, Debug)]
pub struct OidcAuthorization {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub authorization_code: String,
    pub code_verifier: String,
}

/// The redirect target registered for the joint deployment's OAuth client.
///
/// `patch-coauth-config.py` registers this pair alongside any Inkson origin, so
/// it is available whether or not a browser lane is running — which is what
/// lets a headless provisioning path complete the authorization at all.
const LOOPBACK_REDIRECT_URI: &str = "http://127.0.0.1/auth/callback";

/// Run the authorization-code flow against Coauth as the logged-in account.
///
/// The client **must not follow redirects**: the authorize response is a 302
/// into the approval page, and its `Location` carries the grant id this flow
/// needs. A client that follows it silently loses the one value the step exists
/// to produce.
pub async fn authorize_with_current_account(
    http: &reqwest::Client,
    coauth_base: &str,
    client_id: &str,
) -> Result<OidcAuthorization> {
    let base = coauth_base.trim_end_matches('/');
    let discovery =
        super::http::get_plain_json(http, &format!("{base}/.well-known/openid-configuration"))
            .await
            .context("read Coauth OIDC discovery")?;
    let discovery = json_object(&discovery, "OIDC discovery")?;
    let issuer = discovery
        .get("issuer")
        .and_then(Value::as_str)
        .context("OIDC discovery omitted issuer")?
        .to_owned();
    let authorization_endpoint = discovery
        .get("authorization_endpoint")
        .and_then(Value::as_str)
        .context("OIDC discovery omitted authorization_endpoint")?;

    let state = random_b64url("state");
    let nonce = random_b64url("nonce");
    let code_verifier = random_b64url("verifier");
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(code_verifier.as_bytes()));

    let mut authorize =
        url::Url::parse(authorization_endpoint).context("parse authorization_endpoint")?;
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", LOOPBACK_REDIRECT_URI)
        .append_pair("scope", "openid")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &code_challenge);

    let response = http
        .get(authorize.as_str())
        .send()
        .await
        .context("GET Coauth authorize")?;
    let status = response.status();
    if !status.is_redirection() {
        let body = response.text().await.unwrap_or_default();
        bail!(
            "Coauth authorize did not enter approval ({status}): {body}. \
             A 200 here usually means the HTTP client is following redirects."
        );
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .context("Coauth authorize redirect carried no Location")?
        .to_owned();
    let approval = url::Url::parse(&location)
        .or_else(|_| url::Url::parse(base).and_then(|b| b.join(&location)))
        .context("parse approval location")?;
    if !approval.path().contains("/oauth/approval/") {
        bail!("Coauth authorize returned an unexpected location: {approval}");
    }
    let grant_id = approval
        .path_segments()
        .and_then(|mut segments| segments.rfind(|s| !s.is_empty()))
        .context("approval location carried no grant id")?
        .to_owned();

    let approved = post_json(
        http,
        &format!("{base}/_coauth/self/oauth/authorization-grants/{grant_id}/decision"),
        &json!({ "action": "approve" }),
    )
    .await
    .context("approve the OAuth authorization grant")?;
    let approved = json_object(&approved, "OAuth approval")?;
    if approved.get("status").and_then(Value::as_str) != Some("success") {
        bail!("Coauth OAuth approval did not succeed: {approved:?}");
    }
    let redirect = approved
        .get("redirect_url")
        .and_then(Value::as_str)
        .context("OAuth approval returned no callback URL")?;
    let callback = url::Url::parse(redirect).context("parse OAuth callback URL")?;

    let mut returned_state = None;
    let mut authorization_code = None;
    for (key, value) in callback.query_pairs() {
        match key.as_ref() {
            "state" => returned_state = Some(value.into_owned()),
            "code" => authorization_code = Some(value.into_owned()),
            _ => {}
        }
    }
    // The state check is the whole point of sending one; a callback that comes
    // back with someone else's state is the failure this flow must not accept.
    if returned_state.as_deref() != Some(state.as_str()) {
        bail!("Coauth OAuth callback state did not match the request");
    }

    Ok(OidcAuthorization {
        issuer,
        client_id: client_id.to_owned(),
        redirect_uri: LOOPBACK_REDIRECT_URI.to_owned(),
        state,
        nonce,
        authorization_code: authorization_code
            .context("OAuth callback omitted the authorization code")?,
        code_verifier,
    })
}

/// Test-scoped entropy, derived rather than drawn from an RNG.
///
/// This is a `state`/`nonce`/`code_verifier` for one provisioning run in one
/// test process; it never protects anything outside it. Deriving from the clock
/// and a label keeps the crate free of an RNG dependency, and the values are
/// still unique per call because the nanosecond clock advances between them.
/// Production PKCE material is CSPRNG-backed in the real clients.
fn random_b64url(label: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(b"cotest-provisioning-v1");
    hasher.update(label.as_bytes());
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}
