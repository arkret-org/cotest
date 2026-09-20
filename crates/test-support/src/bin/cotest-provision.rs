//! Line-oriented JSON bridge to `cotest_test_support::provisioning`.
//!
//! One request per line on stdin, one response per line on stdout, correlated
//! by `id`. This is how the TypeScript suite reaches the same provisioning code
//! a Rust scenario calls directly — the point of the module being that there is
//! one implementation of the canonical chain, not one per language.
//!
//! Why a long-lived process rather than one invocation per call, the way
//! `cotest-wire` works: provisioning carries state that must survive between
//! steps. The cookie jar holds Coauth's authenticated account session, and the
//! gate handoff authorizes against it. A fresh process per call would log in
//! again for every step, or lose the session entirely.
//!
//! Protocol:
//!
//! ```text
//! -> {"id":"1","op":"describe_station","endpoints":{...}}
//! <- {"id":"1","ok":true,"result":{...}}
//! <- {"id":"1","ok":false,"error":"..."}
//! ```
//!
//! stdout carries responses only. Diagnostics go to stderr, and secrets — the
//! password, the recovery mnemonic, the grant — are never written to either:
//! they travel in the response body to the caller that asked for them, and the
//! runner's secret scan reads the logs.

use std::collections::HashMap;
use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};
use cotest_test_support::garth_client::GarthClientHandle;
use cotest_test_support::provisioning::{
    AccountHandoff, DeploymentEndpoints, FoundPrincipalRequest, FoundingDeviceKey, MockEmailInbox,
    UnboundAccount, authorize_with_current_account, create_account_handoff, describe_station,
    found_principal, provision_unbound_account, read_self_account_viewer,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct Request {
    id: String,
    op: String,
    #[serde(flatten)]
    body: Value,
}

#[derive(Debug, Deserialize)]
struct EndpointsBody {
    coauth_base_url: String,
    soland_base_url: String,
    #[serde(default)]
    mock_email_base_url: Option<String>,
}

impl From<EndpointsBody> for DeploymentEndpoints {
    fn from(value: EndpointsBody) -> Self {
        Self {
            coauth_base_url: value.coauth_base_url,
            soland_base_url: value.soland_base_url,
            mock_email: value
                .mock_email_base_url
                .filter(|url| !url.trim().is_empty())
                .map(|base_url| MockEmailInbox { base_url }),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AccountBody {
    handle: String,
    password: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
}

impl From<AccountBody> for UnboundAccount {
    fn from(value: AccountBody) -> Self {
        let email = value
            .email
            .unwrap_or_else(|| format!("{}@example.test", value.handle));
        let display_name = value
            .display_name
            .unwrap_or_else(|| format!("E2E {}", value.handle));
        Self {
            handle: value.handle,
            email,
            password: value.password,
            display_name,
        }
    }
}

/// A directory name that is legal on every platform the harness runs on.
///
/// Arkret ids carry colons, which Windows rejects in a path component. Keeping
/// the mapping total and lossless-enough (one output char per input char) means
/// two different ids cannot collide into one store.
fn sanitize_path_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

/// State that must live across requests.
///
/// Handoffs are held by id because `found_principal` needs the one this session
/// created — including its founding device key, which never leaves the process.
///
/// Session grants are held the same way and for the same reason: a
/// grant-authorized read has to present the grant *and* a proof signed by the
/// device key it was issued to, and neither is allowed across the bridge. The
/// caller refers to both by the handoff id it already has.
struct Session {
    http: reqwest::Client,
    handoffs: HashMap<String, AccountHandoff>,
    session_grants: HashMap<String, String>,
    /// Garth clients, one per founded principal, keyed by handoff id.
    ///
    /// Held rather than rebuilt per call because a Garth client owns a durable
    /// store on disk: rebuilding it for every request would give each call a
    /// different process's view of the same account, which is the opposite of
    /// what a client is.
    garth_clients: HashMap<String, GarthClientHandle>,
}

impl Session {
    fn new() -> Result<Self> {
        let ca_pem = std::env::var("COTEST_RUN_SCOPED_CA_PEM").context(
            "COTEST_RUN_SCOPED_CA_PEM is required: the harness terminates TLS with a per-run CA, \
             and a client that skipped verification would also accept a misconfigured deployment",
        )?;
        let pem = std::fs::read(&ca_pem).with_context(|| format!("read run-scoped CA {ca_pem}"))?;
        let certificate = reqwest::Certificate::from_pem(&pem)
            .with_context(|| format!("parse run-scoped CA {ca_pem}"))?;
        let http = reqwest::Client::builder()
            .add_root_certificate(certificate)
            // Coauth's account session is a cookie; the gate handoff authorizes
            // against it.
            .cookie_store(true)
            // The authorize step's 302 carries the grant id in its `Location`.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build the provisioning HTTP client")?;
        Ok(Self {
            http,
            handoffs: HashMap::new(),
            session_grants: HashMap::new(),
            garth_clients: HashMap::new(),
        })
    }

    async fn dispatch(&mut self, request: Request) -> Result<Value> {
        match request.op.as_str() {
            "describe_station" => {
                let endpoints: DeploymentEndpoints =
                    serde_json::from_value::<EndpointsBody>(request.body)
                        .context("parse endpoints")?
                        .into();
                let facts = describe_station(&self.http, &endpoints).await?;
                Ok(json!({
                    "trust_domain": facts.trust_domain,
                    "service_id": facts.service_id,
                }))
            }
            "provision_unbound_account" => {
                #[derive(Deserialize)]
                struct Body {
                    endpoints: EndpointsBody,
                    account: AccountBody,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let endpoints: DeploymentEndpoints = body.endpoints.into();
                let account: UnboundAccount = body.account.into();
                provision_unbound_account(&self.http, &endpoints, &account).await?;
                Ok(json!({ "handle": account.handle, "email": account.email }))
            }
            "create_account_handoff" => {
                #[derive(Deserialize)]
                struct Body {
                    coauth_base_url: String,
                    client_id: String,
                    audience_id: String,
                    device_label: String,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let authorization = authorize_with_current_account(
                    &self.http,
                    &body.coauth_base_url,
                    &body.client_id,
                )
                .await?;
                let handoff = create_account_handoff(
                    &self.http,
                    &body.coauth_base_url,
                    &body.audience_id,
                    &authorization,
                    FoundingDeviceKey::derive(&body.device_label),
                )
                .await?;
                let response = json!({
                    "handoff_id": handoff.request_id,
                    "expires_at": handoff.expires_at,
                    "binding": handoff.binding,
                });
                // The grant and the device key stay here. A caller that needs
                // them needs `found_principal`, which runs in this process.
                self.handoffs.insert(handoff.request_id.clone(), handoff);
                Ok(response)
            }
            "found_principal" => {
                #[derive(Deserialize)]
                struct Body {
                    handoff_id: String,
                    coauth_base_url: String,
                    soland_base_url: String,
                    trust_domain: String,
                    audience_id: String,
                    device_id: String,
                    display_name: String,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let handoff = self
                    .handoffs
                    .get(&body.handoff_id)
                    .with_context(|| format!("no handoff {} in this session", body.handoff_id))?;
                let principal = found_principal(
                    &self.http,
                    FoundPrincipalRequest {
                        coauth_base: &body.coauth_base_url,
                        station_base: &body.soland_base_url,
                        trust_domain: &body.trust_domain,
                        audience_id: &body.audience_id,
                        device_id: &body.device_id,
                        display_name: &body.display_name,
                    },
                    handoff,
                )
                .await?;
                // Retained so `read_self_account_viewer` can present it. It
                // is also in the response — the caller needs to assert on the
                // outcome — but the read is done here so the proof is signed by
                // the device key, which is not.
                let grant = principal.session_grant();
                self.session_grants
                    .insert(body.handoff_id.clone(), grant.session_grant.clone());
                // Named fields, not the whole checkpoint: that carries
                // `device_signing_seed_b64url`, and this boundary exists so key
                // material stays on this side of it. What crosses is the
                // identity — including the verification method the seed backs,
                // which is public.
                Ok(json!({
                    "principal_id": principal.outcome.principal_id,
                    "did": principal.did,
                    "device_id": principal.device_id,
                    "account_id": principal.account_id(),
                    "event_verification_method": principal.event_verification_method,
                    "recovery_key": principal.recovery_key,
                    "session_grant": {
                        "session_grant": grant.session_grant,
                        "session_grant_id": grant.session_grant_id,
                        "audience_id": grant.audience_id,
                        "device_id": grant.device_id,
                        "granted_scope": grant.granted_scope,
                        "expires_at": arkret_canonical::format_timestamp_canonical(grant.expires_at),
                    },
                    "binding_receipt": principal.outcome.binding_receipt,
                    "pcr_genesis_commits": principal.outcome.pcr_genesis_commits,
                }))
            }
            "read_self_account_viewer" => {
                #[derive(Deserialize)]
                struct Body {
                    handoff_id: String,
                    soland_base_url: String,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let handoff = self
                    .handoffs
                    .get(&body.handoff_id)
                    .with_context(|| format!("no handoff {} in this session", body.handoff_id))?;
                let grant = self.session_grants.get(&body.handoff_id).with_context(|| {
                    format!(
                        "handoff {} has no session grant; found_principal has not run for it",
                        body.handoff_id
                    )
                })?;
                let read = read_self_account_viewer(
                    &self.http,
                    &body.soland_base_url,
                    grant,
                    &handoff.device_key,
                )
                .await?;
                Ok(json!({ "status": read.status, "body": read.body }))
            }
            // --- Garth as a client -------------------------------------------
            //
            // These drive `ArkretClient` itself, not the provisioning builders
            // above. That distinction is the whole point of a `GarthClient`
            // being selectable: a suite asking for Garth must get Garth's
            // runtime, not the harness reproducing what it would have done.
            "garth_client_open" => {
                #[derive(Deserialize)]
                struct Body {
                    handoff_id: String,
                    soland_base_url: String,
                    account_id: arkret_wire::AccountId,
                    device_id: String,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let handoff = self
                    .handoffs
                    .get(&body.handoff_id)
                    .with_context(|| format!("no handoff {} in this session", body.handoff_id))?;
                let grant = self.session_grants.get(&body.handoff_id).with_context(|| {
                    format!(
                        "handoff {} has no session grant; found_principal has not run for it",
                        body.handoff_id
                    )
                })?;
                // One store directory per principal, under this process's
                // scratch root, so a restart check reopens the same bytes.
                //
                // The handoff id is a `ak:request:<uuid>` and colons are not
                // legal in a Windows path component, so the directory is named
                // by a sanitized form rather than the id itself.
                let store_root = std::env::temp_dir()
                    .join("cotest-garth-client")
                    .join(sanitize_path_component(&body.handoff_id));
                let client = GarthClientHandle::new(
                    self.http.clone(),
                    &body.soland_base_url,
                    grant.clone(),
                    handoff.device_key.signing_key(),
                    body.account_id,
                    &body.device_id,
                    &store_root,
                )?;
                self.garth_clients.insert(body.handoff_id.clone(), client);
                Ok(json!({ "store_root": store_root.to_string_lossy() }))
            }
            "garth_sync_account" => {
                #[derive(Deserialize)]
                struct Body {
                    handoff_id: String,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let client = self.garth_clients.get(&body.handoff_id).with_context(|| {
                    format!(
                        "no Garth client for handoff {}; call garth_client_open first",
                        body.handoff_id
                    )
                })?;
                let outcome = client.sync_account_once().await?;
                Ok(json!({
                    "rounds": outcome.rounds,
                    "cursor": outcome.cursor,
                    "stop_reason": outcome.stop_reason,
                }))
            }
            "garth_cursor_after_restart" => {
                #[derive(Deserialize)]
                struct Body {
                    handoff_id: String,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let client = self.garth_clients.get(&body.handoff_id).with_context(|| {
                    format!(
                        "no Garth client for handoff {}; call garth_client_open first",
                        body.handoff_id
                    )
                })?;
                Ok(json!({ "cursor": client.cursor_after_restart().await? }))
            }
            other => bail!("unknown provisioning op {other:?}"),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut session = Session::new()?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line.context("read stdin")?;
        if line.trim().is_empty() {
            continue;
        }
        // A request that cannot be parsed has no id to answer under, so it ends
        // the bridge rather than being silently dropped: a caller waiting on a
        // response it will never get is worse than a crash.
        let request: Request =
            serde_json::from_str(&line).with_context(|| format!("parse request: {line}"))?;
        let id = request.id.clone();
        let response = match session.dispatch(request).await {
            Ok(result) => json!({ "id": id, "ok": true, "result": result }),
            // `{error:#}` renders the whole anyhow chain, which is where the
            // step that actually failed is named.
            Err(error) => json!({ "id": id, "ok": false, "error": format!("{error:#}") }),
        };
        writeln!(stdout, "{}", serde_json::to_string(&response)?).context("write response")?;
        stdout.flush().context("flush response")?;
    }
    Ok(())
}
