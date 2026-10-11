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
use cotest_test_support::garth_client::{GarthClientConfig, GarthClientHandle};
use cotest_test_support::provisioning::{
    AccountHandoff, DeploymentEndpoints, FoundPrincipalRequest, FoundedPrincipal,
    FoundingDeviceKey, MockEmailInbox, UnboundAccount, authorize_with_current_account,
    create_account_handoff, describe_station, found_principal, provision_unbound_account,
    read_self_account_viewer,
};
use serde::{Deserialize, Serialize};
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
    coland_base_url: String,
    #[serde(default)]
    mock_email_base_url: Option<String>,
}

impl From<EndpointsBody> for DeploymentEndpoints {
    fn from(value: EndpointsBody) -> Self {
        Self {
            coauth_base_url: value.coauth_base_url,
            coland_base_url: value.coland_base_url,
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

/// Private test-run custody only; formal request/outcome DTOs remain SDK-owned.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableIdentity {
    principal: FoundedPrincipal,
    trust_domain: String,
    station_base: String,
    coauth_base: String,
    session_signing_seed_b64url: String,
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
    store_root: std::path::PathBuf,
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
        let run_id =
            arkret_wire::RequestId::new_v7_at(chrono::Utc::now().timestamp_millis() as u64);
        let custody_root =
            std::path::PathBuf::from(std::env::var_os("COTEST_PROVISION_CUSTODY_ROOT").context(
                "COTEST_PROVISION_CUSTODY_ROOT must come from the canonical runner lifecycle",
            )?);
        let custody_metadata = std::fs::symlink_metadata(&custody_root)?;
        anyhow::ensure!(
            custody_metadata.is_dir() && !custody_metadata.file_type().is_symlink(),
            "run-owned custody root must be a regular directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            anyhow::ensure!(
                custody_metadata.permissions().mode() & 0o077 == 0,
                "run-owned custody root permissions must exclude other users"
            );
        }
        let store_root = custody_root.join(sanitize_path_component(run_id.as_str()));
        std::fs::create_dir_all(&store_root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store_root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            http,
            handoffs: HashMap::new(),
            session_grants: HashMap::new(),
            garth_clients: HashMap::new(),
            store_root,
        })
    }

    fn identity_path(&self, handoff_id: &str) -> std::path::PathBuf {
        self.store_root
            .join(sanitize_path_component(handoff_id))
            .join("accepted-identity.json")
    }

    fn persist_identity(&self, handoff_id: &str, identity: &DurableIdentity) -> Result<()> {
        let path = self.identity_path(handoff_id);
        let directory = path.parent().context("identity directory absent")?;
        std::fs::create_dir_all(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .context("create run-owned accepted identity snapshot")?;
        file.write_all(&serde_json::to_vec(identity)?)?;
        file.sync_all()?;
        Ok(())
    }

    fn read_identity(&self, handoff_id: &str) -> Result<DurableIdentity> {
        // Validate the canonical key before filesystem normalization; arbitrary
        // strings must not alias a different handoff's custody directory.
        arkret_wire::RequestId::new(handoff_id.to_owned()).map_err(anyhow::Error::msg)?;
        let path = self.identity_path(handoff_id);
        let metadata = std::fs::symlink_metadata(&path)
            .context("durable accepted identity snapshot unavailable")?;
        anyhow::ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "accepted identity snapshot must be a run-owned regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            anyhow::ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "accepted identity snapshot custody permissions are too broad"
            );
        }
        anyhow::ensure!(
            metadata.len() <= 8 * 1024 * 1024,
            "accepted identity snapshot exceeds its private host bound"
        );
        serde_json::from_slice(&std::fs::read(path)?)
            .context("decode durable accepted identity snapshot")
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
                    coland_base_url: String,
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
                        station_base: &body.coland_base_url,
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
                self.persist_identity(
                    &body.handoff_id,
                    &DurableIdentity {
                        principal: principal.clone(),
                        trust_domain: body.trust_domain,
                        station_base: body.coland_base_url,
                        coauth_base: body.coauth_base_url,
                        session_signing_seed_b64url: handoff.device_key.seed_b64url.clone(),
                    },
                )?;
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
                    coland_base_url: String,
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
                    &body.coland_base_url,
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
                    coland_base_url: String,
                    account_id: arkret_wire::AccountId,
                    device_id: String,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let identity = self.read_identity(&body.handoff_id)?;
                let principal = &identity.principal;
                let accepted_grant = principal
                    .outcome
                    .session_grant_outcome
                    .as_ref()
                    .context("durable accepted initial session grant unavailable")?;
                anyhow::ensure!(
                    accepted_grant.account_id == body.account_id
                        && principal.device_id == body.device_id,
                    "Garth client identity must match the durable accepted principal and grant"
                );
                anyhow::ensure!(
                    url::Url::parse(&body.coland_base_url)?
                        == url::Url::parse(&identity.station_base)?,
                    "Garth Station endpoint must match the canonical provisioning source"
                );
                let session_key =
                    FoundingDeviceKey::restore(&identity.session_signing_seed_b64url)?;
                principal
                    .validate_restored(
                        &self.http,
                        &identity.coauth_base,
                        &identity.station_base,
                        &identity.trust_domain,
                        &session_key,
                    )
                    .await?;
                let seed = principal
                    .event_signing_seed_b64url()
                    .context("accepted Device signer seed is unavailable")?;
                let seed = arkret_canonical::base64url_decode(seed)?;
                let seed: [u8; 32] = seed
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Device signer seed must have 32 bytes"))?;
                let store_root = self
                    .store_root
                    .join(sanitize_path_component(&body.handoff_id));
                let client = GarthClientHandle::new(GarthClientConfig {
                    http: self.http.clone(),
                    station_base_url: &body.coland_base_url,
                    session_grant: principal.session_grant().session_grant.clone(),
                    signing_key: session_key.signing_key(),
                    account_id: body.account_id,
                    device_id: &body.device_id,
                    store_root: &store_root,
                    event_signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
                    event_verification_method: &principal.event_verification_method,
                    trust_domain: &identity.trust_domain,
                })?;
                self.garth_clients.insert(body.handoff_id.clone(), client);
                Ok(json!({ "store_root": store_root.to_string_lossy(),
                    "identity_snapshot_path":self.identity_path(&body.handoff_id).to_string_lossy(),
                    "identity_restored_from_disk":true }))
            }
            "garth_sync_account" => {
                #[derive(Deserialize)]
                struct Body {
                    handoff_id: String,
                    realm_id: Option<arkret_wire::RealmId>,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let client = self.garth_clients.get(&body.handoff_id).with_context(|| {
                    format!(
                        "no Garth client for handoff {}; call garth_client_open first",
                        body.handoff_id
                    )
                })?;
                let outcome = client.sync_account_once(body.realm_id).await?;
                Ok(json!({
                    "rounds": outcome.rounds,
                    "cursor": outcome.cursor,
                    "stop_reason": outcome.stop_reason,
                    "projected": outcome.projected,
                    "event_ids": outcome.event_ids,
                }))
            }
            "garth_cursor_after_restart" => {
                #[derive(Deserialize)]
                struct Body {
                    handoff_id: String,
                    realm_id: Option<arkret_wire::RealmId>,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                // Discard the full runtime before reading custody from disk. A
                // missing or invalid snapshot cannot fall back to Session memory.
                drop(self.garth_clients.remove(&body.handoff_id));
                let identity = self.read_identity(&body.handoff_id)?;
                let principal = identity.principal;
                let accepted_grant = principal
                    .outcome
                    .session_grant_outcome
                    .as_ref()
                    .context("durable accepted initial session grant unavailable")?;
                let origin = identity.station_base;
                Box::pin(self.dispatch(Request {
                    id: request.id,
                    op: "garth_client_open".into(),
                    body: json!({
                        "handoff_id":body.handoff_id,"coland_base_url":origin,
                        "account_id":accepted_grant.account_id,"device_id":principal.device_id
                    }),
                }))
                .await?;
                let client = self
                    .garth_clients
                    .get(&body.handoff_id)
                    .context("rebuilt Garth runtime missing")?;
                let cursor = client.cursor().await?;
                let sync = client.sync_account_once(body.realm_id).await?;
                Ok(
                    json!({ "cursor":cursor,"rounds":sync.rounds,"projected":sync.projected,"stop_reason":sync.stop_reason,"identity_restored_from_disk":true }),
                )
            }
            "garth_create_realm"
            | "garth_join_realm"
            | "garth_grant_messages"
            | "garth_send_message"
            | "garth_read_messages"
            | "garth_retained_message" => {
                let handoff_id = request
                    .body
                    .get("handoff_id")
                    .and_then(Value::as_str)
                    .context("handoff_id required")?;
                let client = self
                    .garth_clients
                    .get(handoff_id)
                    .context("Garth runtime not opened")?;
                let field = |name: &str| {
                    request
                        .body
                        .get(name)
                        .cloned()
                        .with_context(|| format!("{name} required"))
                };
                match request.op.as_str() {
                    "garth_create_realm" => {
                        client
                            .create_realm(
                                field("title")?.as_str().context("title must be a string")?,
                            )
                            .await
                    }
                    "garth_join_realm" => {
                        client
                            .join_realm(serde_json::from_value(field("realm_id")?)?)
                            .await
                    }
                    "garth_grant_messages" => {
                        client
                            .grant_messages(
                                serde_json::from_value(field("realm_id")?)?,
                                serde_json::from_value(field("genesis_event_id")?)?,
                                serde_json::from_value(field("subject_account_id")?)?,
                            )
                            .await
                    }
                    "garth_send_message" => {
                        client
                            .send_message(
                                serde_json::from_value(field("realm_id")?)?,
                                serde_json::from_value(field("strand_id")?)?,
                                field("body")?
                                    .as_str()
                                    .context("message body must be a string")?,
                            )
                            .await
                    }
                    "garth_read_messages" => Ok(
                        json!({"messages":client.read_messages(serde_json::from_value(field("realm_id")?)?).await?}),
                    ),
                    "garth_retained_message" => {
                        client
                            .retained_message(serde_json::from_value(field("event_id")?)?)
                            .await
                    }
                    _ => unreachable!(),
                }
            }
            other => bail!("unknown provisioning op {other:?}"),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.garth_clients.clear();
        let _ = std::fs::remove_dir_all(&self.store_root);
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
            serde_json::from_str(&line).context("parse provisioning bridge request")?;
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
