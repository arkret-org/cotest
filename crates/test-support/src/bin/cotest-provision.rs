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
use cotest_test_support::agent_runtime::{AgentRuntimeHandle, controller_transport};
use cotest_test_support::garth_client::{GarthClientConfig, GarthClientHandle};
use cotest_test_support::provisioning::{
    AccountHandoff, DeploymentEndpoints, FoundPrincipalRequest, FoundedPrincipal,
    FoundingDeviceKey, MockEmailInbox, PreparedPrincipalRegistration, UnboundAccount,
    authorize_with_current_account, create_account_handoff, describe_station,
    prepare_principal_registration, provision_unbound_account, read_self_account_viewer,
    submit_prepared_principal_registration,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

type OperationFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value>> + 'a>>;

// Run child-future construction outside the operation's poll frame.
#[inline(never)]
fn heap_operation<'a, T: 'a, F: std::future::Future<Output = T> + 'a>(
    make: impl FnOnce() -> F,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>> {
    Box::pin(make())
}

fn required_field(body: &Value, name: &str) -> Result<Value> {
    body.get(name)
        .cloned()
        .with_context(|| format!("{name} required"))
}

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

/// Original private holder and SDK request, written before the registration HTTP call.
/// This is test-run custody, never a product vault or a new wire carrier.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableRegistration {
    prepared: PreparedPrincipalRegistration,
    request_id: String,
    account_subject: arkret_identifiers::Hash,
    account_handoff_grant: String,
    expires_at: String,
    binding: Value,
    session_signing_seed_b64url: String,
}

impl DurableRegistration {
    fn handoff(&self) -> Result<AccountHandoff> {
        Ok(AccountHandoff {
            request_id: self.request_id.clone(),
            account_subject: self.account_subject.clone(),
            account_handoff_grant: self.account_handoff_grant.clone(),
            expires_at: self.expires_at.clone(),
            binding: self.binding.clone(),
            device_key: FoundingDeviceKey::restore(&self.session_signing_seed_b64url)?,
        })
    }
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
    agent_runtimes: HashMap<String, AgentRuntimeHandle>,
    store_root: std::path::PathBuf,
    session_id: String,
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
        let reopened_id = std::env::var("COTEST_PROVISION_SESSION_ID").ok();
        let run_id = match &reopened_id {
            Some(id) => arkret_wire::RequestId::new(id.clone()).map_err(anyhow::Error::msg)?,
            None => arkret_wire::RequestId::new_v7_at(chrono::Utc::now().timestamp_millis() as u64),
        };
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
        if reopened_id.is_none() {
            std::fs::create_dir(&store_root)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&store_root, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        validate_private_path(&store_root, true)?;
        Ok(Self {
            http,
            handoffs: HashMap::new(),
            session_grants: HashMap::new(),
            garth_clients: HashMap::new(),
            agent_runtimes: HashMap::new(),
            store_root,
            session_id: run_id.as_str().to_owned(),
        })
    }

    fn identity_path(&self, handoff_id: &str) -> std::path::PathBuf {
        self.store_root
            .join(sanitize_path_component(handoff_id))
            .join("accepted-identity.json")
    }

    fn private_path(&self, handoff_id: &str, name: &str) -> Result<std::path::PathBuf> {
        arkret_wire::RequestId::new(handoff_id.to_owned()).map_err(anyhow::Error::msg)?;
        validate_private_path(&self.store_root, true)?;
        Ok(self
            .store_root
            .join(sanitize_path_component(handoff_id))
            .join(name))
    }

    fn persist_private<T: Serialize>(&self, handoff_id: &str, name: &str, value: &T) -> Result<()> {
        let path = self.private_path(handoff_id, name)?;
        let directory = path.parent().context("custody directory absent")?;
        if !directory.exists() {
            std::fs::create_dir(directory)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        validate_private_path(directory, true)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .context("create private registration custody")?;
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        // The filename must survive the same process crash as its contents.
        #[cfg(unix)]
        std::fs::File::open(directory)?.sync_all()?;
        Ok(())
    }

    fn read_private<T: serde::de::DeserializeOwned>(
        &self,
        handoff_id: &str,
        name: &str,
    ) -> Result<T> {
        let path = self.private_path(handoff_id, name)?;
        validate_private_path(path.parent().context("custody parent absent")?, true)?;
        validate_private_path(&path, false)?;
        let bytes = std::fs::read(&path)?;
        serde_json::from_slice(&bytes).context("decode private registration custody")
    }

    fn persist_identity(&self, handoff_id: &str, identity: &DurableIdentity) -> Result<()> {
        self.persist_private(handoff_id, "accepted-identity.json", identity)
    }

    fn read_identity(&self, handoff_id: &str) -> Result<DurableIdentity> {
        self.read_private(handoff_id, "accepted-identity.json")
            .context("durable accepted identity snapshot unavailable")
    }

    /// Private test IPC consumes the already accepted controller fixture.
    /// Runtime/DPoP keys are generated in Rust and only an opaque handle leaves.
    async fn open_agent_runtime(&mut self, value: Value) -> Result<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            station_base_url: String,
            coauth_base_url: String,
            controller_account_id: arkret_wire::AccountId,
            controller_grant: String,
            controller_holder_seed: String,
            controller_event_seed: String,
            controller_verification_method: arkret_wire::DidUrl,
            agent_id: arkret_wire::DidCoreId,
            strand_id: arkret_wire::StrandId,
        }
        fn key(seed: &str) -> Result<ed25519_dalek::SigningKey> {
            let bytes = arkret_canonical::base64url_decode(seed)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid private key length"))?;
            Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
        }
        let body: Body = serde_json::from_value(value)?;
        let controller = controller_transport(
            self.http.clone(),
            &body.station_base_url,
            body.controller_grant,
            key(&body.controller_holder_seed)?,
        )?;
        let runtime_id =
            arkret_wire::RequestId::new_v7_at(chrono::Utc::now().timestamp_millis() as u64);
        let store = self
            .store_root
            .join("agent-runtime")
            .join(sanitize_path_component(runtime_id.as_str()));
        let runtime = AgentRuntimeHandle::pair(
            self.http.clone(),
            &body.station_base_url,
            &body.coauth_base_url,
            &controller,
            &body.controller_account_id,
            &body.controller_verification_method,
            &key(&body.controller_event_seed)?,
            body.agent_id,
            body.strand_id,
            &store,
        )
        .await?;
        let authorization = runtime.authorization.clone();
        self.agent_runtimes
            .insert(runtime_id.as_str().to_owned(), runtime);
        Ok(json!({"runtime_id":runtime_id,"authorization_event_id":authorization}))
    }

    fn garth_client_for_body(&self, body: &Value) -> Result<&GarthClientHandle> {
        let handoff_id = body
            .get("handoff_id")
            .and_then(Value::as_str)
            .context("handoff_id required")?;
        self.garth_clients
            .get(handoff_id)
            .context("Garth runtime not opened")
    }

    #[inline(never)]
    fn garth_create_realm(&self, body: Value) -> OperationFuture<'_> {
        heap_operation(|| async move {
            let client = self.garth_client_for_body(&body)?;
            let title = required_field(&body, "title")?;
            let title = title.as_str().context("title must be a string")?;
            heap_operation(|| client.create_realm(title)).await
        })
    }

    #[inline(never)]
    fn garth_join_realm(&self, body: Value) -> OperationFuture<'_> {
        heap_operation(|| async move {
            let client = self.garth_client_for_body(&body)?;
            let realm = serde_json::from_value(required_field(&body, "realm_id")?)?;
            heap_operation(|| client.join_realm(realm)).await
        })
    }

    #[inline(never)]
    fn garth_grant_messages(&self, body: Value) -> OperationFuture<'_> {
        heap_operation(|| async move {
            let client = self.garth_client_for_body(&body)?;
            let realm = serde_json::from_value(required_field(&body, "realm_id")?)?;
            let genesis = serde_json::from_value(required_field(&body, "genesis_event_id")?)?;
            let subject = serde_json::from_value(required_field(&body, "subject_account_id")?)?;
            heap_operation(|| client.grant_messages(realm, genesis, subject)).await
        })
    }

    #[inline(never)]
    fn garth_send_message(&self, body: Value) -> OperationFuture<'_> {
        heap_operation(|| async move {
            let client = self.garth_client_for_body(&body)?;
            let realm = serde_json::from_value(required_field(&body, "realm_id")?)?;
            let strand = serde_json::from_value(required_field(&body, "strand_id")?)?;
            let text = required_field(&body, "body")?;
            let text = text.as_str().context("message body must be a string")?;
            heap_operation(|| client.send_message(realm, strand, text)).await
        })
    }

    #[inline(never)]
    fn garth_read_messages(&self, body: Value) -> OperationFuture<'_> {
        heap_operation(|| async move {
            let client = self.garth_client_for_body(&body)?;
            let realm = serde_json::from_value(required_field(&body, "realm_id")?)?;
            Ok(json!({"messages": heap_operation(|| client.read_messages(realm)).await?}))
        })
    }

    #[inline(never)]
    fn garth_retained_message(&self, body: Value) -> OperationFuture<'_> {
        heap_operation(|| async move {
            let client = self.garth_client_for_body(&body)?;
            let event = serde_json::from_value(required_field(&body, "event_id")?)?;
            heap_operation(|| client.retained_message(event)).await
        })
    }

    // Separate operation state machines keep founding and restored-identity
    // temporaries out of the same poll frame on default native thread stacks.
    fn dispatch(
        &mut self,
        request: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value>> + '_>> {
        match request.op.as_str() {
            "agent_runtime_pair" => Box::pin(async move {
                self.open_agent_runtime(request.body)
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!(
                            cotest_test_support::agent_runtime::runtime_pair_error_summary(&error)
                        )
                    })
            }),
            "agent_runtime_issue_current_session" => Box::pin(async move {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Body {
                    runtime_id: String,
                }
                let result = async {
                    let body: Body = serde_json::from_value(request.body)?;
                    self.agent_runtimes
                        .get_mut(&body.runtime_id)
                        .context("runtime unavailable")?
                        .issue_current_content_session()
                        .await?;
                    Ok::<_, anyhow::Error>(json!({"issued": true}))
                }
                .await;
                result.map_err(|_| anyhow::anyhow!("Agent fresh content session issuance failed"))
            }),
            "agent_runtime_prepare_message" => Box::pin(async move {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Body {
                    runtime_id: String,
                    realm_id: arkret_wire::RealmId,
                    strand_id: arkret_wire::StrandId,
                    text: String,
                }
                let result = async {
                    let body: Body = serde_json::from_value(request.body)?;
                    let runtime = self
                        .agent_runtimes
                        .get(&body.runtime_id)
                        .context("runtime unavailable")?;
                    let event = runtime
                        .prepare_message(body.realm_id, body.strand_id, &body.text)
                        .await?;
                    Ok::<_, anyhow::Error>(json!({"event_id":event}))
                }
                .await;
                result.map_err(|_| anyhow::anyhow!("Agent message preparation failed"))
            }),
            "agent_runtime_submit_message" => Box::pin(async move {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Body {
                    runtime_id: String,
                    event_id: arkret_wire::EventId,
                }
                let result = async {
                    let body: Body = serde_json::from_value(request.body)?;
                    self.agent_runtimes
                        .get(&body.runtime_id)
                        .context("runtime unavailable")?
                        .submit_message(body.event_id)
                        .await
                }
                .await;
                result.map_err(|_| {
                    anyhow::anyhow!("Agent message submission or exact read-back failed")
                })
            }),
            "custody_session" => Box::pin(async move {
                Ok(json!({ "session_id": self.session_id, "pid": std::process::id() }))
            }),
            "registration_custody" => Box::pin(async move {
                use sha2::Digest;
                let id = request
                    .body
                    .get("handoff_id")
                    .and_then(Value::as_str)
                    .context("handoff_id required")?;
                let durable: DurableRegistration =
                    self.read_private(id, "prepared-registration.json")?;
                anyhow::ensure!(
                    durable.request_id == id,
                    "custody handoff address differs from original request"
                );
                Ok(
                    json!({"request_digest": hex::encode(sha2::Sha256::digest(serde_json::to_vec(&durable.prepared.register_body)?)),
                    "accepted_persisted":self.identity_path(id).exists()}),
                )
            }),
            "recover_principal" => Box::pin(async move {
                let id = request
                    .body
                    .get("handoff_id")
                    .and_then(Value::as_str)
                    .context("handoff_id required")?;
                let durable: DurableRegistration =
                    self.read_private(id, "prepared-registration.json")?;
                anyhow::ensure!(
                    durable.request_id == id,
                    "custody handoff address differs from original request"
                );
                let handoff = durable.handoff()?;
                let principal =
                    submit_prepared_principal_registration(&self.http, &durable.prepared, &handoff)
                        .await?;
                let identity = DurableIdentity {
                    principal,
                    trust_domain: durable.prepared.trust_domain,
                    station_base: durable.prepared.station_base,
                    coauth_base: durable.prepared.coauth_base,
                    session_signing_seed_b64url: durable.session_signing_seed_b64url,
                };
                // A completed local checkpoint is never silently overwritten by replay.
                if self.identity_path(id).exists() {
                    let prior = self.read_identity(id)?;
                    anyhow::ensure!(
                        serde_json::to_value(&prior.principal.outcome)?
                            == serde_json::to_value(&identity.principal.outcome)?,
                        "exact replay changed original accepted outcome"
                    );
                } else {
                    self.persist_identity(id, &identity)?;
                }
                Ok(principal_response(&identity.principal))
            }),
            "describe_station" => Box::pin(async move {
                let endpoints: DeploymentEndpoints =
                    serde_json::from_value::<EndpointsBody>(request.body)
                        .context("parse endpoints")?
                        .into();
                let facts = describe_station(&self.http, &endpoints).await?;
                Ok(json!({
                    "trust_domain": facts.trust_domain,
                    "service_id": facts.service_id,
                }))
            }),
            "provision_unbound_account" => Box::pin(async move {
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
            }),
            "create_account_handoff" => Box::pin(async move {
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
            }),
            "found_principal" => Box::pin(async move {
                #[derive(Deserialize)]
                struct Body {
                    handoff_id: String,
                    coauth_base_url: String,
                    coland_base_url: String,
                    trust_domain: String,
                    audience_id: String,
                    device_id: String,
                    display_name: String,
                    #[serde(default)]
                    stop_after_accept: bool,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let handoff = self
                    .handoffs
                    .get(&body.handoff_id)
                    .with_context(|| format!("no handoff {} in this session", body.handoff_id))?;
                let prepared = prepare_principal_registration(
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
                self.persist_private(
                    &body.handoff_id,
                    "prepared-registration.json",
                    &DurableRegistration {
                        prepared: prepared.clone(),
                        request_id: handoff.request_id.clone(),
                        account_subject: handoff.account_subject.clone(),
                        account_handoff_grant: handoff.account_handoff_grant.clone(),
                        expires_at: handoff.expires_at.clone(),
                        binding: handoff.binding.clone(),
                        session_signing_seed_b64url: handoff.device_key.seed_b64url.clone(),
                    },
                )?;
                let principal =
                    submit_prepared_principal_registration(&self.http, &prepared, handoff).await?;
                if body.stop_after_accept {
                    // The service accepted the exact request, but the host has not
                    // retained any outcome/grant. The caller now SIGKILLs this process.
                    return Ok(json!({"accepted_before_persist":true,
                        "outcome":principal.outcome,"pid":std::process::id()}));
                }
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
                Ok(principal_response(&principal))
            }),
            "read_self_account_viewer" => Box::pin(async move {
                #[derive(Deserialize)]
                struct Body {
                    handoff_id: String,
                    coland_base_url: String,
                }
                let body: Body = serde_json::from_value(request.body).context("parse request")?;
                let identity = self.read_identity(&body.handoff_id)?;
                anyhow::ensure!(
                    identity.station_base == body.coland_base_url,
                    "viewer origin differs from accepted custody"
                );
                let key = FoundingDeviceKey::restore(&identity.session_signing_seed_b64url)?;
                identity
                    .principal
                    .validate_restored(
                        &identity.coauth_base,
                        &identity.station_base,
                        &identity.trust_domain,
                        &key,
                    )
                    .await?;
                let grant = &identity.principal.session_grant().session_grant;
                let read = read_self_account_viewer(&self.http, &body.coland_base_url, grant, &key)
                    .await?;
                Ok(json!({ "status": read.status, "body": read.body }))
            }),
            // --- Garth as a client -------------------------------------------
            //
            // These drive `ArkretClient` itself, not the provisioning builders
            // above. That distinction is the whole point of a `GarthClient`
            // being selectable: a suite asking for Garth must get Garth's
            // runtime, not the harness reproducing what it would have done.
            "garth_client_open" => Box::pin(async move {
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
            }),
            "sign_invite_subject" => Box::pin(async move {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Body {
                    handoff_id: String, invite_id: String, realm_id: String,
                    token_commitment: String, claim_nonce: String, verification_id: String,
                    binding_proof: arkret_models_collaboration::governance::membership_invite::InviteClaimBindingProof,
                }
                let body: Body = serde_json::from_value(request.body)?;
                let identity = self.read_identity(&body.handoff_id)?;
                let holder = FoundingDeviceKey::restore(&identity.session_signing_seed_b64url)?;
                identity
                    .principal
                    .validate_restored(
                        &identity.coauth_base,
                        &identity.station_base,
                        &identity.trust_domain,
                        &holder,
                    )
                    .await?;
                let checkpoint = &identity.principal.checkpoint;
                cotest_test_support::wire::invite_subject_proof(json!({
                    "subject_account_id":identity.principal.account_id(), "invite_id":body.invite_id,
                    "realm_id":body.realm_id,"token_commitment":body.token_commitment,
                    "claim_nonce":body.claim_nonce,"verification_id":body.verification_id,
                    "binding_proof":body.binding_proof,
                    "verification_method":checkpoint.get("root_verification_method").context("original native root method absent")?,
                    "subject_did":identity.principal.did,
                    "root_public_key_multibase":checkpoint.get("root_public_key_multibase").context("original native root key absent")?,
                    "recovery_key":identity.principal.recovery_key,
                }))
            }),
            "sign_third_party_invite_provision" => Box::pin(async move {
                use arkret_models_collaboration::governance::third_party_invite::{
                    ThirdPartyInviteDeliveryTargetUri, ThirdPartyInviteOobKind,
                    ThirdPartyInviteProvisionRequestBody,
                };
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Body {
                    handoff_id: String,
                    request_id: arkret_wire::RequestId,
                    realm_id: arkret_wire::RealmId,
                    verification_id: arkret_wire::DidCoreId,
                    oob_code_kind: ThirdPartyInviteOobKind,
                    delivery_target_uri: ThirdPartyInviteDeliveryTargetUri,
                    expires_at: String,
                    created_at: Option<String>,
                    domain: String,
                }
                let body: Body = serde_json::from_value(request.body)?;
                let identity = self.read_identity(&body.handoff_id)?;
                let holder = FoundingDeviceKey::restore(&identity.session_signing_seed_b64url)?;
                identity
                    .principal
                    .validate_restored(
                        &identity.coauth_base,
                        &identity.station_base,
                        &identity.trust_domain,
                        &holder,
                    )
                    .await?;
                let seed = identity
                    .principal
                    .checkpoint
                    .get("device_signing_seed_b64url")
                    .and_then(Value::as_str)
                    .context("accepted Device signer absent")?;
                let signer = FoundingDeviceKey::restore(seed)?.signing_key();
                let now = chrono::Utc::now();
                let created_at = body
                    .created_at
                    .as_deref()
                    .map(arkret_canonical::parse_timestamp_canonical)
                    .transpose()?
                    .unwrap_or(now);
                let mut signed = ThirdPartyInviteProvisionRequestBody {
                    request_id: body.request_id,
                    realm_id: body.realm_id,
                    inviter_account_id: identity.principal.account_id().clone(),
                    verification_id: body.verification_id.clone(),
                    oob_code_kind: body.oob_code_kind,
                    delivery_target_uri: body.delivery_target_uri,
                    expires_at: arkret_canonical::parse_timestamp_canonical(&body.expires_at)?,
                    signature: arkret_wire::PayloadProof {
                        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                        verification_method: arkret_wire::DidUrl::new(
                            identity.principal.event_verification_method.clone(),
                        )
                        .map_err(anyhow::Error::msg)?,
                        payload_digest: arkret_wire::Hash::new(format!(
                            "sha256:{}",
                            "0".repeat(64)
                        ))?,
                        created_at,
                        domain: Some(body.domain),
                        audience: Some(arkret_wire::Audience::Single(
                            body.verification_id.to_string(),
                        )),
                        proof_purpose: None,
                        jws: String::new(),
                    },
                };
                signed.signature.payload_digest = signed.payload_digest()?;
                let proof = signed.signature.unsigned();
                let jws = arkret_signatures::proof::sign_ed25519_detached_jws(
                    &signer,
                    &signed.unsigned_proof_binding_bytes(&proof)?,
                )
                .map_err(anyhow::Error::msg)?;
                signed.signature = proof.finalize(jws)?;
                signed.validate_for_service(&body.verification_id)?;
                Ok(serde_json::to_value(signed)?)
            }),
            "third_party_invite_acceptance_attestation" => Box::pin(async move {
                let id = request
                    .body
                    .get("handoff_id")
                    .and_then(Value::as_str)
                    .context("handoff_id required")?;
                let client = self
                    .garth_clients
                    .get(id)
                    .context("Garth runtime not opened")?;
                let body = serde_json::from_value(
                    request
                        .body
                        .get("request")
                        .cloned()
                        .context("typed request required")?,
                )?;
                client
                    .third_party_invite_acceptance_attestation(&body)
                    .await
            }),
            "garth_submit_typed_event" => Box::pin(async move {
                let id = request
                    .body
                    .get("handoff_id")
                    .and_then(Value::as_str)
                    .context("handoff_id required")?;
                let client = self
                    .garth_clients
                    .get(id)
                    .context("Garth runtime not opened")?;
                let realm = serde_json::from_value(
                    request
                        .body
                        .get("realm_id")
                        .cloned()
                        .context("realm_id required")?,
                )?;
                let kind = request
                    .body
                    .get("kind")
                    .and_then(Value::as_str)
                    .context("kind required")?;
                client
                    .submit_typed_event(
                        realm,
                        kind,
                        request
                            .body
                            .get("payload")
                            .cloned()
                            .context("payload required")?,
                        serde_json::from_value(
                            request
                                .body
                                .get("semantic_refs")
                                .cloned()
                                .unwrap_or_else(|| json!([])),
                        )?,
                    )
                    .await
            }),
            "garth_cursor" => Box::pin(async move {
                let id = request
                    .body
                    .get("handoff_id")
                    .and_then(Value::as_str)
                    .context("handoff_id required")?;
                let client = self
                    .garth_clients
                    .get(id)
                    .context("Garth runtime not opened")?;
                Ok(json!({"cursor":client.cursor().await?}))
            }),
            "garth_sync_account" => Box::pin(async move {
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
            }),
            "garth_cursor_after_restart" => Box::pin(async move {
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
                self.dispatch(Request {
                    id: request.id,
                    op: "garth_client_open".into(),
                    body: json!({
                        "handoff_id":body.handoff_id,"coland_base_url":origin,
                        "account_id":accepted_grant.account_id,"device_id":principal.device_id
                    }),
                })
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
            }),
            "garth_create_realm" => self.garth_create_realm(request.body),
            "garth_join_realm" => self.garth_join_realm(request.body),
            "garth_grant_messages" => self.garth_grant_messages(request.body),
            "garth_send_message" => self.garth_send_message(request.body),
            "garth_read_messages" => self.garth_read_messages(request.body),
            "garth_retained_message" => self.garth_retained_message(request.body),
            other => {
                let operation = other.to_owned();
                Box::pin(async move { bail!("unknown provisioning op {operation:?}") })
            }
        }
    }
}

fn validate_private_path(path: &std::path::Path, directory: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).context("private custody unavailable")?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink()
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        "custody must be a regular private path"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "custody permissions must exclude other users"
        );
    }
    anyhow::ensure!(
        directory || metadata.len() <= 8 * 1024 * 1024,
        "custody exceeds private host bound"
    );
    Ok(())
}

fn principal_response(principal: &FoundedPrincipal) -> Value {
    let grant = principal.session_grant();
    json!({
        "principal_id":principal.outcome.principal_id,"did":principal.did,
        "device_id":principal.device_id,"account_id":principal.account_id(),
        "event_verification_method":principal.event_verification_method,
        "recovery_key":principal.recovery_key,
        "session_grant": {"session_grant":grant.session_grant,"session_grant_id":grant.session_grant_id,
            "audience_id":grant.audience_id,"device_id":grant.device_id,"granted_scope":grant.granted_scope,
            "expires_at":arkret_canonical::format_timestamp_canonical(grant.expires_at)},
        "binding_receipt":principal.outcome.binding_receipt,"pcr_genesis_commits":principal.outcome.pcr_genesis_commits,
        "accepted_outcome":principal.outcome,
    })
}

impl Drop for Session {
    fn drop(&mut self) {
        self.garth_clients.clear();
        self.agent_runtimes.clear();
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
