//! Garth driven as a client, in-process, so a TypeScript suite can select it.
//!
//! This is the half that makes a `GarthClient` honest. `provisioning` founds a
//! principal using Garth's *builders*; that is not the client runtime. What
//! runs here is `ArkretClient` over `NativeExecutor` and the durable
//! `FileStore` — Garth's own subscription engine, transport loop and cursor
//! store — so a test that selects `--client-kind=garth` is exercising Garth
//! rather than the harness agreeing with itself.
//!
//! It lives on the light build edge with the rest of test-support, so the
//! browserless lane can drive it without building Inkson.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use arkret_event_draft::{EventSpec, TypedEventDraft};
use arkret_http_client::{Auth, Client as SdkClient, DpopAuth};
use arkret_identifiers::DeviceId;
use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
use arkret_wire::{AccountId, ActorId, Event, EventId, RealmId, ScopeRef, StrandId, event_spec};
use ed25519_dalek::SigningKey;
use garth::{
    AccountRunner, ArkretClient, ClientEvent, ClientProjector, CursorScope, CursorStore,
    EventCacheStore, FileStore, NativeExecutor, OutboundEngine, OutboundEngineOutcome,
    QueuedSubmission, RunOptions, SyncLoopControl, SystemClock, TransportProvider,
};
use serde_json::{Value, json};

/// A Garth client bound to one founded principal.
///
/// The store path is stable for the life of this handle, which is what lets a
/// caller ask for a restart: the same path reopened is a new process's view of
/// the same durable state.
pub struct GarthClientHandle {
    runtime: ArkretClient<SdkClient, FileStore>,
    outbound: OutboundEngine<FileStore, SystemClock>,
    signer: Ed25519DetachedJwsSigner,
    trust_domain: String,
    actor_id: ActorId,
    device_id: DeviceId,
}

/// Transport, identity and durable storage for one founded Garth client.
pub struct GarthClientConfig<'a> {
    pub http: reqwest::Client,
    pub station_base_url: &'a str,
    pub session_grant: String,
    pub signing_key: SigningKey,
    pub account_id: AccountId,
    pub device_id: &'a str,
    pub store_root: &'a Path,
    pub event_signing_key: SigningKey,
    pub event_verification_method: &'a str,
    pub trust_domain: &'a str,
}

/// What one account-sync round did.
#[derive(Debug)]
pub struct SyncOutcome {
    /// Sync requests Garth's engine actually issued.
    pub rounds: usize,
    /// The cursor Garth committed to its durable store, if any.
    pub cursor: Option<String>,
    /// Why the loop stopped. `cancelled` is the expected answer for a bounded
    /// round; anything else means the Station or the session ended it.
    pub stop_reason: String,
    pub projected: usize,
    pub event_ids: Vec<String>,
}

impl GarthClientHandle {
    /// Build a client for a principal the canonical chain already founded.
    ///
    /// The session is DPoP-bound: the grant plus a proof over each request's
    /// own method and URL, signed by the device key the grant was issued to.
    /// Both halves are required, and minting the proof per request is Garth's
    /// transport doing it, not a pre-baked header.
    /// `http` must already trust the run-scoped CA.
    ///
    /// Building a fresh client here instead was the first thing that broke: the
    /// harness terminates TLS with a per-run authority, so a default client
    /// cannot reach the Station at all — and the failure did not look like one.
    /// Garth's loop treats a transport error as retryable, so it backed off and
    /// retried until the bridge's call timeout, which reads as a hang rather
    /// than as "this client cannot connect".
    pub fn new(config: GarthClientConfig<'_>) -> Result<Self> {
        let GarthClientConfig {
            http,
            station_base_url,
            session_grant,
            signing_key,
            account_id,
            device_id,
            store_root,
            event_signing_key,
            event_verification_method,
            trust_domain,
        } = config;
        let signing_key = Arc::new(signing_key);
        let auth = Auth::Dpop(DpopAuth::with_dpop_token(session_grant, move |request| {
            garth::session::dpop::build_http_dpop_proof(request, &signing_key).map_err(|error| {
                arkret_http_client::Error::Protocol(format!("build DPoP proof: {error}"))
            })
        }));
        let method_did = arkret_identity::verification_method_did(event_verification_method)?;
        ensure!(
            arkret_wire::project_did_to_core_id(&method_did)? == account_id.principal_id,
            "Event signer does not belong to the founded Account"
        );
        ensure!(
            event_verification_method.ends_with(&format!("#{device_id}")),
            "Event signer does not belong to the founded Device"
        );
        let station_url =
            url::Url::parse(station_base_url).context("parse the Station base URL")?;
        let mut builder = SdkClient::builder(station_url.clone())
            .auth(auth)
            .http_client(http);
        // The supplied deployment endpoint authorizes only this fixture's local
        // DNS namespace and HTTPS port; public discovery keeps the SDK policy.
        if let Some(host) = station_url.host_str() {
            for namespace in ["local.host", "localhost"] {
                if host == namespace || host.ends_with(&format!(".{namespace}")) {
                    builder = builder.loopback_service_discovery(
                        namespace,
                        station_url
                            .port_or_known_default()
                            .context("Station port missing")?,
                    )?;
                    break;
                }
            }
        }
        let sdk = builder
            .build()
            .context("build the Garth client's Station transport")?;
        std::fs::create_dir_all(store_root).context("create the Garth store directory")?;
        let store_path = store_root.join("account.json");
        let store = FileStore::open(&store_path).map_err(anyhow::Error::msg)?;
        let signer = Ed25519DetachedJwsSigner::new(event_signing_key, event_verification_method);
        Ok(Self {
            runtime: ArkretClient::new(sdk, store.clone()),
            outbound: OutboundEngine::new(store, SystemClock),
            signer,
            trust_domain: trust_domain.to_owned(),
            actor_id: ActorId::account(account_id),
            device_id: DeviceId::new(device_id.to_owned()).map_err(anyhow::Error::msg)?,
        })
    }

    fn scope(&self) -> CursorScope {
        CursorScope::Account {
            service_id: None,
            actor_id: self.actor_id.clone(),
            device_id: self.device_id.clone(),
        }
    }

    /// Run one bounded account-subscribe round through Garth's engine.
    ///
    /// Bounded because the engine's job after the first response is to
    /// long-poll; a caller that waited for the second round would be measuring
    /// the Station's wait window rather than Garth.
    pub async fn sync_account_once(&self, realm_id: Option<RealmId>) -> Result<SyncOutcome> {
        let store = self.runtime.store().clone();
        let control = SyncLoopControl::new();
        let provider = BoundedProvider {
            sdk: self.runtime.authority().transport().clone(),
            control: control.clone(),
            rounds: Arc::new(AtomicUsize::new(0)),
            realm_id,
        };
        let projector = CountingProjector {
            projected: AtomicUsize::new(0),
            event_ids: Mutex::new(Vec::new()),
        };

        let stop = AccountRunner::new(NativeExecutor, store.clone())
            .with_control(control)
            .run(
                &provider,
                &projector,
                self.scope(),
                RunOptions {
                    beat: Duration::from_millis(1),
                    ..RunOptions::default()
                },
            )
            .await;
        let rounds = provider.rounds.load(Ordering::SeqCst);
        let stop = match stop {
            Ok(stop) => stop,
            // The engine classifies an unreachable Station as retryable and
            // would otherwise back off past the caller's timeout, which reads
            // as a hang rather than as the connection failure it is.
            Err(error) => anyhow::bail!("Garth's transport could not reach the Station: {}", error),
        };

        let cursor = store
            .load(self.scope())
            .await
            .map_err(anyhow::Error::msg)?
            .map(|cursor| cursor.to_string());
        Ok(SyncOutcome {
            rounds,
            cursor,
            stop_reason: format!("{stop:?}").to_lowercase(),
            projected: projector.projected.load(Ordering::SeqCst),
            event_ids: projector
                .event_ids
                .into_inner()
                .map_err(|_| anyhow::anyhow!("Garth observer poisoned"))?,
        })
    }

    /// Read the cursor from this runtime. The bridge recreates the entire handle first.
    pub async fn cursor(&self) -> Result<Option<String>> {
        Ok(self.runtime.store().load(self.scope()).await?)
    }

    fn draft<K: EventSpec>(
        &self,
        scope: ScopeRef,
        payload: Value,
    ) -> Result<arkret_wire::AuthoredEvent> {
        self.draft_at::<K>(scope, payload, chrono::Utc::now())
    }

    fn draft_at<K: EventSpec>(
        &self,
        scope: ScopeRef,
        payload: Value,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<arkret_wire::AuthoredEvent> {
        let payload = serde_json::from_value::<K::Payload>(payload)?;
        Ok(
            TypedEventDraft::<K>::new(scope, self.actor_id.clone(), payload)?
                .author_with_digest_suite(created_at, arkret_canonical::DigestSuite::Sha256)?,
        )
    }

    fn signed<K: EventSpec>(&self, scope: ScopeRef, payload: Value) -> Result<Event> {
        let mut event = self.draft::<K>(scope, payload)?;
        sign_event(&mut event, &self.signer, SignEventOptions::default())?;
        Ok(event.into_event())
    }

    async fn submit(&self, submission: QueuedSubmission) -> Result<garth::SendQueueItem> {
        let expected = submission.event_id.clone();
        self.outbound.enqueue(submission).await?;
        match self
            .outbound
            .submit_next(self.runtime.authority(), &Default::default())
            .await?
        {
            OutboundEngineOutcome::Committed { item, .. } if item.event_id() == &expected => {
                Ok(*item)
            }
            OutboundEngineOutcome::Rejected { reason_code, .. } => {
                // Queue items retain signed private payloads; diagnostics only
                // expose a registered refusal, never the item or response text.
                let code = if let Some(code) = arkret_wire::ErrorCode::from_wire(&reason_code) {
                    code.as_str().to_owned()
                } else {
                    match arkret_wire::ReasonCode::from_wire(&reason_code) {
                        arkret_wire::ReasonCode::Unknown(_) => "unregistered_refusal".to_owned(),
                        code => code.as_str().to_owned(),
                    }
                };
                anyhow::bail!("Garth outbound refused the requested Event: {code}")
            }
            OutboundEngineOutcome::Failed { problem, .. } => {
                let code = problem
                    .as_ref()
                    .and_then(|problem| problem.error_code())
                    .map(|code| code.as_str())
                    .unwrap_or("local_or_unregistered_failure");
                let status = problem.as_ref().map(|problem| problem.status);
                anyhow::bail!("Garth outbound failed the requested Event: {code}, HTTP {status:?}")
            }
            OutboundEngineOutcome::Retry { .. } => {
                anyhow::bail!("Garth outbound queued the requested Event for retry")
            }
            OutboundEngineOutcome::Idle => {
                anyhow::bail!("Garth outbound has no due requested Event")
            }
            OutboundEngineOutcome::Committed { .. } => {
                anyhow::bail!("Garth outbound committed a different Event")
            }
        }
    }

    async fn submit_event(&self, event: Event) -> Result<garth::SendQueueItem> {
        self.submit(QueuedSubmission::new(
            arkret_wire::AuthoritySubmitRequest::Event(arkret_wire::EventAdmissionSubmission::new(
                event,
            )),
        )?)
        .await
    }

    /// Closed SDK EventSpecs for external business consumers of this bridge.
    /// Payload parsing happens before authoring, and the normal persistent
    /// outbound engine remains the only submitter.
    pub async fn submit_typed_event(
        &self,
        realm: RealmId,
        kind: &str,
        payload: Value,
        semantic_refs: Vec<arkret_wire::SemanticRef>,
    ) -> Result<Value> {
        let scope = ScopeRef::Realm { realm_id: realm };
        macro_rules! author {
            ($spec:ty) => {{
                let payload = serde_json::from_value::<<$spec as EventSpec>::Payload>(payload)?;
                let mut event =
                    TypedEventDraft::<$spec>::new(scope, self.actor_id.clone(), payload)?
                        .with_semantic_refs(semantic_refs)
                        .author_with_digest_suite(
                            chrono::Utc::now(),
                            arkret_canonical::DigestSuite::Sha256,
                        )?;
                sign_event(&mut event, &self.signer, SignEventOptions::default())?;
                event.into_event()
            }};
        }
        let event = match kind {
            "ak.invite.create" => author!(event_spec::InviteCreate),
            "ak.invite.third_party" => author!(event_spec::InviteThirdParty),
            "ak.invite.claim" => author!(event_spec::InviteClaim),
            "ak.invite.accept" => author!(event_spec::InviteAccept),
            "ak.invite.revoke" => author!(event_spec::InviteRevoke),
            "ak.realm.join_rule" => author!(event_spec::RealmJoinRule),
            "ak.realm.policy_bundle" => author!(event_spec::RealmPolicyBundle),
            "ak.capability.grant" => author!(event_spec::CapabilityGrant),
            "ak.capability.revoke" => author!(event_spec::CapabilityRevoke),
            "ak.member.state" => author!(event_spec::MemberState),
            _ => anyhow::bail!("business bridge does not recognize this SDK EventSpec"),
        };
        let signed = event.clone();
        let item = self.submit_event(event).await?;
        Ok(json!({"event":signed,"commit":item.commit(),"event_id":item.event_id()}))
    }

    /// Registered SDK reader over the original DPoP-bound Garth transport.
    pub async fn third_party_invite_acceptance_attestation(
        &self,
        request: &arkret_models_collaboration::governance::third_party_invite::ThirdPartyInviteAcceptanceAttestationRequestBody,
    ) -> Result<Value> {
        let outcome = self
            .runtime
            .authority()
            .transport()
            .third_party_invite_acceptance_attestation(request)
            .await?;
        Ok(serde_json::to_value(outcome)?)
    }

    /// Found a normal plaintext collaboration Realm through Garth's durable queue.
    /// The explicitly declared Station receives plaintext; this does not claim MLS coverage.
    pub async fn create_realm(&self, title: &str) -> Result<Value> {
        let salt = arkret::GenesisSalt::generate()?;
        let station = &self
            .actor_id
            .as_account_id()
            .context("Human Account required")?
            .station_id;
        let genesis = self.signed::<event_spec::RealmCreate>(ScopeRef::RealmGenesis, json!({"object": {
            "schema": "ak.schema.realm_genesis.v1", "purpose": "collaboration", "genesis_salt": salt,
            "trust_domain": self.trust_domain, "security_class": "standard", "governance_station_id": station,
            "initial_join_rule": "public", "initial_history_access": "all_history_for_current_members",
            "initial_discoverability": "listed"
        }}))?;
        let realm_id = genesis.realm_id.clone();
        let genesis_id = genesis.event_id.clone();
        let scope = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let mut events = vec![arkret_wire::EventAdmissionSubmission::new(genesis)];
        macro_rules! slot {
            ($kind:ty, $payload:expr) => {
                events.push(arkret_wire::EventAdmissionSubmission::new({
                    let mut event = TypedEventDraft::<$kind>::new(
                        scope.clone(),
                        self.actor_id.clone(),
                        serde_json::from_value($payload)?,
                    )?
                    .with_authorization_ref(genesis_id.clone().into())
                    .author_with_digest_suite(
                        chrono::Utc::now(),
                        arkret_canonical::DigestSuite::Sha256,
                    )?;
                    sign_event(&mut event, &self.signer, SignEventOptions::default())?;
                    event.into_event()
                }));
            };
        }
        slot!(
            event_spec::RealmProfile,
            json!({"schema":"ak.schema.realm_profile.v1","title":title})
        );
        slot!(
            event_spec::RealmPolicyBundle,
            json!({"policy_revision":1,"federation_policy":"restricted"})
        );
        slot!(event_spec::RealmJoinRule, json!({"value":"public"}));
        slot!(
            event_spec::RealmHistoryAccess,
            json!({"from":null,"to":"all_history_for_current_members"})
        );
        slot!(
            event_spec::RealmDiscovery,
            json!({"value":{"discoverability":"listed"}})
        );
        slot!(
            event_spec::RealmPlaintextVisibleServices,
            json!({"services":[{
                "service_id":station,"service_kind":"station","purposes":["message_index"],
                "data_classes":["message_content"],"visibility":"private_plaintext"
            }]})
        );
        slot!(
            event_spec::MemberState,
            json!({"member_id":self.actor_id,"membership":"join"})
        );
        let request_id =
            arkret_wire::RequestId::new_v7_at(chrono::Utc::now().timestamp_millis() as u64);
        let unit = arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission {
            unit_kind: arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
            idempotency_key: arkret_wire::UuidV7::new(request_id.uuid())?,
            events,
        };
        self.submit(QueuedSubmission::realm_bootstrap(unit)?)
            .await?;
        let strand_created_at = chrono::Utc::now();
        let mut strand = self.draft_at::<event_spec::StrandCreate>(scope.clone(), json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":realm_id,
            "tracks":{"discussion":{"enabled":true,"is_primary":true,"profile":"discussion"}},
            "created_by":self.actor_id,"created_at":arkret_canonical::format_timestamp_canonical(strand_created_at)
        }}), strand_created_at)?;
        sign_event(&mut strand, &self.signer, SignEventOptions::default())?;
        let strand = strand.into_event();
        let strand_id = StrandId::from_event_id(&strand.event_id);
        self.submit_event(strand).await?;
        self.submit_event(self.signed::<event_spec::RealmSetDefaultStrand>(
            scope,
            json!({
                "realm_id":realm_id,"strand_id":strand_id
            }),
        )?)
        .await?;
        Ok(json!({"realm_id":realm_id,"strand_id":strand_id,"genesis_event_id":genesis_id}))
    }

    pub async fn join_realm(&self, realm_id: RealmId) -> Result<Value> {
        let item = self
            .submit_event(self.signed::<event_spec::MemberState>(
                ScopeRef::Realm { realm_id },
                json!({"member_id":self.actor_id,"membership":"join"}),
            )?)
            .await?;
        Ok(serde_json::to_value(item.commit())?)
    }

    /// Membership conveys no write capability; the root controller grants the exact action
    /// separately.
    pub async fn grant_messages(
        &self,
        realm_id: RealmId,
        genesis: EventId,
        subject: AccountId,
    ) -> Result<Value> {
        let item = self.submit_event(self.signed::<event_spec::CapabilityGrant>(ScopeRef::Realm { realm_id: realm_id.clone() },
            json!({"grant":{
                "schema":"ak.schema.capability.v1","realm_id":realm_id,"issuer_id":self.actor_id,
                "subject":ActorId::account(subject),"actions":["ak.message.create"],
                "resources":[{"kind":"realm","realm_id":realm_id}],
                "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm_id,"authority_event_ref":genesis,"authority_generation":0}],
                "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
            }}))?).await?;
        Ok(serde_json::to_value(item.commit())?)
    }

    pub async fn send_message(
        &self,
        realm_id: RealmId,
        strand_id: StrandId,
        body: &str,
    ) -> Result<Value> {
        let event = self.draft::<event_spec::MessageCreate>(ScopeRef::Realm { realm_id }, json!({
            "strand_id":strand_id,"track_name":"discussion","content":{"kind":"ak.content.text","body":body}
        }))?;
        let frozen = garth::MessageAuthoringSession::from_authored_event(event)?
            .sign(&self.signer, SignEventOptions::default())?;
        let item = self.submit(frozen.into_queued_submission()).await?;
        Ok(
            json!({"event_id":item.event_id(),"commit_id":item.commit().context("committed message missing Commit")?.commit_id}),
        )
    }

    /// Fetch and authenticate a complete prefix through Garth's RealmReplica.
    /// Local queue contents and cached ids never supply network read authority.
    pub async fn read_messages(
        &self,
        realm_id: RealmId,
    ) -> Result<Vec<arkret_wire::CommittedEventFullView>> {
        use sha2::Digest as _;
        let nonce = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            sha2::Sha256::digest(format!(
                "{}:{}",
                realm_id,
                chrono::Utc::now()
                    .timestamp_nanos_opt()
                    .context("clock out of range")?
            )),
        ))
        .map_err(anyhow::Error::msg)?;
        let request = arkret_wire::AuthorityBundleRequest {
            realm_id: realm_id.clone(),
            nonce: nonce.clone(),
        };
        let authority = self.runtime.authority();
        let http = authority.transport();
        let bundle = authority.resolve_authority(&request).await?;
        let freshness = arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), nonce);
        let keys = garth::fetch_historical_station_key_directory(http, &bundle, None, None).await?;
        let mut replica = garth::RealmReplica::new(realm_id.clone());
        replica.install_verified_authority(&request, bundle.clone(), &freshness, &keys)?;
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let mut after = None;
        let mut messages = Vec::new();
        loop {
            let scan = arkret_wire::StreamScanRequest {
                realm_id: realm_id.clone(),
                stream_ref: stream.clone(),
                direction: arkret_wire::StreamScanDirection::After(after),
                limit: 100,
            };
            let page = authority.scan(&scan).await?;
            let truncated = page.truncated;
            let keys =
                garth::fetch_historical_station_key_directory(http, &bundle, Some(&page), None)
                    .await?;
            let verified = replica.apply_verified_scan(&scan, page, &freshness, &keys)?;
            for row in verified.into_rows() {
                if let arkret_wire::CommittedEventView::Full(full) = row
                    && full.event.kind == arkret_wire::EventKind::MessageCreate
                {
                    messages.push(full);
                }
            }
            let next = replica
                .verified_head(&stream)
                .context("scan produced no authenticated head")?
                .stream_position;
            ensure!(
                after.is_none_or(|previous| next > previous) || !truncated,
                "scan did not advance"
            );
            after = Some(next);
            if !truncated {
                break;
            }
        }
        // Validate each original Human producer against its exact accepted historical signer fact.
        // A current-key lookup cannot establish the signer of an already committed message.
        for full in &messages {
            let query: arkret_models_identity::SignerKeysQueryRequestBody = serde_json::from_value(
                crate::wire::historical_human_signer_query(
                    json!({"event":full.event,"commit":full.commit,
                    "recipient_account_id":self.actor_id.as_account_id().context("recipient Account unavailable")?}),
                )?,
            )?;
            let outcome = http.signer_keys_query(&query).await?;
            crate::wire::historical_human_signer_fact(
                json!({"event":full.event,"commit":full.commit,"query":query,"outcome":outcome}),
            )?;
        }
        for full in &messages {
            self.runtime
                .store()
                .remember(full.event.event_id.clone())
                .await?;
        }
        Ok(messages)
    }

    pub async fn retained_message(&self, event_id: EventId) -> Result<Value> {
        let snapshot = self.outbound.snapshot().await?;
        let item = snapshot
            .items
            .iter()
            .find(|item| item.event_id() == &event_id)
            .context("message is absent from the reopened durable Garth queue")?;
        ensure!(
            item.status == garth::SendQueueStatus::Committed,
            "retained message is not committed"
        );
        Ok(
            json!({"event":item.submission.primary_event(),"commit":item.commit(),
            "seen":self.runtime.store().seen(event_id).await?}),
        )
    }
}

/// Hands the engine the harness's own CA-trusting Station client, and closes
/// the loop after the first attempt whatever its outcome.
struct BoundedProvider {
    sdk: SdkClient,
    control: SyncLoopControl,
    rounds: Arc<AtomicUsize>,
    realm_id: Option<RealmId>,
}

impl TransportProvider for BoundedProvider {
    type Transport = SdkClient;

    async fn provide(&self) -> garth::Result<SdkClient> {
        self.rounds.fetch_add(1, Ordering::SeqCst);
        self.control.cancel();
        Ok(self.sdk.clone())
    }

    fn account_request(&self, after: Option<String>) -> garth::Result<garth::SyncRequestBody> {
        // Account-global catchup does not request Realm stream details. The
        // host's exact demand must be repeated when resuming its durable
        // cursor; it cannot be inferred from a previous historical read.
        Ok(garth::SyncRequestBody {
            catchup: Some(after.is_none()),
            after,
            filter: self.realm_id.as_ref().map(|realm_id| garth::AccountFilter {
                realm_ids: Some(vec![realm_id.clone()]),
                stream_refs: Some(vec![arkret_wire::CommitStreamRef::Realm {
                    realm_id: realm_id.clone(),
                }]),
                window_limit: Some(100),
                ..garth::AccountFilter::default()
            }),
            ..garth::SyncRequestBody::default()
        })
    }
}

/// Counts what the engine decoded, so a round that returned nothing is
/// distinguishable from one that never ran.
#[derive(Debug)]
struct CountingProjector {
    projected: AtomicUsize,
    event_ids: Mutex<Vec<String>>,
}

impl ClientProjector for CountingProjector {
    async fn project(&self, batch: Vec<ClientEvent>) -> garth::Result<()> {
        for event in &batch {
            if let ClientEvent::Committed(delta) = event {
                self.event_ids
                    .lock()
                    .map_err(|_| {
                        garth::Error::Protocol("subscription observation lock poisoned".into())
                    })?
                    .push(delta.commit().event_ref.to_string());
            }
        }
        self.projected.fetch_add(batch.len(), Ordering::SeqCst);
        Ok(())
    }
}
