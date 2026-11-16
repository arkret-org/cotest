//! An independent real WebVH Applet producer. Only method-native public DID
//! artifacts are served by this test listener; every business admission is sent
//! to the separately running production Station. No verifier or grant is mocked.

use std::sync::Arc;

use anyhow::{Context as _, Result, ensure};
use arkret_models_integration::*;
use arkret_wire::{
    ActorId, AppletId, Did, DidCoreId, DidUrl, Event, EventId, EventKind, GrantId, RealmId,
    ScopeRef,
};
use ed25519_dalek::SigningKey;
use rand_chacha::rand_core::SeedableRng as _;
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::conn::{Listener, TcpListener};
use salvo::prelude::*;
use serde_json::{Value, json};

use crate::harness::{ArkretServer, expect_json, reserve_port};

#[derive(Clone)]
struct MethodArtifacts {
    log: Arc<Vec<u8>>,
    document: Arc<Vec<u8>>,
}

#[handler]
impl MethodArtifacts {
    async fn handle(&self, req: &mut Request, res: &mut Response) {
        let body = if req.uri().path().ends_with("/did.jsonl") {
            Some((self.log.as_ref(), "application/jsonl"))
        } else if req.uri().path().ends_with("/did.json") {
            Some((self.document.as_ref(), "application/json"))
        } else {
            None
        };
        if let Some((body, media_type)) = body {
            res.headers_mut()
                .insert("content-type", media_type.parse().unwrap());
            if res.write_body(body.clone()).is_err() {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            }
        } else {
            res.status_code(StatusCode::NOT_FOUND);
        }
    }
}

pub(crate) struct RecorderService {
    pub package: AppletPackage,
    pub epoch_evidence: AppletRegistrationEpochEvidence,
    signing_key: SigningKey,
    method: DidUrl,
    did: Did,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RecorderService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RecorderService {
    pub async fn start(station: &ArkretServer) -> Result<Self> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut port = reserve_port()?;
        let base: url::Url = format!("https://127.0.0.1:{}/", port.port()).parse()?;
        let mut entropy = [0; 32];
        getrandom::fill(&mut entropy)?;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(entropy);
        let mut service_seed = [0; 32];
        getrandom::fill(&mut service_seed)?;
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let inception =
            arkret_signatures::webvh::prepare_applet_service_inception_with_did_key_seed(
                &mut rng,
                &arkret_signatures::webvh::ServiceInceptionInput {
                    principal_endpoint: &base,
                    local_id: "recorder",
                    also_known_as: &[],
                    version_created_at: now,
                    did_key_fragment: Some("recorder-key"),
                },
                &service_seed,
            )?;
        let did = Did::new(inception.did.clone())?;
        let service_id = arkret_wire::project_did_to_core_id(&did)?;
        ensure!(
            &service_id != station.service_id(),
            "recorder cannot borrow the Station identity"
        );
        let method = DidUrl::new(inception.did_key_id.clone()).map_err(anyhow::Error::msg)?;
        let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
            service_id.clone(),
            "applet_service".into(),
            serde_json::from_value(inception.log_entry["state"].clone())?,
            vec![inception.log_entry.clone()],
            Vec::new(),
            now,
        )?;
        let epoch_evidence = AppletRegistrationEpochEvidence::from_did_document(
            &resolution.normalized_did_document,
            AppletDidMethodVersionEvidence::versioned(
                "did:webvh",
                Some(
                    resolution
                        .method_history_evidence
                        .boundary()
                        .to_version_id
                        .clone(),
                ),
                None,
            )?,
        )?;
        let mut controller_seed = [0; 32];
        getrandom::fill(&mut controller_seed)?;
        let controller_key = SigningKey::from_bytes(&controller_seed);
        let controller_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            controller_key.verifying_key().as_bytes(),
        );
        let controller = Did::new(format!("did:key:{controller_multibase}"))?;
        let controller_method = DidUrl::new(format!("{controller}#{controller_multibase}"))
            .map_err(anyhow::Error::msg)?;
        let applet = AppletId::new(arkret_identifiers::new_prefixed_uuid7("ak:applet:"))?;
        let mut package = AppletPackage::new(
            "rtc-recorder",
            applet,
            service_id,
            did.clone(),
            arkret_wire::project_did_to_core_id(&controller)?,
            base.as_str().trim_end_matches('/'),
            vec!["arkret.portal".into()],
            AppletWireNamespaces {
                handles: vec![AppletNamespaceEntry::exclusive(format!(
                    "recorder.{}",
                    uuid::Uuid::now_v7().simple()
                ))],
                ..Default::default()
            },
        );
        package.requested_scopes = vec![arkret_wire::CapabilityActionId::CALL_RECORD.into()];
        package.webhook_signature_policy = WebhookSignaturePolicy::http_message_signature(
            method.clone(),
            vec![HttpMessageSignatureAlgorithm::Ed25519],
        );
        package.endpoint_policy = AppletEndpointPolicy {
            endpoints: vec![AppletEndpointEntry {
                method: AppletEndpointMethod::Post,
                path: "/_arkret/edge/applet/transactions".into(),
                authentication_kind: Some(AppletEndpointAuth::WebhookSignature),
                description: None,
                extra: Default::default(),
            }],
            extra: Default::default(),
        };
        package.stamp_registration_epoch(&epoch_evidence)?;
        package.stamp_package_digest()?;
        package.sign(
            &arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
                controller_seed,
                controller,
                controller_method.clone(),
            ),
            &controller_method,
        )?;
        let mut log = arkret_canonical::canonical_json_bytes(&inception.log_entry)?;
        log.push(b'\n');
        let artifacts = MethodArtifacts {
            log: Arc::new(log),
            document: Arc::new(arkret_canonical::canonical_json_bytes(
                &inception.log_entry["state"],
            )?),
        };
        let (cert, tls_key) = station.native_test_tls_identity_paths()?;
        port.release();
        let acceptor = TcpListener::new(format!("127.0.0.1:{}", base.port().unwrap()))
            .rustls(RustlsConfig::new(
                Keycert::new()
                    .cert_from_path(cert)?
                    .key_from_path(tls_key)?,
            ))
            .try_bind()
            .await?;
        let router = Router::new()
            .goal(artifacts.clone())
            .push(Router::with_path("{**rest}").goal(artifacts));
        let task = tokio::spawn(async move {
            Server::new(acceptor).serve(router).await;
        });
        Ok(Self {
            package,
            epoch_evidence,
            signing_key: SigningKey::from_bytes(&service_seed),
            method,
            did,
            task,
        })
    }

    /// Preview and install through the actual standard API. Caller-signed
    /// registration and G2 enter the Station's native atomic install unit.
    pub(crate) async fn installation_request(
        &self,
        station: &ArkretServer,
        member: &crate::scenarios::mls_lifecycle_live::Member,
        realm: &RealmId,
    ) -> Result<(AppletInstallRequestBody, Event, Event)> {
        installation_request_for_package(
            &self.package,
            &self.epoch_evidence,
            station,
            member,
            realm,
            &[],
        )
        .await
    }

    pub async fn install(
        &self,
        station: &ArkretServer,
        member: &crate::scenarios::mls_lifecycle_live::Member,
        realm: &RealmId,
    ) -> Result<(AppletInstallResponseBody, Event, Event)> {
        let (body, registration, grant) = self.installation_request(station, member, realm).await?;
        let response: AppletInstallResponseBody = serde_json::from_value(
            expect_json(
                member
                    .client
                    .post("/_arkret/self/applets/install")
                    .header(
                        "idempotency-key",
                        arkret_identifiers::new_prefixed_uuid7("ak:request:"),
                    )
                    .json(&body),
                reqwest::StatusCode::CREATED,
            )
            .await?,
        )?;
        response.validate()?;
        Ok((response, registration, grant))
    }

    pub fn ready_event(
        &self,
        actor: &ActorId,
        realm: &RealmId,
        grant: &GrantId,
        payload: arkret_models_collaboration::events_payloads::call::CallStatePayload,
    ) -> Result<Event> {
        let unsigned = Event {
            event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0; 32]),
            kind: EventKind::CallState,
            realm_id: realm.clone(),
            scope_ref: ScopeRef::realm(realm.clone()),
            actor_id: actor.clone(),
            executed_by: Some(ActorId::service(self.package.service_id.clone())),
            authorization_ref: Some(
                arkret_wire::AuthorizationRef::new(grant.as_str()).map_err(anyhow::Error::msg)?,
            ),
            applet_id: Some(self.package.applet_id.clone()),
            external_ref: None,
            created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            semantic_refs: Vec::new(),
            payload: serde_json::from_value(serde_json::to_value(payload)?)?,
            producer_proof: None,
        };
        let at = unsigned.created_at;
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            unsigned,
            arkret_canonical::DigestSuite::Sha256,
        )?;
        arkret_signatures::sign_event(
            &mut authored,
            &arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
                self.signing_key.to_bytes(),
                self.did.clone(),
                self.method.clone(),
            ),
            arkret_signatures::SignEventOptions::new().with_created_at(at),
        )?;
        Ok(authored.into_event())
    }

    pub async fn submit(&self, station: &ArkretServer, event: &Event) -> Result<Value> {
        use arkret_models_collaboration::authority_commit::{
            PeerAuthorityForwardEventRequestBody, PeerAuthoritySubmitRequestBody,
        };
        use arkret_signatures::http_signature::{
            Component, ContentDigest, ContentDigestAlgorithm, SignedRequestParts,
            canonical_message, format_signature_input_component_list, parse_signature_input,
            sign_message,
        };
        let body = PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(
            PeerAuthorityForwardEventRequestBody::new(
                arkret_wire::EventAdmissionSubmission::new(event.clone()),
                None,
                None,
                None,
            )?,
        );
        let bytes = arkret_canonical::canonical_json_bytes(&body)?;
        let target = station.url("/_arkret/peer/events");
        let authority = url::Url::parse(&target)?
            [url::Position::BeforeHost..url::Position::AfterPort]
            .to_owned();
        let digest = ContentDigest::compute(&bytes, ContentDigestAlgorithm::Sha256).wire_value;
        let mut headers = vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("content-digest".into(), digest.clone()),
            (
                "source-service-id".into(),
                self.package.service_id.to_string(),
            ),
            (
                "destination-service-id".into(),
                station.service_id().to_string(),
            ),
            (
                "source-trust-domain".into(),
                station.trust_domain().to_string(),
            ),
            (
                "destination-trust-domain".into(),
                station.trust_domain().to_string(),
            ),
            (
                "arkret-operation".into(),
                arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1.into(),
            ),
            (
                "idempotency-key".into(),
                arkret_identifiers::new_prefixed_uuid7("ak:request:"),
            ),
        ];
        let covered = vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
            Component::Header("content-digest".into()),
            Component::Header("source-service-id".into()),
            Component::Header("destination-service-id".into()),
            Component::Header("source-trust-domain".into()),
            Component::Header("destination-trust-domain".into()),
            Component::Header("arkret-operation".into()),
            Component::Header("idempotency-key".into()),
        ];
        let now = chrono::Utc::now().timestamp();
        let input = format!(
            "{};created={now};expires={};keyid=\"{}\";alg=\"ed25519\"",
            format_signature_input_component_list("sig1", &covered)?,
            now + 300,
            self.method
        );
        let base = canonical_message(
            &SignedRequestParts {
                method: "POST".into(),
                target_uri: target.clone(),
                authority,
                path: String::new(),
                headers: headers.clone(),
                body_digest: Some(digest),
            },
            &parse_signature_input(&input)?,
        )?;
        headers.push(("signature-input".into(), input));
        headers.push((
            "signature".into(),
            format!("sig1=:{}:", sign_message(&base, &self.signing_key)),
        ));
        let mut request = station.http().post(target).body(bytes);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        expect_json(request, reqwest::StatusCode::OK).await
    }

    /// Build one real Service-authenticated material read, using the SDK's
    /// canonical RFC 9421 scenario rather than a fixture verification policy.
    pub(crate) fn authority_material_request(
        &self,
        station: &ArkretServer,
        body: &arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialRequestBody,
    ) -> Result<reqwest::RequestBuilder> {
        use arkret_signatures::http_signature::{
            ContentDigest, ContentDigestAlgorithm, HttpSignatureScenario, SignedRequestParts,
            sign_http_message_for_scenario,
        };
        let bytes = arkret_canonical::canonical_json_bytes(body)?;
        let target = station.url(&format!(
            "/_arkret/self/applets/{}/authority/material",
            self.package.applet_id
        ));
        let url = url::Url::parse(&target)?;
        let digest = ContentDigest::compute(&bytes, ContentDigestAlgorithm::Sha256).wire_value;
        let headers = vec![
            ("content-type".into(), "application/json".into()),
            ("content-digest".into(), digest.clone()),
            (
                "source-service-id".into(),
                self.package.service_id.to_string(),
            ),
            (
                "destination-service-id".into(),
                station.service_id().to_string(),
            ),
            (
                "source-trust-domain".into(),
                station.trust_domain().to_string(),
            ),
            (
                "destination-trust-domain".into(),
                station.trust_domain().to_string(),
            ),
            (
                "arkret-operation".into(),
                arkret_wire::ServiceOperationId::SELF_APPLET_AUTHORITY_READ_MATERIAL_V1.into(),
            ),
        ];
        let signed = sign_http_message_for_scenario(
            &SignedRequestParts {
                method: "POST".into(),
                target_uri: target.clone(),
                authority: url[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
                path: url.path().into(),
                headers: headers.clone(),
                body_digest: Some(digest),
            },
            HttpSignatureScenario::ServiceToServiceV1,
            &["content-digest"],
            "sig1",
            self.method.as_str(),
            chrono::Utc::now().timestamp(),
            &self.signing_key,
        )?;
        let mut request = station.http().post(target).body(bytes);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        Ok(request
            .header("signature-input", signed.signature_input_header)
            .header("signature", signed.signature_header))
    }

    pub fn service_id(&self) -> &DidCoreId {
        &self.package.service_id
    }

    /// Read the real method endpoint again after acceptance. An observation
    /// made before the ready Commit cannot prove that later historical time.
    pub async fn current_resolution(
        &self,
        station: &ArkretServer,
    ) -> Result<arkret_models_identity::AuthenticatedServiceResolution> {
        let body = station
            .http()
            .get(arkret_identity::DidWebvhResolver::log_url(&self.did)?)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let entries = body
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let document = entries
            .last()
            .context("real recorder method returned no history")?["state"]
            .clone();
        Ok(
            arkret_identity::build_authenticated_webvh_service_resolution(
                self.package.service_id.clone(),
                "applet_service".into(),
                serde_json::from_value(document)?,
                entries,
                Vec::new(),
                arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            )?,
        )
    }
}

/// Shared real preview authoring for independently hosted Applet packages.
pub(crate) async fn installation_request_for_package(
    package: &AppletPackage,
    epoch_evidence: &AppletRegistrationEpochEvidence,
    station: &ArkretServer,
    member: &crate::scenarios::mls_lifecycle_live::Member,
    realm: &RealmId,
    extra_constraints: &[arkret_models_collaboration::governance::grant_constraint::GrantConstraint],
) -> Result<(AppletInstallRequestBody, Event, Event)> {
    use arkret_models_collaboration::events_payloads::{
        CapabilityGrantCreateBody, CapabilityGrantPayload,
    };
    use arkret_models_collaboration::governance::grant_constraint::{
        CapabilitySubject, GrantConstraint, IssuerAuthorityRef,
    };
    let registration = member
        .client
        .author_event(
            realm.as_str(),
            EventKind::AppletRegistration.as_str(),
            serde_json::to_value(package.to_registration(epoch_evidence, None)?)?,
        )
        .await?;
    let grant = member
        .client
        .author_event(
            realm.as_str(),
            EventKind::CapabilityGrant.as_str(),
            serde_json::to_value(CapabilityGrantPayload {
                grant: CapabilityGrantCreateBody {
                    schema: arkret_wire::SchemaId::CAPABILITY_V1.into(),
                    realm_id: Some(realm.clone()),
                    issuer_id: member.actor.clone(),
                    subject: CapabilitySubject::Actor(ActorId::service(package.service_id.clone())),
                    actions: package.requested_scopes.clone(),
                    resources: vec![arkret_wire::WireResourceSelector::realm(realm.clone())],
                    constraints: [GrantConstraint::applet_authority(
                        package.applet_id.clone(),
                        ActorId::service(package.service_id.clone()),
                        package.registration_epoch.clone(),
                    )]
                    .into_iter()
                    .chain(extra_constraints.iter().cloned())
                    .collect(),
                    issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                        realm_id: realm.clone(),
                        authority_event_ref: realm.event_id(),
                        authority_generation: 0,
                    }],
                    issued_at: chrono::Utc::now(),
                },
            })?,
        )
        .await?;
    let basis: AppletInstallAuthoringRequestBasis = serde_json::from_value(json!({
        "schema":AppletInstallAuthoringRequestBasis::SCHEMA,"purpose":"install_service","target_station_id":station.service_id(),
        "install_actor_id":member.actor,"applet_id":package.applet_id,"service_id":package.service_id,"package_digest":package.package_digest,
        "effective_scope":{"kind":"realm","realm_id":realm},"approval_request":{"approve_actions":package.requested_scopes,
            "ghost_actor_mode":"policy_declared","delegated_native_actors_allowed":false,"e2ee_join_allowed":false,"widget_allowed":false},
        "actor_policy":{"ghost_actor_mode":"policy_declared"},"e2ee_policy":{"mls_join_allowed":false},"widget_policy":{"widget_allowed":false},
        "registration_event":registration,"capability_grant_events":[grant]
    }))?;
    let preview: AppletInstallPreviewResponseBody = serde_json::from_value(
        expect_json(
            member
                .client
                .post("/_arkret/self/applets/install/preview")
                .json(&AppletInstallPreviewRequestBody {
                    applet_package: package.clone(),
                    authoring_request_basis: basis.clone(),
                }),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    let body = AppletInstallRequestBody {
        applet_package: package.clone(),
        authoring_request_basis: basis,
        plan_digest: preview.plan.plan_digest,
    };
    Ok((body, registration, grant))
}
